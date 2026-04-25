#!/usr/bin/env python3
"""
OpenTrackIO consumer with a small tkinter dashboard.

Same network behaviour as opentrackio_client.py -- joins the OpenTrackIO
multicast group (or listens on a unicast port) and parses one JSON sample per
UDP datagram -- but instead of printing to stdout it renders:

  * a numeric readout of every field the server emits,
  * horizontal bars for the focus / iris / zoom lens encoders (0..1),
  * rolling history graphs for position (x,y,z) and rotation (pan,tilt,roll)
    drawn directly on a tkinter Canvas (no matplotlib required),
  * a connection / rate indicator (destination, packets/sec, live/stale).

Network I/O runs on a background thread and hands samples to the UI thread
through a queue, so the window stays responsive even under heavy sample
rates.

Run (loopback against the bundled server):
    python3 opentrackio_server.py --unicast 127.0.0.1 --rate 60   &
    python3 opentrackio_client_ui.py --unicast

Or on a real multicast LAN:
    python3 opentrackio_client_ui.py --source 1

This script only depends on the Python standard library.
"""

from __future__ import annotations

import argparse
import json
import queue
import socket
import struct
import sys
import threading
import time
import tkinter as tk
from collections import deque
from tkinter import ttk


# ---------------------------------------------------------------------------
# Constants (keep in sync with opentrackio_client.py / opentrackio_server.py)
# ---------------------------------------------------------------------------

OTIO_DEFAULT_PORT = 55555
OTIO_MCAST_BASE = "239.135.1."
OTIO_SOURCE_MIN = 1
OTIO_SOURCE_MAX = 200

# OpenTrackIO raw-UDP packet header (matches opentrackio_server.py and
# UE5.7 LiveLinkOpenTrackIOParser.cpp byte-for-byte). The listener
# auto-detects: datagrams that start with 'OTrk' are decoded as wrapped
# packets; everything else is parsed as raw JSON.
OTIO_HEADER_SIZE          = 16
OTIO_HEADER_IDENTIFIER    = b"OTrk"
OTIO_LAST_SEGMENT_FLAG    = 0x8000
OTIO_PAYLOAD_LEN_MASK     = 0x7FFF

# How much history to keep in the rolling graphs.
HISTORY_SECONDS = 10.0
# Max samples buffered per channel. 1000 is plenty for 10 s at 60 Hz.
HISTORY_MAX = 1200
# How often the UI polls the queue and repaints.
UI_TICK_MS = 33   # ~30 fps


def _fletcher16(data: bytes) -> int:
    s1 = 0
    s2 = 0
    for b in data:
        s1 = (s1 + b) & 0xFF
        s2 = (s2 + s1) & 0xFF
    return ((s2 << 8) | s1) & 0xFFFF


def _extract_payload(data: bytes) -> bytes | None:
    """Return the JSON payload from a datagram, or None if it is malformed.

    Accepts both the wrapped 'OTrk' packet format and bare JSON.
    """
    if data.startswith(OTIO_HEADER_IDENTIFIER):
        if len(data) < OTIO_HEADER_SIZE:
            return None
        (_ident, _reserved, _encoding, _sequence,
         _segment_offset, flag_and_len, checksum) = struct.unpack(
            ">IBBHIHH", data[:OTIO_HEADER_SIZE])
        payload_len = flag_and_len & OTIO_PAYLOAD_LEN_MASK
        payload = data[OTIO_HEADER_SIZE:OTIO_HEADER_SIZE + payload_len]
        if len(payload) != payload_len:
            return None
        # Fletcher-16 over header[0:14] + payload, per UE5.7 parser.
        expected = _fletcher16(data[:OTIO_HEADER_SIZE - 2] + bytes(payload))
        if expected != checksum:
            return None
        return payload
    return data


def multicast_address_for(source_number: int) -> str:
    if not (OTIO_SOURCE_MIN <= source_number <= OTIO_SOURCE_MAX):
        raise ValueError(
            f"OpenTrackIO source number must be in "
            f"[{OTIO_SOURCE_MIN}, {OTIO_SOURCE_MAX}], got {source_number}"
        )
    return f"{OTIO_MCAST_BASE}{source_number}"


# ---------------------------------------------------------------------------
# Sockets
# ---------------------------------------------------------------------------

def make_multicast_listener(group: str, port: int,
                            iface: str = "0.0.0.0") -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.bind(("", port))
    mreq = struct.pack("4s4s",
                       socket.inet_aton(group),
                       socket.inet_aton(iface))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock


def make_unicast_listener(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    return sock


# ---------------------------------------------------------------------------
# Background network thread
# ---------------------------------------------------------------------------

class NetListener(threading.Thread):
    """Receives OpenTrackIO datagrams and forwards parsed samples to a queue."""

    def __init__(self, sock: socket.socket, out_queue: "queue.Queue[dict]"):
        super().__init__(daemon=True, name="otio-netlistener")
        self._sock = sock
        self._queue = out_queue
        self._stop_event = threading.Event()
        # Small timeout so we can observe the stop flag without blocking
        # forever on an empty socket.
        self._sock.settimeout(0.25)

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, _addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            payload = _extract_payload(data)
            if payload is None:
                continue
            try:
                sample = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            # Attach arrival time so the UI can age history consistently even
            # if the server clock drifts.
            sample["__rx_time"] = time.time()
            try:
                self._queue.put_nowait(sample)
            except queue.Full:
                pass


# ---------------------------------------------------------------------------
# Rolling graph widget
# ---------------------------------------------------------------------------

class RollingGraph(tk.Canvas):
    """A small auto-scaling line chart for a handful of named channels."""

    # A small fixed palette, high contrast on dark-ish backgrounds.
    COLORS = ("#ff6b6b", "#4ecdc4", "#ffe66d",
              "#a78bfa", "#60a5fa", "#f472b6")

    def __init__(self, parent: tk.Widget, title: str, channel_names: list[str],
                 unit: str = "", bg: str = "#1e1e1e", height: int = 140):
        super().__init__(parent, bg=bg, height=height, highlightthickness=0)
        self.title = title
        self.unit = unit
        self.channels = {name: deque(maxlen=HISTORY_MAX)
                         for name in channel_names}
        self._min_range = 0.01  # avoid div-by-zero on flat signals

    def push(self, rx_time: float, values: dict[str, float]) -> None:
        for name, buf in self.channels.items():
            if name in values:
                buf.append((rx_time, float(values[name])))
        # Drop points older than the display window.
        cutoff = rx_time - HISTORY_SECONDS
        for buf in self.channels.values():
            while buf and buf[0][0] < cutoff:
                buf.popleft()

    def redraw(self, now: float) -> None:
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 20 or h < 20:
            return

        # Axis / padding
        pad_l, pad_r, pad_t, pad_b = 48, 8, 18, 14
        plot_w = max(1, w - pad_l - pad_r)
        plot_h = max(1, h - pad_t - pad_b)

        # Title
        self.create_text(pad_l, 2, anchor="nw", fill="#cccccc",
                         text=self.title, font=("TkDefaultFont", 9, "bold"))

        # Find combined Y range across all channels
        lo, hi = float("inf"), float("-inf")
        for buf in self.channels.values():
            for _t, v in buf:
                lo = min(lo, v); hi = max(hi, v)
        if lo == float("inf"):
            lo, hi = 0.0, 0.0
        if hi - lo < self._min_range:
            mid = (hi + lo) / 2.0
            lo, hi = mid - self._min_range / 2, mid + self._min_range / 2

        # Gridlines + axis labels (just min / mid / max)
        for frac, label_val in ((0.0, hi), (0.5, (hi + lo) / 2), (1.0, lo)):
            y = pad_t + frac * plot_h
            self.create_line(pad_l, y, w - pad_r, y, fill="#333333")
            self.create_text(pad_l - 4, y, anchor="e", fill="#888888",
                             text=f"{label_val:+.2f}{self.unit}",
                             font=("TkDefaultFont", 8))

        # Time baseline: "now" is the right edge, HISTORY_SECONDS ago is left
        t_right = now
        t_left = now - HISTORY_SECONDS
        t_span = HISTORY_SECONDS

        def map_point(t: float, v: float) -> tuple[float, float]:
            x = pad_l + (t - t_left) / t_span * plot_w
            norm = 0.0 if hi == lo else (v - lo) / (hi - lo)
            y = pad_t + (1.0 - norm) * plot_h
            return x, y

        # Per-channel polylines
        for i, (name, buf) in enumerate(self.channels.items()):
            color = self.COLORS[i % len(self.COLORS)]
            pts: list[float] = []
            for t, v in buf:
                x, y = map_point(t, v)
                pts.extend((x, y))
            if len(pts) >= 4:
                self.create_line(*pts, fill=color, width=1.5, smooth=False)

        # Legend (last known value per channel)
        lx = pad_l + 6
        ly = h - pad_b + 2
        for i, (name, buf) in enumerate(self.channels.items()):
            color = self.COLORS[i % len(self.COLORS)]
            last = buf[-1][1] if buf else 0.0
            txt = f"{name}: {last:+.3f}{self.unit}"
            self.create_rectangle(lx, ly + 2, lx + 10, ly + 10,
                                  fill=color, outline="")
            self.create_text(lx + 14, ly, anchor="nw", fill="#dddddd",
                             text=txt, font=("TkDefaultFont", 8))
            lx += 12 + 8 + 7 * len(txt)  # rough advance; enough for our labels


# ---------------------------------------------------------------------------
# Encoder bar widget
# ---------------------------------------------------------------------------

class EncoderBar(tk.Canvas):
    """A 0..1 bar with label and numeric readout -- one per lens encoder."""

    def __init__(self, parent: tk.Widget, label: str, color: str,
                 bg: str = "#1e1e1e"):
        super().__init__(parent, bg=bg, height=28, highlightthickness=0)
        self.label = label
        self.color = color
        self.value = 0.0

    def set_value(self, v: float) -> None:
        self.value = max(0.0, min(1.0, float(v)))

    def redraw(self) -> None:
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 20 or h < 10:
            return
        bar_x0, bar_y0 = 72, 6
        bar_x1, bar_y1 = w - 56, h - 6
        # Label
        self.create_text(8, h / 2, anchor="w", fill="#dddddd",
                         text=self.label, font=("TkDefaultFont", 9, "bold"))
        # Track
        self.create_rectangle(bar_x0, bar_y0, bar_x1, bar_y1,
                              fill="#2a2a2a", outline="#444444")
        # Fill
        fill_x = bar_x0 + (bar_x1 - bar_x0) * self.value
        self.create_rectangle(bar_x0, bar_y0, fill_x, bar_y1,
                              fill=self.color, outline="")
        # Numeric readout
        self.create_text(w - 8, h / 2, anchor="e", fill="#eeeeee",
                         text=f"{self.value:.3f}",
                         font=("TkDefaultFont", 10))


# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------

class Dashboard:
    def __init__(self, root: tk.Tk, mode_descr: str,
                 in_queue: "queue.Queue[dict]", listener: NetListener,
                 exit_after: float | None = None):
        self.root = root
        self.q = in_queue
        self.listener = listener
        self.mode_descr = mode_descr
        self.exit_after = exit_after

        # Runtime stats
        self.sample_count = 0
        self.rate_window: deque[float] = deque(maxlen=240)  # rx timestamps
        self.last_rx: float = 0.0
        self.current_source_id = "(waiting...)"
        self.started_at = time.time()

        root.title("OpenTrackIO Client")
        root.configure(bg="#121212")
        root.minsize(760, 640)

        self._build_style()
        self._build_widgets()

        # Graceful shutdown on Ctrl+C or window close.
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.bind("<Control-c>", lambda _e: self.on_close())
        root.bind("<Escape>", lambda _e: self.on_close())

        # Kick off the UI update loop.
        self.root.after(UI_TICK_MS, self._tick)

    # ----- layout -----

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        # Fall back gracefully if a theme isn't available.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TLabelframe",
                        background="#1a1a1a", foreground="#dddddd",
                        bordercolor="#333333", relief="groove")
        style.configure("TLabelframe.Label",
                        background="#1a1a1a", foreground="#cccccc")
        style.configure("TFrame", background="#1a1a1a")
        style.configure("TLabel", background="#1a1a1a",
                        foreground="#dddddd", font=("TkDefaultFont", 10))
        style.configure("Value.TLabel", foreground="#ffffff",
                        font=("TkFixedFont", 11))
        style.configure("Dim.TLabel",   foreground="#888888",
                        font=("TkDefaultFont", 9))
        style.configure("Live.TLabel",  foreground="#6de26d",
                        font=("TkDefaultFont", 10, "bold"))
        style.configure("Stale.TLabel", foreground="#e26d6d",
                        font=("TkDefaultFont", 10, "bold"))

    def _build_widgets(self) -> None:
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        # ---------- top: connection / rate indicator ----------
        top = ttk.LabelFrame(outer, text="Connection", padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="Listening on:", style="Dim.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(top, text=self.mode_descr,  style="Value.TLabel").grid(row=0, column=1, sticky="w", padx=(6, 20))
        ttk.Label(top, text="Status:",        style="Dim.TLabel").grid(row=0, column=2, sticky="w")
        # Pin widths so value changes never resize the Connection frame (which
        # in turn would resize every frame packed below it).
        self.lbl_status = ttk.Label(top, text="waiting", style="Stale.TLabel",
                                    width=14, anchor="w")
        self.lbl_status.grid(row=0, column=3, sticky="w", padx=(6, 20))
        ttk.Label(top, text="Rate:", style="Dim.TLabel").grid(row=0, column=4, sticky="w")
        self.lbl_rate = ttk.Label(top, text="0 pkt/s", style="Value.TLabel",
                                  width=10, anchor="w")
        self.lbl_rate.grid(row=0, column=5, sticky="w", padx=(6, 20))
        ttk.Label(top, text="Count:", style="Dim.TLabel").grid(row=0, column=6, sticky="w")
        self.lbl_count = ttk.Label(top, text="0", style="Value.TLabel",
                                   width=10, anchor="w")
        self.lbl_count.grid(row=0, column=7, sticky="w", padx=(6, 20))

        ttk.Label(top, text="Source:", style="Dim.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))
        # Width ~50 fits "urn:uuid:<36>" comfortably so the row never grows
        # the moment the first real sample arrives.
        self.lbl_source = ttk.Label(top, text=self.current_source_id,
                                    style="Value.TLabel",
                                    width=50, anchor="w")
        self.lbl_source.grid(row=1, column=1, columnspan=7, sticky="w",
                             padx=(6, 0), pady=(4, 0))

        # ---------- middle: numeric readout ----------
        # The mid row does NOT expand children -- they stay at their requested
        # width. This is the critical fix: with fixed-width labels inside each
        # box, pack(side="left") no longer redistributes space as values
        # change.
        mid = ttk.Frame(outer, padding=(0, 10))
        mid.pack(fill="x")

        tc_box = ttk.LabelFrame(mid, text="Timing", padding=8)
        tc_box.pack(side="left", fill="y", padx=(0, 8))
        ttk.Label(tc_box, text="Timecode", style="Dim.TLabel").grid(row=0, column=0, sticky="w")
        # 11 chars = "HH:MM:SS:FF"
        self.lbl_tc = ttk.Label(tc_box, text="--:--:--:--", style="Value.TLabel",
                                width=12, anchor="w")
        self.lbl_tc.grid(row=1, column=0, sticky="w")
        ttk.Label(tc_box, text="Rate", style="Dim.TLabel").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.lbl_tc_rate = ttk.Label(tc_box, text="--.-- Hz", style="Value.TLabel",
                                     width=12, anchor="w")
        self.lbl_tc_rate.grid(row=3, column=0, sticky="w")

        pos_box = ttk.LabelFrame(mid, text="Position (m)", padding=8)
        pos_box.pack(side="left", fill="y", padx=4)
        self.lbl_pos = {}
        for i, axis in enumerate(("x", "y", "z")):
            ttk.Label(pos_box, text=axis, style="Dim.TLabel").grid(row=0, column=i, sticky="w", padx=4)
            # 8 chars holds "-12.345" comfortably; our sine-wave max is ~3m.
            lbl = ttk.Label(pos_box, text=" +0.000", style="Value.TLabel",
                            width=8, anchor="w")
            lbl.grid(row=1, column=i, sticky="w", padx=4)
            self.lbl_pos[axis] = lbl

        rot_box = ttk.LabelFrame(mid, text="Rotation (deg)", padding=8)
        rot_box.pack(side="left", fill="y", padx=4)
        self.lbl_rot = {}
        for i, axis in enumerate(("pan", "tilt", "roll")):
            ttk.Label(rot_box, text=axis, style="Dim.TLabel").grid(row=0, column=i, sticky="w", padx=4)
            # Pan swings ±45°, so "+45.00"/"-45.00" -> 7 chars with a leading
            # space for alignment on small magnitudes.
            lbl = ttk.Label(rot_box, text=" +0.00", style="Value.TLabel",
                            width=8, anchor="w")
            lbl.grid(row=1, column=i, sticky="w", padx=4)
            self.lbl_rot[axis] = lbl

        lens_box = ttk.LabelFrame(mid, text="Lens", padding=8)
        lens_box.pack(side="left", fill="y", padx=(4, 0))
        self.lbl_lens = {}
        # (label, unit, column width). Width is in char cells of TkFixedFont,
        # big enough for the widest legal value (e.g. "100.00mm").
        for i, (name, unit, col_w) in enumerate((
            ("Focal length", "mm", 10),
            ("Focus dist",   "m",  8),
            ("fStop",        "",   8),
        )):
            ttk.Label(lens_box, text=name, style="Dim.TLabel").grid(row=0, column=i, sticky="w", padx=4)
            lbl = ttk.Label(lens_box, text=f"0.00{unit}", style="Value.TLabel",
                            width=col_w, anchor="w")
            lbl.grid(row=1, column=i, sticky="w", padx=4)
            self.lbl_lens[name] = (lbl, unit)

        # Invisible spacer soaks up leftover horizontal space on the right,
        # so that when the window is wider than the four boxes put together
        # the boxes stay flush-left at their pinned widths instead of having
        # the pack manager try (and fail, since expand=False on all of them)
        # to centre them awkwardly.
        ttk.Frame(mid).pack(side="left", fill="x", expand=True)

        # ---------- encoders ----------
        enc_box = ttk.LabelFrame(outer, text="Lens encoders (0..1)", padding=8)
        enc_box.pack(fill="x", pady=(0, 10))
        self.bar_focus = EncoderBar(enc_box, "Focus", "#ff6b6b")
        self.bar_iris  = EncoderBar(enc_box, "Iris",  "#4ecdc4")
        self.bar_zoom  = EncoderBar(enc_box, "Zoom",  "#ffe66d")
        for bar in (self.bar_focus, self.bar_iris, self.bar_zoom):
            bar.pack(fill="x", pady=2)

        # ---------- graphs ----------
        graphs = ttk.Frame(outer)
        graphs.pack(fill="both", expand=True)

        pos_lf = ttk.LabelFrame(graphs, text=f"Position history (last {int(HISTORY_SECONDS)} s)", padding=4)
        pos_lf.pack(fill="both", expand=True, pady=(0, 8))
        self.graph_pos = RollingGraph(pos_lf, title="", channel_names=["x", "y", "z"], unit="m")
        self.graph_pos.pack(fill="both", expand=True)

        rot_lf = ttk.LabelFrame(graphs, text=f"Rotation history (last {int(HISTORY_SECONDS)} s)", padding=4)
        rot_lf.pack(fill="both", expand=True)
        self.graph_rot = RollingGraph(rot_lf, title="", channel_names=["pan", "tilt", "roll"], unit="°")
        self.graph_rot.pack(fill="both", expand=True)

    # ----- main loop tick -----

    def _tick(self) -> None:
        # Drain all queued samples first, so if the UI is a little behind we
        # catch up rather than lag further.
        latest: dict | None = None
        drained = 0
        try:
            while True:
                latest = self.q.get_nowait()
                drained += 1
                self._ingest(latest)
        except queue.Empty:
            pass

        now = time.time()
        self._repaint(now)

        if self.exit_after is not None and (now - self.started_at) >= self.exit_after:
            self.on_close()
            return

        self.root.after(UI_TICK_MS, self._tick)

    def _ingest(self, sample: dict) -> None:
        rx = float(sample.get("__rx_time", time.time()))
        self.sample_count += 1
        self.rate_window.append(rx)
        self.last_rx = rx

        src = sample.get("sourceId")
        if src and src != self.current_source_id:
            self.current_source_id = src

        tr = (sample.get("transforms") or [{}])[0]
        t_ = tr.get("translation") or {}
        r_ = tr.get("rotation") or {}
        self.graph_pos.push(rx, {
            "x": t_.get("x", 0.0),
            "y": t_.get("y", 0.0),
            "z": t_.get("z", 0.0),
        })
        self.graph_rot.push(rx, {
            "pan":  r_.get("pan",  0.0),
            "tilt": r_.get("tilt", 0.0),
            "roll": r_.get("roll", 0.0),
        })

        # Cache the most recent sample for the numeric readouts.
        self._last_sample = sample

    def _repaint(self, now: float) -> None:
        # Live / stale indicator
        if self.last_rx == 0.0:
            self.lbl_status.configure(text="waiting", style="Stale.TLabel")
        elif now - self.last_rx > 1.0:
            self.lbl_status.configure(
                text=f"stale ({now - self.last_rx:.1f}s)",
                style="Stale.TLabel",
            )
        else:
            self.lbl_status.configure(text="live", style="Live.TLabel")

        # Rate: samples in last 1 s
        cutoff = now - 1.0
        while self.rate_window and self.rate_window[0] < cutoff:
            self.rate_window.popleft()
        # All numeric formats below pad to a fixed character width (right-
        # aligned text with leading spaces) so the rendered glyphs stay in
        # place as values change -- this is what keeps the frame widths from
        # jittering.
        self.lbl_rate.configure(text=f"{len(self.rate_window):>3.0f} pkt/s")
        self.lbl_count.configure(text=f"{self.sample_count}")
        self.lbl_source.configure(text=self.current_source_id)

        sample = getattr(self, "_last_sample", None)
        if sample is not None:
            tc = (sample.get("timing") or {}).get("timecode") or {}
            tc_str = "{:02d}:{:02d}:{:02d}:{:02d}".format(
                tc.get("hours", 0), tc.get("minutes", 0),
                tc.get("seconds", 0), tc.get("frames", 0),
            )
            self.lbl_tc.configure(text=tc_str)

            sr = (sample.get("timing") or {}).get("sampleRate") or {}
            num = sr.get("num"); den = sr.get("denom")
            if num and den:
                self.lbl_tc_rate.configure(text=f"{num/den:6.2f} Hz")

            tr = (sample.get("transforms") or [{}])[0]
            t_ = tr.get("translation") or {}
            r_ = tr.get("rotation") or {}
            # {:+7.3f} -> sign + up to 3 int digits + . + 3 dec = 7 chars min
            self.lbl_pos["x"].configure(text=f"{t_.get('x', 0):+7.3f}")
            self.lbl_pos["y"].configure(text=f"{t_.get('y', 0):+7.3f}")
            self.lbl_pos["z"].configure(text=f"{t_.get('z', 0):+7.3f}")
            # {:+7.2f} -> sign + up to 3 int digits + . + 2 dec = 7 chars min
            self.lbl_rot["pan"].configure(text=f"{r_.get('pan',  0):+7.2f}")
            self.lbl_rot["tilt"].configure(text=f"{r_.get('tilt', 0):+7.2f}")
            self.lbl_rot["roll"].configure(text=f"{r_.get('roll', 0):+7.2f}")

            ln = sample.get("lens") or {}
            enc = ln.get("encoders") or {}
            self.bar_focus.set_value(enc.get("focus", 0.0))
            self.bar_iris.set_value(enc.get("iris", 0.0))
            self.bar_zoom.set_value(enc.get("zoom", 0.0))
            # {:6.2f} -> up to 3 int digits + . + 2 dec, right-aligned in 6.
            lbl, unit = self.lbl_lens["Focal length"]
            lbl.configure(text=f"{ln.get('pinholeFocalLength', 0):6.2f}{unit}")
            lbl, unit = self.lbl_lens["Focus dist"]
            lbl.configure(text=f"{ln.get('focusDistance', 0):5.2f}{unit}")
            lbl, unit = self.lbl_lens["fStop"]
            lbl.configure(text=f"T{ln.get('fStop', 0):5.2f}{unit}")

        # Redraw visuals
        for bar in (self.bar_focus, self.bar_iris, self.bar_zoom):
            bar.redraw()
        self.graph_pos.redraw(now)
        self.graph_rot.redraw(now)

    # ----- shutdown -----

    def on_close(self) -> None:
        try:
            self.listener.stop()
        except Exception:
            pass
        try:
            self.root.destroy()
        except tk.TclError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OpenTrackIO tkinter client")
    p.add_argument("--source", type=int, default=1,
                   help="OpenTrackIO Source Number (1..200). Picks the "
                        "multicast group 239.135.1.<source>. Default: 1")
    p.add_argument("--port", type=int, default=OTIO_DEFAULT_PORT,
                   help=f"UDP port. Default: {OTIO_DEFAULT_PORT}")
    p.add_argument("--iface", type=str, default="0.0.0.0",
                   help="Local interface for the multicast join. "
                        "Default: 0.0.0.0")
    p.add_argument("--unicast", action="store_true",
                   help="Listen on plain unicast on --port instead of "
                        "joining a multicast group.")
    p.add_argument("--exit-after", type=float, default=None,
                   help="Close the window after N seconds (useful for "
                        "smoke tests and CI).")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.unicast:
        sock = make_unicast_listener(args.port)
        mode_descr = f"unicast 0.0.0.0:{args.port}"
    else:
        group = multicast_address_for(args.source)
        sock = make_multicast_listener(group, args.port, iface=args.iface)
        mode_descr = (f"multicast {group}:{args.port} "
                      f"(source {args.source}, iface {args.iface})")

    sample_queue: "queue.Queue[dict]" = queue.Queue(maxsize=4096)
    listener = NetListener(sock, sample_queue)
    listener.start()

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"error: cannot open display: {exc}", file=sys.stderr)
        listener.stop()
        return 1

    Dashboard(root, mode_descr, sample_queue, listener,
              exit_after=args.exit_after)
    try:
        root.mainloop()
    finally:
        listener.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
