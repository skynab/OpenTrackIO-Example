#!/usr/bin/env python3
"""
OpenTrackIO consumer (client).

Joins the OpenTrackIO multicast group on UDP port 55555, parses every
arriving JSON sample, performs some light validation against the expected
schema shape, and prints the camera rigid-body transform and lens data.

Run:
    python3 opentrackio_client.py                 # multicast, source 1
    python3 opentrackio_client.py --source 7
    python3 opentrackio_client.py --unicast       # plain unicast listen on
                                                  #   0.0.0.0:55555
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time


OTIO_DEFAULT_PORT = 55555
OTIO_MCAST_BASE = "239.135.1."
OTIO_SOURCE_MIN = 1
OTIO_SOURCE_MAX = 200

# OpenTrackIO raw-UDP packet header. Layout matches Unreal Engine 5.7's
# LiveLinkOpenTrackIOParser.cpp byte-for-byte (see opentrackio_server.py for
# the full annotated layout). We accept both formats on the wire: datagrams
# that start with the 'OTrk' magic are decoded as wrapped packets, everything
# else is treated as raw JSON for backwards-compatibility with the
# --no-header server mode.
OTIO_HEADER_SIZE           = 16
OTIO_HEADER_IDENTIFIER     = b"OTrk"           # for prefix-detect
OTIO_HEADER_IDENTIFIER_U32 = 0x4F54726B
OTIO_ENCODING_JSON         = 0x01
OTIO_ENCODING_CBOR         = 0x02
OTIO_LAST_SEGMENT_FLAG     = 0x8000
OTIO_PAYLOAD_LEN_MASK      = 0x7FFF


def fletcher16(data: bytes) -> int:
    s1 = 0
    s2 = 0
    for b in data:
        s1 = (s1 + b) & 0xFF
        s2 = (s2 + s1) & 0xFF
    return ((s2 << 8) | s1) & 0xFFFF


class PacketError(Exception):
    """Raised when a datagram cannot be decoded as an OpenTrackIO packet."""


def parse_packet(data: bytes) -> tuple[bytes, dict]:
    """Return (payload, header_info) for an OpenTrackIO wrapped datagram.

    Raises PacketError if the datagram does not start with the 'OTrk' magic.
    Raw-JSON datagrams (no header) should be detected by the caller first.
    """
    if len(data) < OTIO_HEADER_SIZE:
        raise PacketError(f"datagram too short ({len(data)} bytes)")
    if data[:4] != OTIO_HEADER_IDENTIFIER:
        raise PacketError("missing 'OTrk' identifier")

    (identifier, reserved, encoding, sequence,
     segment_offset, flag_and_len, checksum) = struct.unpack(
        ">IBBHIHH", data[:OTIO_HEADER_SIZE])

    if identifier != OTIO_HEADER_IDENTIFIER_U32:
        raise PacketError(
            f"missing 'OTrk' identifier (got 0x{identifier:08x})"
        )

    last_segment = bool(flag_and_len & OTIO_LAST_SEGMENT_FLAG)
    payload_len  = flag_and_len & OTIO_PAYLOAD_LEN_MASK

    payload = data[OTIO_HEADER_SIZE:OTIO_HEADER_SIZE + payload_len]
    if len(payload) != payload_len:
        raise PacketError(
            f"payload length mismatch (header says {payload_len}, "
            f"datagram has {len(payload)})"
        )

    # UE5.7 computes Fletcher-16 over the first 14 header bytes (everything
    # except the checksum field itself) PLUS the payload.
    expected = fletcher16(data[:OTIO_HEADER_SIZE - 2] + bytes(payload))
    if expected != checksum:
        raise PacketError(
            f"checksum mismatch (header 0x{checksum:04x}, "
            f"computed 0x{expected:04x})"
        )
    return payload, {
        "sequence":       sequence,
        "segment_offset": segment_offset,
        "last_segment":   last_segment,
        "encoding":       encoding,
        "payload_len":    payload_len,
        "checksum":       checksum,
    }


def multicast_address_for(source_number: int) -> str:
    if not (OTIO_SOURCE_MIN <= source_number <= OTIO_SOURCE_MAX):
        raise ValueError(
            f"OpenTrackIO source number must be in "
            f"[{OTIO_SOURCE_MIN}, {OTIO_SOURCE_MAX}], got {source_number}"
        )
    return f"{OTIO_MCAST_BASE}{source_number}"


# ---------------------------------------------------------------------------
# Socket setup
# ---------------------------------------------------------------------------

def make_multicast_listener(group: str,
                            port: int,
                            iface: str = "0.0.0.0") -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Some platforms also expose SO_REUSEPORT which is nice for multiple
    # consumers on one host; ignore if unavailable.
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
# Sample validation + pretty print
# ---------------------------------------------------------------------------

REQUIRED_TOP = ("protocol", "sourceId", "sampleId", "timing",
                "transforms", "lens")


def validate_sample(sample: dict) -> list[str]:
    """Return a list of human-readable warnings. Empty list means OK."""
    warnings: list[str] = []

    for key in REQUIRED_TOP:
        if key not in sample:
            warnings.append(f"missing top-level field '{key}'")

    proto = sample.get("protocol") or {}
    if proto.get("name") != "OpenTrackIO":
        warnings.append(f"unexpected protocol.name: {proto.get('name')!r}")

    tr = (sample.get("transforms") or [{}])[0]
    for axis in ("x", "y", "z"):
        if axis not in (tr.get("translation") or {}):
            warnings.append(f"transforms[0].translation.{axis} missing")
    for axis in ("pan", "tilt", "roll"):
        if axis not in (tr.get("rotation") or {}):
            warnings.append(f"transforms[0].rotation.{axis} missing")

    lens = sample.get("lens") or {}
    if "encoders" not in lens:
        warnings.append("lens.encoders missing")
    return warnings


def format_sample_line(sample: dict) -> str:
    tc = (sample.get("timing") or {}).get("timecode") or {}
    tc_str = "{:02d}:{:02d}:{:02d}:{:02d}".format(
        tc.get("hours", 0), tc.get("minutes", 0),
        tc.get("seconds", 0), tc.get("frames", 0),
    )

    tr = (sample.get("transforms") or [{}])[0]
    t_ = tr.get("translation") or {}
    r_ = tr.get("rotation") or {}
    ln = sample.get("lens") or {}
    enc = ln.get("encoders") or {}

    return (
        f"TC {tc_str}  "
        f"pos=({t_.get('x',0):+.3f},{t_.get('y',0):+.3f},{t_.get('z',0):+.3f})  "
        f"rot=(p{r_.get('pan',0):+6.2f} t{r_.get('tilt',0):+6.2f} "
        f"r{r_.get('roll',0):+6.2f})  "
        f"enc(f{enc.get('focus',0):.3f} i{enc.get('iris',0):.3f} "
        f"z{enc.get('zoom',0):.3f})  "
        f"fl={ln.get('pinholeFocalLength',0):.2f}mm  "
        f"fd={ln.get('focusDistance',0):.2f}m  "
        f"T{ln.get('fStop',0):.2f}"
    )


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    if args.unicast:
        sock = make_unicast_listener(args.port)
        mode_descr = f"unicast 0.0.0.0:{args.port}"
    else:
        group = multicast_address_for(args.source)
        sock = make_multicast_listener(group, args.port, iface=args.iface)
        mode_descr = (
            f"multicast {group}:{args.port} "
            f"(source number {args.source}, iface {args.iface})"
        )

    print(f"[opentrackio-client] listening on {mode_descr}")
    print(f"[opentrackio-client] Ctrl+C to stop")

    count = 0
    last_print = 0.0
    known_sources: dict[str, int] = {}

    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue

            # Auto-detect: wrapped OpenTrackIO packet vs raw JSON.
            header_info: dict | None = None
            if data.startswith(OTIO_HEADER_IDENTIFIER):
                try:
                    payload, header_info = parse_packet(data)
                except PacketError as exc:
                    print(f"[skip] bad OpenTrackIO packet from {addr}: {exc}")
                    continue
            else:
                payload = data

            try:
                sample = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                print(f"[skip] non-JSON datagram from {addr}: {exc}")
                continue

            warnings = validate_sample(sample)
            src = sample.get("sourceId", "<unknown>")
            known_sources[src] = known_sources.get(src, 0) + 1
            count += 1

            if args.raw:
                print(json.dumps(sample, indent=2))
                print("-" * 72)
            else:
                now = time.time()
                # Throttle human-readable output to ~every 100 ms so we can
                # still see the wave moving without drowning the terminal.
                if now - last_print >= 0.1:
                    line = format_sample_line(sample)
                    tag = " ".join(f"[WARN {w}]" for w in warnings) if warnings else ""
                    print(f"{line}  {tag}".rstrip())
                    last_print = now

            if args.count and count >= args.count:
                break
    except KeyboardInterrupt:
        pass

    print(f"\n[opentrackio-client] received {count} samples from "
          f"{len(known_sources)} source(s):")
    for src, n in known_sources.items():
        print(f"  {src}  ->  {n} samples")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OpenTrackIO consumer")
    p.add_argument("--source", type=int, default=1,
                   help="OpenTrackIO Source Number (1..200). Picks the "
                        "multicast group 239.135.1.<source>. Default: 1")
    p.add_argument("--port", type=int, default=OTIO_DEFAULT_PORT,
                   help=f"UDP port. Default: {OTIO_DEFAULT_PORT}")
    p.add_argument("--iface", type=str, default="0.0.0.0",
                   help="Local interface to join the multicast group on. "
                        "Default: 0.0.0.0 (system default).")
    p.add_argument("--unicast", action="store_true",
                   help="Listen on plain unicast on --port instead of "
                        "joining a multicast group.")
    p.add_argument("--raw", action="store_true",
                   help="Print every sample as pretty-printed JSON.")
    p.add_argument("--count", type=int, default=0,
                   help="Exit after receiving N samples (0 = unlimited).")
    return p.parse_args(argv)


if __name__ == "__main__":
    sys.exit(run(parse_args()))
