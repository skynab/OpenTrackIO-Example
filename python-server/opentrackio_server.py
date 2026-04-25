#!/usr/bin/env python3
"""
OpenTrackIO producer (server).

Streams OpenTrackIO JSON samples over UDP to a multicast (or unicast)
destination. Every field that the SMPTE RIS-OSVP / camdkit schema describes
as a dynamic value -- camera rigid-body transform (translation + pan/tilt/roll)
and lens encoders (focus / iris / zoom) together with the derived lens
parameters -- is driven by an independent sine wave so a consumer can see the
full shape of the message without needing a real tracking rig.

Protocol defaults follow the public OpenTrackIO documentation:
    - Transport   : UDPv4
    - Port        : 55555
    - Multicast IP: 239.135.1.<source_number>   (source_number in 1..200)
    - Payload     : one JSON document per UDP datagram

Run:
    python3 opentrackio_server.py                  # multicast, source 1
    python3 opentrackio_server.py --source 7 --rate 60
    python3 opentrackio_server.py --unicast 127.0.0.1   # easy loopback test
"""

from __future__ import annotations

import argparse
import json
import math
import socket
import struct
import sys
import time
import uuid
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# OpenTrackIO constants
# ---------------------------------------------------------------------------

OTIO_PROTOCOL_NAME = "OpenTrackIO"
OTIO_PROTOCOL_VERSION = [1, 0, 1]
OTIO_DEFAULT_PORT = 55555
OTIO_MCAST_BASE = "239.135.1."          # last octet is the source number
OTIO_SOURCE_MIN = 1
OTIO_SOURCE_MAX = 200


def multicast_address_for(source_number: int) -> str:
    if not (OTIO_SOURCE_MIN <= source_number <= OTIO_SOURCE_MAX):
        raise ValueError(
            f"OpenTrackIO source number must be in "
            f"[{OTIO_SOURCE_MIN}, {OTIO_SOURCE_MAX}], got {source_number}"
        )
    return f"{OTIO_MCAST_BASE}{source_number}"


# ---------------------------------------------------------------------------
# OpenTrackIO raw-UDP packet header
#
# Layout matches Unreal Engine 5.7 LiveLinkOpenTrackIOParser.cpp byte-for-byte
# (source confirmed by the UE plugin's own FArchive operator<<). All
# multi-byte integers are big-endian ("network order").
#
#   Offset  Size  Field                          Notes
#   ------  ----  -----------------------------  ------------------------------
#   0       4     identifier (uint32)            0x4F54726B == ASCII 'OTrk'
#   4       1     reserved (uint8)               0
#   5       1     encoding (uint8)               0x01 = JSON, 0x02 = CBOR
#   6       2     sequence (uint16)              increments per *complete* sample
#   8       4     segmentOffset (uint32)         byte offset of this segment in
#                                                the reassembled payload
#  12       2     lastSegmentFlagAndLen (uint16) bit 15 = last-segment flag,
#                                                bits 0-14 = payload bytes in
#                                                THIS segment
#  14       2     checksum (uint16)              Fletcher-16 (mod 256) over the
#                                                concatenation of header[0:14]
#                                                + payload
#  16       N     payload                        JSON text or CBOR
#
# Pass --no-header on the command line to emit bare JSON instead, which is
# useful for Wireshark / nc-based debugging.
# ---------------------------------------------------------------------------

OTIO_HEADER_SIZE          = 16
OTIO_HEADER_IDENTIFIER_U32 = 0x4F54726B   # 'OTrk' as big-endian uint32
OTIO_ENCODING_JSON        = 0x01
OTIO_ENCODING_CBOR        = 0x02
OTIO_LAST_SEGMENT_FLAG    = 0x8000        # top bit of lastSegmentFlagAndLen
OTIO_PAYLOAD_LEN_MASK     = 0x7FFF        # low 15 bits of lastSegmentFlagAndLen
OTIO_MAX_PAYLOAD_PER_SEG  = OTIO_PAYLOAD_LEN_MASK


def fletcher16(data: bytes) -> int:
    """Fletcher-16 over `data`, matching UE's CalculateChecksum (mod 256)."""
    s1 = 0
    s2 = 0
    for b in data:
        s1 = (s1 + b) & 0xFF
        s2 = (s2 + s1) & 0xFF
    return ((s2 << 8) | s1) & 0xFFFF


def build_packet(payload: bytes,
                 sequence: int,
                 encoding: int = OTIO_ENCODING_JSON,
                 segment_offset: int = 0,
                 last_segment: bool = True) -> bytes:
    """Wrap a payload in a UE5.7-compatible OpenTrackIO datagram header.

    For the unfragmented common case, leave segment_offset=0 and
    last_segment=True. Returns the full datagram (header + payload).
    """
    payload_len = len(payload)
    if payload_len > OTIO_MAX_PAYLOAD_PER_SEG:
        raise ValueError(
            f"payload of {payload_len} bytes does not fit in a single "
            f"segment (max {OTIO_MAX_PAYLOAD_PER_SEG}). Implement "
            f"segmentation if you hit this."
        )

    flag_and_len = (OTIO_LAST_SEGMENT_FLAG if last_segment else 0) \
                   | (payload_len & OTIO_PAYLOAD_LEN_MASK)

    # Build the first 14 bytes (header *minus* the checksum field).
    header_no_checksum = struct.pack(
        ">IBBHIH",
        OTIO_HEADER_IDENTIFIER_U32,
        0,                              # reserved
        encoding & 0xFF,                # encoding
        sequence & 0xFFFF,              # sequence number
        segment_offset & 0xFFFFFFFF,    # segment offset
        flag_and_len & 0xFFFF,          # last-segment flag + payload length
    )
    assert len(header_no_checksum) == OTIO_HEADER_SIZE - 2

    # UE computes Fletcher-16 over (header_no_checksum + payload), NOT just
    # the payload. This is the single most common reason for a non-UE
    # implementation to fail UE's checksum gate.
    checksum = fletcher16(header_no_checksum + payload)

    return header_no_checksum + struct.pack(">H", checksum) + payload


# ---------------------------------------------------------------------------
# Sine-wave generator for every streamed value
# ---------------------------------------------------------------------------

@dataclass
class Sine:
    """y = center + amplitude * sin(2*pi*frequency*t + phase)"""
    center: float
    amplitude: float
    frequency: float      # Hz
    phase: float = 0.0    # radians

    def at(self, t: float) -> float:
        return self.center + self.amplitude * math.sin(
            2.0 * math.pi * self.frequency * t + self.phase
        )


# A deliberately varied set of waves so every channel moves differently.
# Units follow the OpenTrackIO schema (metres / degrees / millimetres / etc.).
WAVES = {
    # Camera rigid body translation (metres)
    "tx":            Sine(center=0.0, amplitude=1.0, frequency=0.10, phase=0.0),
    "ty":            Sine(center=1.5, amplitude=0.5, frequency=0.13, phase=math.pi / 3),
    "tz":            Sine(center=2.0, amplitude=0.8, frequency=0.07, phase=math.pi / 2),
    # Camera rigid body rotation (degrees: pan/tilt/roll)
    "pan":           Sine(center=0.0, amplitude=45.0, frequency=0.05, phase=0.0),
    "tilt":          Sine(center=0.0, amplitude=20.0, frequency=0.11, phase=math.pi / 4),
    "roll":          Sine(center=0.0, amplitude=10.0, frequency=0.09, phase=math.pi / 6),
    # Lens encoders (0..1 normalised)
    "focus_enc":     Sine(center=0.5, amplitude=0.5, frequency=0.20, phase=0.0),
    "iris_enc":      Sine(center=0.5, amplitude=0.5, frequency=0.17, phase=math.pi / 5),
    "zoom_enc":      Sine(center=0.5, amplitude=0.5, frequency=0.15, phase=math.pi / 7),
    # Derived lens values
    "focal_length":  Sine(center=35.0, amplitude=15.0, frequency=0.15, phase=0.0),    # mm
    "focus_dist":    Sine(center=3.0,  amplitude=2.5,  frequency=0.20, phase=0.0),    # m
    "f_stop":        Sine(center=4.0,  amplitude=2.0,  frequency=0.08, phase=0.0),    # T/f stop
    "entrance_pupil": Sine(center=0.06, amplitude=0.02, frequency=0.12, phase=0.0),   # m
}


# ---------------------------------------------------------------------------
# Sample builder
# ---------------------------------------------------------------------------

def build_sample(source_id: str,
                 source_number: int,
                 sample_index: int,
                 rate_hz: float,
                 t: float) -> dict:
    """Assemble one OpenTrackIO JSON sample dictionary."""

    # Walltime-derived SMPTE-ish timecode at the given rate.
    total_frames = sample_index
    frame_rate_int = int(round(rate_hz))
    frames = total_frames % frame_rate_int
    total_seconds = total_frames // frame_rate_int
    seconds = total_seconds % 60
    minutes = (total_seconds // 60) % 60
    hours = (total_seconds // 3600) % 24

    sample = {
        "protocol": {
            "name": OTIO_PROTOCOL_NAME,
            "version": OTIO_PROTOCOL_VERSION,
        },
        # Source and sample identification
        "sourceId":     f"urn:uuid:{source_id}",
        "sourceNumber": source_number,
        "sampleId":     f"urn:uuid:{uuid.uuid4()}",

        # Timing
        "timing": {
            "mode": "internal",
            "sampleRate":   {"num": frame_rate_int, "denom": 1},
            "recordedRate": {"num": frame_rate_int, "denom": 1},
            "sampleTimestamp": {
                "seconds":     int(t),
                "nanoseconds": int((t - int(t)) * 1e9),
            },
            "timecode": {
                "hours":   hours,
                "minutes": minutes,
                "seconds": seconds,
                "frames":  frames,
                "frameRate": {"num": frame_rate_int, "denom": 1},
            },
        },

        # Rigid body camera transform (position + orientation)
        "transforms": [
            {
                "id":     "Camera",
                "translation": {
                    "x": WAVES["tx"].at(t),
                    "y": WAVES["ty"].at(t),
                    "z": WAVES["tz"].at(t),
                },
                "rotation": {
                    "pan":  WAVES["pan"].at(t),
                    "tilt": WAVES["tilt"].at(t),
                    "roll": WAVES["roll"].at(t),
                },
            }
        ],

        # Lens block: encoders + derived parameters
        "lens": {
            "encoders": {
                "focus": WAVES["focus_enc"].at(t),
                "iris":  WAVES["iris_enc"].at(t),
                "zoom":  WAVES["zoom_enc"].at(t),
            },
            "pinholeFocalLength": WAVES["focal_length"].at(t),
            "focusDistance":      WAVES["focus_dist"].at(t),
            "fStop":              WAVES["f_stop"].at(t),
            "entrancePupilOffset": WAVES["entrance_pupil"].at(t),
            # OpenTrackIO permits multiple distortion models per lens, so
            # this field is an array. UE5.7's FLiveLinkOpenTrackIOLens.Distortion
            # is a TArray<...> and rejects the whole Lens block if it sees a
            # bare object here ("Expecting JSON array").
            "distortion": [
                {
                    "model":    "Brown-Conrady",
                    "radial":     [0.0, 0.0, 0.0],
                    "tangential": [0.0, 0.0],
                },
            ],
        },

        # Tracker block: per-frame tracker state.
        "tracker": {
            "notes":     "OpenTrackIO sine-wave demo producer",
            "recording": False,
            "slate":     "Demo",
            "status":    "Optical Good",
        },

        # Static block: unchanging identity of the producer / rig.
        #
        # NOTE: UE5.7's FLiveLinkOpenTrackIOStaticCamera::IsValid() requires
        # all of make/model/serialNumber/**label** to be non-empty before the
        # plugin will register a Live Link subject. Drop any of these and you
        # will see "Receiving" in the plugin but no subject populates.
        # ConvertTypeToFName() uses Label (preferred) or Make_Model as the
        # subject's display name in Live Link.
        "static": {
            "duration": {"num": 0, "denom": 1},
            "camera": {
                "make":         "OpenTrackIO-SineCam",
                "model":        "Demo-1",
                "serialNumber": "0000-DEMO",
                "firmwareVersion": "0.1.0",
                "label":        "SineCam",
                "activeSensorPhysicalDimensions": {"height": 24.0, "width": 36.0},
                "activeSensorResolution":         {"height": 2160, "width": 3840},
                "captureFrameRate":  {"num": frame_rate_int, "denom": 1},
                "anamorphicSqueeze": {"num": 1, "denom": 1},
                "isoSpeed":     400,
                "shutterAngle": 180.0,
            },
            "lens": {
                "make":         "OpenTrackIO-SineLens",
                "model":        "Zoom 24-70",
                "serialNumber": "0000-LENS",
                "firmwareVersion":      "0.1.0",
                "nominalFocalLength":   35.0,
                "distortionOverscanMax":   1.0,
                "undistortionOverscanMax": 1.0,
            },
            "tracker": {
                "make":         "OpenTrackIO-SineTracker",
                "model":        "Tracker-1",
                "serialNumber": "0000-TRK",
                "firmwareVersion": "0.1.0",
            },
        },
    }
    return sample


# ---------------------------------------------------------------------------
# Socket setup
# ---------------------------------------------------------------------------

def make_multicast_socket(ttl: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(
        socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", ttl)
    )
    # Let the local loopback interface see our traffic so a client on the
    # same box can subscribe and receive.
    sock.setsockopt(
        socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, struct.pack("b", 1)
    )
    return sock


def make_unicast_socket() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    if args.unicast:
        dest_host = args.unicast
        sock = make_unicast_socket()
        mode_descr = f"unicast to {dest_host}:{args.port}"
    else:
        dest_host = multicast_address_for(args.source)
        sock = make_multicast_socket(ttl=args.ttl)
        mode_descr = (
            f"multicast to {dest_host}:{args.port} "
            f"(source number {args.source}, TTL {args.ttl})"
        )

    source_id = str(uuid.uuid4())
    period = 1.0 / args.rate
    count = 0
    start = time.time()

    print(f"[opentrackio-server] streaming {mode_descr}")
    print(f"[opentrackio-server] sourceId urn:uuid:{source_id}")
    print(f"[opentrackio-server] rate {args.rate} Hz -- Ctrl+C to stop")

    try:
        while True:
            t = time.time() - start
            sample = build_sample(
                source_id=source_id,
                source_number=args.source,
                sample_index=count,
                rate_hz=args.rate,
                t=t,
            )
            payload = json.dumps(sample, separators=(",", ":")).encode("utf-8")
            if args.no_header:
                datagram = payload
            else:
                datagram = build_packet(payload, sequence=count)
            sock.sendto(datagram, (dest_host, args.port))

            if args.verbose and count % max(1, int(args.rate)) == 0:
                tr = sample["transforms"][0]
                ln = sample["lens"]
                print(
                    f"[{count:06d}] t={t:7.3f}s  "
                    f"pos=({tr['translation']['x']:+.3f},"
                    f"{tr['translation']['y']:+.3f},"
                    f"{tr['translation']['z']:+.3f})  "
                    f"rot=(p{tr['rotation']['pan']:+.2f},"
                    f"t{tr['rotation']['tilt']:+.2f},"
                    f"r{tr['rotation']['roll']:+.2f})  "
                    f"fl={ln['pinholeFocalLength']:.2f}mm  "
                    f"fd={ln['focusDistance']:.2f}m  "
                    f"T{ln['fStop']:.2f}  "
                    f"bytes={len(datagram)}"
                )

            count += 1
            next_tick = start + count * period
            delay = next_tick - time.time()
            if delay > 0:
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n[opentrackio-server] stopped after {count} samples")
        return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OpenTrackIO sine-wave producer")
    p.add_argument("--source", type=int, default=1,
                   help="OpenTrackIO Source Number (1..200). Determines the "
                        "multicast destination 239.135.1.<source>. Default: 1")
    p.add_argument("--port", type=int, default=OTIO_DEFAULT_PORT,
                   help=f"UDP port. Default: {OTIO_DEFAULT_PORT}")
    p.add_argument("--rate", type=float, default=60.0,
                   help="Sample rate in Hz. Default: 60")
    p.add_argument("--ttl", type=int, default=1,
                   help="Multicast TTL. Default: 1 (link-local)")
    p.add_argument("--unicast", type=str, default=None,
                   help="Send to this unicast host instead of multicast "
                        "(useful for local testing without IGMP).")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print one human-readable summary per second.")
    p.add_argument("--no-header", action="store_true",
                   help="Send the raw JSON payload with no OpenTrackIO "
                        "packet header. Use with consumers that expect "
                        "plain-JSON datagrams. Default: header is included "
                        "(required by the UE LiveLinkOpenTrackIO plugin).")
    return p.parse_args(argv)


if __name__ == "__main__":
    sys.exit(run(parse_args()))
