# OpenTrackIO sine-wave server + client

Minimal reference implementation of the SMPTE RIS-OSVP
[OpenTrackIO](https://ris-pub.smpte.org/ris-osvp-metadata-camdkit/) protocol.

Everything lives in three sibling folders:

```
python-server/   opentrackio_server.py          Python reference producer
python-client/   opentrackio_client.py          Python CLI consumer
                 opentrackio_client_ui.py       Python tkinter dashboard consumer
cpp-server/      opentrackio_server.cpp         Cross-platform C++17 producer
                 CMakeLists.txt                 CMake build script
```

The server streams OpenTrackIO samples over UDP. Each datagram is a
JSON payload wrapped in an 18-byte OpenTrackIO packet header (`OTrk`
identifier + sequence/segment fields + Fletcher-16 payload checksum),
which is what Unreal Engine 5.7's `LiveLinkOpenTrackIO` plugin and other
conformant consumers expect on the wire. Pass `--no-header` to either
server to emit bare JSON instead, for quick-and-dirty inspection with
`nc` / Wireshark. Every dynamic value — the camera rigid-body transform
(x/y/z plus pan/tilt/roll) and the lens encoders and derived lens
parameters (focus, iris, zoom, focal length, focus distance, fStop,
entrance pupil offset) — is driven by its own sine wave, so a consumer
sees the full shape of the message without needing a real tracking rig.

The client joins the multicast group, auto-detects wrapped vs. raw
datagrams, parses each JSON sample, and either prints a compact summary
line (CLI) or renders a live dashboard (UI).

## Protocol defaults

| Thing | Value |
|-------|-------|
| Transport | UDPv4, one JSON document per datagram |
| Port | `55555` |
| Multicast group | `239.135.1.<source_number>` where `source_number ∈ 1..200` (UE5.7 plugin default: `239.135.1.1:55555`) |
| TTL | `1` (link-local by default) |

These match the public OpenTrackIO documentation: the Source Number is an
8-bit value that selects the last octet of the multicast address, allowing
producers and consumers to meet without prior IP-level configuration.

## Sample shape

Each datagram is a single JSON object of the form:

```json
{
  "protocol":     {"name": "OpenTrackIO", "version": [1,0,1]},
  "sourceId":     "urn:uuid:...",
  "sourceNumber": 1,
  "sampleId":     "urn:uuid:...",
  "timing":       {"mode":"internal","sampleRate":{...},"timecode":{...}, ...},
  "transforms": [
    {
      "id": "Camera",
      "translation": {"x": 0.21, "y": 1.98, "z": 2.79},
      "rotation":    {"pan": 4.78, "tilt": 17.04, "roll": 6.56}
    }
  ],
  "lens": {
    "encoders":           {"focus": 0.71, "iris": 0.92, "zoom": 0.85},
    "pinholeFocalLength": 39.70,
    "focusDistance":       4.03,
    "fStop":               4.34,
    "entrancePupilOffset": 0.065,
    "distortion": [{"model":"Brown-Conrady","radial":[0,0,0],"tangential":[0,0]}]
  },
  "tracker": {"notes":"...", "recording":false, "slate":"Demo", "status":"Optical Good"},
  "static": {
    "duration": {"num":0,"denom":1},
    "camera":  {"make":"...","model":"...","serialNumber":"...","label":"...", ...},
    "lens":    {"make":"...","model":"...","serialNumber":"...", ...},
    "tracker": {"make":"...","model":"...","serialNumber":"..."}
  }
}
```

### `static.camera` requires a `label`

UE5.7's `FLiveLinkOpenTrackIOStaticCamera::IsValid()` requires
**all four** of `make`, `model`, `serialNumber`, **and `label`** to be
non-empty before the plugin will register a Live Link subject. If any
of these is missing, the OpenTrackIO source will show **Status =
"Receiving"** in the Live Link panel but no subject will populate.
The plugin's `ConvertTypeToFName()` uses `Label` (preferred) or
`Make_Model` to build the subject's display name.

`fStop`, `pinholeFocalLength`, and `focusDistance` are typed as
`FOpenTrackIOOptionalFloat` in UE, but the plugin's parser has a
custom JSON importer (`TryReadStructOptional`) that accepts bare
numbers and sets `bIsSet = true` automatically — you can send them
either as `4.34` or as `{"bIsSet": true, "Value": 4.34}` and both work.

## Packet header (wrapping the JSON payload)

Each UDP datagram is built as `[16-byte header][JSON payload]`. The
header layout matches Unreal Engine 5.7's
`LiveLinkOpenTrackIOParser.cpp` byte-for-byte (verified against the UE
plugin's own `FArchive operator<<`). All multi-byte integers are
big-endian (network byte order):

| Offset | Size | Field                       | Notes                                                                                |
|-------:|-----:|-----------------------------|--------------------------------------------------------------------------------------|
|      0 |    4 | identifier (`uint32`)       | `0x4F54726B` == ASCII `OTrk`                                                         |
|      4 |    1 | reserved (`uint8`)          | `0`                                                                                  |
|      5 |    1 | encoding (`uint8`)          | `0x01` = JSON, `0x02` = CBOR                                                         |
|      6 |    2 | sequence (`uint16`)         | Increments per *complete* sample                                                     |
|      8 |    4 | segmentOffset (`uint32`)    | Byte offset of this segment in the reassembled payload (0 if unfragmented)           |
|     12 |    2 | lastSegFlagAndLen (`uint16`)| Bit 15 = last-segment flag (`0x8000`); bits 0-14 = payload length in *this* segment  |
|     14 |    2 | checksum (`uint16`)         | Fletcher-16 (mod 256) over `header[0:14]` **+** `payload`                            |

Fletcher-16 is computed over the concatenation of the first 14 header
bytes (everything except the checksum field itself) and the payload
bytes, with running sums reduced modulo 256 — the reference
implementation is `fletcher16` in `python-server/opentrackio_server.py`.
Note: a common mistake is to checksum only the payload; UE5.7 will
reject those packets with `"Failed to verify packet checksum."`.

For an unfragmented sample the producer sets `segmentOffset = 0` and
`lastSegFlagAndLen = 0x8000 | payload_len` (top bit on, payload length
in the low 15 bits — so per-segment payload max is 32 767 bytes;
larger samples need to be split across multiple datagrams).

Passing `--no-header` on either server skips the wrapper and emits bare
JSON. The Python client and dashboard auto-detect the format (presence
of the `OTrk` magic); UE5.7's `LiveLinkOpenTrackIO` plugin **does
require** the wrapper, so leave it on for Unreal.

## Quick start — multicast (typical VP LAN)

```bash
# Terminal 1
python3 python-server/opentrackio_server.py --source 1 --rate 60 --verbose

# Terminal 2
python3 python-client/opentrackio_client.py --source 1
```

Both must use the same `--source` number so they end up on the same
multicast group (`239.135.1.<source>`).

## Quick start — loopback unicast (no multicast required)

Handy for local development, containers without IGMP, or CI:

```bash
# Terminal 1
python3 python-server/opentrackio_server.py --unicast 127.0.0.1 --rate 60 --verbose

# Terminal 2
python3 python-client/opentrackio_client.py --unicast
```

## Server options

```
--source N        OpenTrackIO Source Number (1..200). Default: 1.
--port P          UDP port. Default: 55555.
--rate HZ         Sample rate. Default: 60.
--ttl N           Multicast TTL. Default: 1.
--unicast HOST    Send unicast to HOST instead of multicast.
--no-header       Emit bare JSON with no OTrk wrapper (for debugging).
--verbose         Print one summary line per second.
```

## Client options

```
--source N        Multicast group 239.135.1.N. Default: 1.
--port P          UDP port. Default: 55555.
--iface IP        Local interface for the multicast join. Default: 0.0.0.0.
--unicast         Listen on plain unicast on --port.
--raw             Pretty-print every sample as JSON instead of a summary line.
--count N         Exit after N samples (0 = unlimited).
```

## Unreal Engine 5.7 LiveLinkOpenTrackIO

To drive the `LiveLinkOpenTrackIO` Live Link source in Unreal Engine
5.7, run either server with the default settings (the OTrk wrapper is
on by default) and point UE at the same port / multicast group:

```bash
python3 python-server/opentrackio_server.py --source 1 --rate 60
# or
./cpp-server/build/opentrackio_server --source 1 --rate 60
```

In the Unreal editor, open **Window → Virtual Production → Live Link**,
add an **OpenTrackIO** source, and select the matching source number
(1..200 — selects multicast group `239.135.1.<N>`) or enter the
unicast host/port if you launched the server with `--unicast`.

## Expected output

Server (with `--verbose`):

```
[opentrackio-server] streaming unicast to 127.0.0.1:55555
[opentrackio-server] sourceId urn:uuid:f63573f6-...
[opentrackio-server] rate 60.0 Hz -- Ctrl+C to stop
[000060] t=  1.000s  pos=(+0.588,+1.993,+2.349)  rot=(p+14.04,t+13.42,r+5.21) ...
```

Client:

```
TC 00:00:00:10  pos=(+0.211,+1.985,+2.791)  rot=(p +4.78 t+17.04 r +6.56)
    enc(f0.706 i0.918 z0.847)  fl=39.71mm  fd=4.03m  T4.34
```

## Dashboard UI

`python-client/opentrackio_client_ui.py` is a tkinter dashboard variant of
the client. It runs the same network listener on a background thread and
shows:

* a numeric readout of every field (timecode, position, rotation, lens),
* horizontal bars for the focus / iris / zoom lens encoders,
* rolling 10-second history graphs for position (x/y/z) and rotation
  (pan/tilt/roll), drawn directly on a `tk.Canvas` (no matplotlib),
* a connection / rate indicator (destination, packets/sec, live/stale).

Same flags as the CLI client:

```bash
python3 python-client/opentrackio_client_ui.py --unicast     # localhost
python3 python-client/opentrackio_client_ui.py --source 1    # multicast
```

**Requires tkinter.** tkinter ships with the official Python installers on
Windows and macOS. On Debian/Ubuntu install it with:

```bash
sudo apt-get install python3-tk
```

## C++ server (cross-platform)

`cpp-server/opentrackio_server.cpp` is a C++17 port of the producer. Same
wire format, same flags, no third-party dependencies. Builds on Windows
(Winsock2), Linux, and macOS.

Build with CMake:

```bash
cd cpp-server
cmake -B build && cmake --build build --config Release
```

Or directly:

```bash
cd cpp-server

# Linux / macOS
c++ -std=c++17 -O2 -o opentrackio_server opentrackio_server.cpp

# Windows (MSVC developer prompt)
cl /std:c++17 /O2 opentrackio_server.cpp ws2_32.lib
```

Usage is identical to the Python server:

```bash
./opentrackio_server --unicast 127.0.0.1 --rate 60 --verbose
./opentrackio_server --source 1 --rate 60
```

## Files

| Path | Purpose |
|------|---------|
| `python-server/opentrackio_server.py`      | Python producer reference. |
| `python-client/opentrackio_client.py`      | Python consumer (CLI). Joins the group, parses + prints samples. |
| `python-client/opentrackio_client_ui.py`   | Python consumer (tkinter dashboard) with live readouts, encoder bars, rolling graphs. |
| `cpp-server/opentrackio_server.cpp`        | Cross-platform C++17 producer (no deps). |
| `cpp-server/CMakeLists.txt`                | CMake build script for the C++ server. |
| `README.md`                                | This document. |
