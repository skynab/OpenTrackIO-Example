// opentrackio_server.cpp
//
// Cross-platform C++17 OpenTrackIO producer.
//
// Streams OpenTrackIO JSON samples (SMPTE RIS-OSVP / camdkit) over UDP to a
// multicast or unicast destination. Every dynamic value -- camera rigid-body
// transform (x/y/z, pan/tilt/roll) and lens encoders + derived parameters
// (focus/iris/zoom, focal length, focus distance, fStop, entrance pupil) --
// is driven by an independent sine wave.
//
// Protocol defaults:
//   Transport    : UDPv4
//   Port         : 55555
//   Multicast IP : 239.135.1.<source_number>  (1..200)
//   Payload      : one JSON document per UDP datagram
//
// Build (Linux / macOS):
//     c++ -std=c++17 -O2 -o opentrackio_server opentrackio_server.cpp
//
// Build (Windows, MSVC developer prompt):
//     cl /std:c++17 /O2 opentrackio_server.cpp ws2_32.lib
//
// Or use the supplied CMakeLists.txt:
//     cmake -B build && cmake --build build --config Release
//
// No third-party dependencies.

// ---------------------------------------------------------------------------
// Platform compatibility
// ---------------------------------------------------------------------------
#if defined(_WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  using socket_t = SOCKET;
  static constexpr socket_t kInvalidSocket = INVALID_SOCKET;
  static inline int close_socket(socket_t s) { return ::closesocket(s); }
  static inline int sock_errno() { return WSAGetLastError(); }
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <errno.h>
  using socket_t = int;
  static constexpr socket_t kInvalidSocket = -1;
  static inline int close_socket(socket_t s) { return ::close(s); }
  static inline int sock_errno() { return errno; }
#endif

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// OpenTrackIO constants
// ---------------------------------------------------------------------------
static constexpr const char* kProtocolName    = "OpenTrackIO";
static constexpr int         kProtoVerMajor   = 1;
static constexpr int         kProtoVerMinor   = 0;
static constexpr int         kProtoVerPatch   = 1;
static constexpr int         kDefaultPort     = 55555;
static constexpr const char* kMulticastBase   = "239.135.1."; // last octet = source number
static constexpr int         kSourceMin       = 1;
static constexpr int         kSourceMax       = 200;

// OpenTrackIO raw-UDP packet header. Layout matches Unreal Engine 5.7
// LiveLinkOpenTrackIOParser.cpp byte-for-byte (verified against the UE
// FArchive operator<< for FLiveLinkOpenTrackIODatagramHeader). Each
// datagram is prefixed with this 16-byte structure, big-endian
// ("network order"). Pass --no-header to emit bare JSON instead.
//
//   Offset  Size  Field                     Notes
//   0       4     identifier (uint32)       0x4F54726B == ASCII 'OTrk'
//   4       1     reserved (uint8)          0
//   5       1     encoding (uint8)          0x01 = JSON, 0x02 = CBOR
//   6       2     sequence (uint16)         per *complete* sample
//   8       4     segmentOffset (uint32)    byte offset in reassembled payload
//   12      2     lastSegFlagAndLen (uint16) bit 15 = last segment,
//                                            bits 0-14 = payload length
//   14      2     checksum (uint16)         Fletcher-16 over header[0:14]
//                                            + payload, mod 256
//   16      N     payload                   JSON or CBOR
static constexpr size_t   kHeaderSize         = 16;
static constexpr uint8_t  kHeaderIdBytes[4]   = {'O', 'T', 'r', 'k'};
static constexpr uint8_t  kEncodingJson       = 0x01;
static constexpr uint8_t  kEncodingCbor       = 0x02;
static constexpr uint16_t kLastSegmentFlag    = 0x8000;
static constexpr uint16_t kPayloadLenMask     = 0x7FFF;

// Fletcher-16 over `data`, mod 256, matching UE5.7 CalculateChecksum.
static uint16_t fletcher16(const uint8_t* data, size_t len) {
    uint8_t s1 = 0, s2 = 0;
    for (size_t i = 0; i < len; ++i) {
        s1 = static_cast<uint8_t>(s1 + data[i]);
        s2 = static_cast<uint8_t>(s2 + s1);
    }
    return static_cast<uint16_t>((static_cast<uint16_t>(s2) << 8)
                                 | static_cast<uint16_t>(s1));
}

// Stateful Fletcher-16 used to checksum the concatenation of (header[0:14],
// payload) without copying — UE feeds the header bytes first, then the
// payload, into a single running accumulator.
static uint16_t fletcher16_concat(const uint8_t* header, size_t header_len,
                                  const uint8_t* payload, size_t payload_len) {
    uint8_t s1 = 0, s2 = 0;
    for (size_t i = 0; i < header_len; ++i) {
        s1 = static_cast<uint8_t>(s1 + header[i]);
        s2 = static_cast<uint8_t>(s2 + s1);
    }
    for (size_t i = 0; i < payload_len; ++i) {
        s1 = static_cast<uint8_t>(s1 + payload[i]);
        s2 = static_cast<uint8_t>(s2 + s1);
    }
    return static_cast<uint16_t>((static_cast<uint16_t>(s2) << 8)
                                 | static_cast<uint16_t>(s1));
}

static std::vector<uint8_t> build_packet(const std::string& payload,
                                         uint16_t sequence,
                                         uint8_t  encoding       = kEncodingJson,
                                         uint32_t segment_offset = 0,
                                         bool     last_segment   = true) {
    const auto* payload_bytes =
        reinterpret_cast<const uint8_t*>(payload.data());
    const size_t payload_len = payload.size();
    if (payload_len > kPayloadLenMask) {
        std::fprintf(stderr,
            "OpenTrackIO payload too large for a single segment "
            "(%zu > %u). Implement segmentation.\n",
            payload_len, kPayloadLenMask);
        std::exit(2);
    }

    const uint16_t flag_and_len =
        static_cast<uint16_t>((last_segment ? kLastSegmentFlag : 0u)
                              | (static_cast<uint16_t>(payload_len)
                                 & kPayloadLenMask));

    // Build the first 14 bytes (header *minus* the checksum field), so we
    // can both checksum it and emit it in one go.
    std::array<uint8_t, kHeaderSize - 2> hdr{};
    size_t i = 0;
    hdr[i++] = kHeaderIdBytes[0];
    hdr[i++] = kHeaderIdBytes[1];
    hdr[i++] = kHeaderIdBytes[2];
    hdr[i++] = kHeaderIdBytes[3];
    hdr[i++] = 0;            // reserved
    hdr[i++] = encoding;     // encoding
    hdr[i++] = static_cast<uint8_t>((sequence >> 8) & 0xFF);
    hdr[i++] = static_cast<uint8_t>(sequence & 0xFF);
    hdr[i++] = static_cast<uint8_t>((segment_offset >> 24) & 0xFF);
    hdr[i++] = static_cast<uint8_t>((segment_offset >> 16) & 0xFF);
    hdr[i++] = static_cast<uint8_t>((segment_offset >>  8) & 0xFF);
    hdr[i++] = static_cast<uint8_t>(segment_offset & 0xFF);
    hdr[i++] = static_cast<uint8_t>((flag_and_len >> 8) & 0xFF);
    hdr[i++] = static_cast<uint8_t>(flag_and_len & 0xFF);

    // Fletcher-16 over (header_minus_checksum + payload).
    const uint16_t checksum =
        fletcher16_concat(hdr.data(), hdr.size(),
                          payload_bytes, payload_len);

    std::vector<uint8_t> out;
    out.reserve(kHeaderSize + payload_len);
    out.insert(out.end(), hdr.begin(), hdr.end());
    out.push_back(static_cast<uint8_t>((checksum >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(checksum & 0xFF));
    out.insert(out.end(), payload_bytes, payload_bytes + payload_len);
    return out;
}

// ---------------------------------------------------------------------------
// Platform helpers
// ---------------------------------------------------------------------------
struct NetStartup {
    NetStartup() {
#if defined(_WIN32)
        WSADATA wsa;
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::fprintf(stderr, "WSAStartup failed\n");
            std::exit(1);
        }
#endif
    }
    ~NetStartup() {
#if defined(_WIN32)
        ::WSACleanup();
#endif
    }
};

// ---------------------------------------------------------------------------
// Random UUID v4 (RFC 4122) — no OS-specific libs
// ---------------------------------------------------------------------------
static std::string make_uuid_v4() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> dist;

    uint64_t hi = dist(rng);
    uint64_t lo = dist(rng);

    // Set version (4) and variant (10xx) bits per RFC 4122.
    hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    std::array<uint8_t, 16> b{};
    for (int i = 0; i < 8; ++i) {
        b[i]     = static_cast<uint8_t>((hi >> (8 * (7 - i))) & 0xFF);
        b[8 + i] = static_cast<uint8_t>((lo >> (8 * (7 - i))) & 0xFF);
    }

    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(36);
    for (int i = 0; i < 16; ++i) {
        s.push_back(hex[b[i] >> 4]);
        s.push_back(hex[b[i] & 0xF]);
        if (i == 3 || i == 5 || i == 7 || i == 9) s.push_back('-');
    }
    return s;
}

// ---------------------------------------------------------------------------
// Sine channel
// ---------------------------------------------------------------------------
struct Sine {
    double center;
    double amplitude;
    double frequency; // Hz
    double phase;     // radians

    double at(double t) const {
        constexpr double two_pi = 6.283185307179586476925286766559;
        return center + amplitude * std::sin(two_pi * frequency * t + phase);
    }
};

// ---------------------------------------------------------------------------
// Minimal JSON writer
//
// We only need to emit a fixed-shape document with numbers, strings, arrays
// and objects, so pulling in a full JSON library is overkill. This helper
// keeps output compact (no whitespace) which is what you want on the wire.
// ---------------------------------------------------------------------------
class JsonWriter {
public:
    // Opening a container is itself a value (an item in its parent array, or
    // the value side of an object key), so we use the value-separator rule.
    void obj_open()  { emit_value_sep(); put('{'); first_item_.push_back(true); }
    void obj_close() { put('}'); first_item_.pop_back(); }
    void arr_open()  { emit_value_sep(); put('['); first_item_.push_back(true); }
    void arr_close() { put(']'); first_item_.pop_back(); }

    // Keys mark the start of a new item in an object; the following value is
    // part of the same item, so it must NOT emit another comma.
    void key(const char* k) {
        emit_item_sep();
        write_string(k);
        put(':');
        expecting_value_ = true;
    }

    void str(const std::string& s) { emit_value_sep(); write_string(s); }
    void str(const char* s)        { emit_value_sep(); write_string(s); }
    void boolean(bool b)           { emit_value_sep(); out_ += b ? "true" : "false"; }
    void null_()                   { emit_value_sep(); out_ += "null"; }

    void integer(long long v) {
        emit_value_sep();
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld", v);
        out_ += buf;
    }
    void uinteger(unsigned long long v) {
        emit_value_sep();
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%llu", v);
        out_ += buf;
    }
    void number(double v) {
        emit_value_sep();
        char buf[48];
        // %.17g round-trips any IEEE-754 double.
        std::snprintf(buf, sizeof(buf), "%.17g", v);
        out_ += buf;
    }

    // Emit: "k": {"num": ..., "denom": ...}
    void rational(const char* k, long long num, long long denom) {
        key(k); obj_open();
          key("num");   integer(num);
          key("denom"); integer(denom);
        obj_close();
    }

    std::string take() { return std::move(out_); }

private:
    void put(char c) { out_.push_back(c); }

    // Called before writing any new *item* into the current container. An
    // item is: one key-value pair in an object, or one value in an array.
    void emit_item_sep() {
        if (first_item_.empty()) return;        // top level, nothing to do
        if (first_item_.back()) {               // first item in this container
            first_item_.back() = false;
            return;
        }
        put(',');                               // subsequent item
    }

    // Called before writing any value. If we just wrote a key, the value is
    // part of the same item and we suppress the item separator.
    void emit_value_sep() {
        if (expecting_value_) { expecting_value_ = false; return; }
        emit_item_sep();
    }

    void write_string(const std::string& s) {
        put('"');
        for (char c : s) write_char(c);
        put('"');
    }
    void write_string(const char* s) {
        put('"');
        for (; *s; ++s) write_char(*s);
        put('"');
    }
    void write_char(char c) {
        switch (c) {
            case '"':  out_ += "\\\""; break;
            case '\\': out_ += "\\\\"; break;
            case '\b': out_ += "\\b";  break;
            case '\f': out_ += "\\f";  break;
            case '\n': out_ += "\\n";  break;
            case '\r': out_ += "\\r";  break;
            case '\t': out_ += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out_ += buf;
                } else {
                    out_.push_back(c);
                }
        }
    }

    std::string out_;
    std::vector<bool> first_item_;        // per-container "no items yet" flag
    bool              expecting_value_ = false;
};

// ---------------------------------------------------------------------------
// Wave table — one sine per dynamic field
// ---------------------------------------------------------------------------
struct WaveTable {
    // translation (metres)
    Sine tx { 0.0, 1.0, 0.10, 0.0 };
    Sine ty { 1.5, 0.5, 0.13, 1.0471975511965976 }; // pi/3
    Sine tz { 2.0, 0.8, 0.07, 1.5707963267948966 }; // pi/2
    // rotation (degrees)
    Sine pan  { 0.0, 45.0, 0.05, 0.0 };
    Sine tilt { 0.0, 20.0, 0.11, 0.7853981633974483 }; // pi/4
    Sine roll { 0.0, 10.0, 0.09, 0.5235987755982988 }; // pi/6
    // lens encoders (0..1)
    Sine focusEnc { 0.5, 0.5, 0.20, 0.0 };
    Sine irisEnc  { 0.5, 0.5, 0.17, 0.6283185307179586 }; // pi/5
    Sine zoomEnc  { 0.5, 0.5, 0.15, 0.4487989505128276 }; // pi/7
    // derived lens
    Sine focalLength   { 35.0, 15.0, 0.15, 0.0 };
    Sine focusDistance { 3.0,  2.5,  0.20, 0.0 };
    Sine fStop         { 4.0,  2.0,  0.08, 0.0 };
    Sine entrancePupil { 0.06, 0.02, 0.12, 0.0 };
};

// ---------------------------------------------------------------------------
// Sample builder
// ---------------------------------------------------------------------------
struct Timecode {
    int hours{}, minutes{}, seconds{}, frames{};
};
static Timecode timecode_from_index(long long idx, int rate) {
    Timecode tc;
    long long totalSec = idx / rate;
    tc.frames  = static_cast<int>(idx % rate);
    tc.seconds = static_cast<int>(totalSec % 60);
    tc.minutes = static_cast<int>((totalSec / 60) % 60);
    tc.hours   = static_cast<int>((totalSec / 3600) % 24);
    return tc;
}

static std::string build_sample_json(const std::string& source_id,
                                     int source_number,
                                     long long sample_index,
                                     double rate_hz,
                                     double t,
                                     const WaveTable& w) {
    const int rate_int = static_cast<int>(std::lround(rate_hz));
    const Timecode tc = timecode_from_index(sample_index, rate_int);

    long long ts_sec  = static_cast<long long>(t);
    long long ts_nsec = static_cast<long long>((t - static_cast<double>(ts_sec)) * 1e9);

    JsonWriter j;
    j.obj_open();

    // protocol
    j.key("protocol"); j.obj_open();
        j.key("name");    j.str(kProtocolName);
        j.key("version"); j.arr_open();
            j.integer(kProtoVerMajor);
            j.integer(kProtoVerMinor);
            j.integer(kProtoVerPatch);
        j.arr_close();
    j.obj_close();

    j.key("sourceId");     j.str("urn:uuid:" + source_id);
    j.key("sourceNumber"); j.integer(source_number);
    j.key("sampleId");     j.str("urn:uuid:" + make_uuid_v4());

    // timing
    j.key("timing"); j.obj_open();
        j.key("mode"); j.str("internal");
        j.rational("sampleRate",   rate_int, 1);
        j.rational("recordedRate", rate_int, 1);
        j.key("sampleTimestamp"); j.obj_open();
            j.key("seconds");     j.integer(ts_sec);
            j.key("nanoseconds"); j.integer(ts_nsec);
        j.obj_close();
        j.key("timecode"); j.obj_open();
            j.key("hours");   j.integer(tc.hours);
            j.key("minutes"); j.integer(tc.minutes);
            j.key("seconds"); j.integer(tc.seconds);
            j.key("frames");  j.integer(tc.frames);
            j.rational("frameRate", rate_int, 1);
        j.obj_close();
    j.obj_close();

    // transforms[0]: Camera rigid body
    j.key("transforms"); j.arr_open();
        j.obj_open();
            j.key("id"); j.str("Camera");
            j.key("translation"); j.obj_open();
                j.key("x"); j.number(w.tx.at(t));
                j.key("y"); j.number(w.ty.at(t));
                j.key("z"); j.number(w.tz.at(t));
            j.obj_close();
            j.key("rotation"); j.obj_open();
                j.key("pan");  j.number(w.pan.at(t));
                j.key("tilt"); j.number(w.tilt.at(t));
                j.key("roll"); j.number(w.roll.at(t));
            j.obj_close();
        j.obj_close();
    j.arr_close();

    // lens
    j.key("lens"); j.obj_open();
        j.key("encoders"); j.obj_open();
            j.key("focus"); j.number(w.focusEnc.at(t));
            j.key("iris");  j.number(w.irisEnc.at(t));
            j.key("zoom");  j.number(w.zoomEnc.at(t));
        j.obj_close();
        j.key("pinholeFocalLength"); j.number(w.focalLength.at(t));
        j.key("focusDistance");      j.number(w.focusDistance.at(t));
        j.key("fStop");              j.number(w.fStop.at(t));
        j.key("entrancePupilOffset"); j.number(w.entrancePupil.at(t));
        // OpenTrackIO permits multiple distortion models per lens, so this
        // field is an array. UE5.7's FLiveLinkOpenTrackIOLens.Distortion is
        // a TArray<...> and rejects the whole Lens block if it sees a bare
        // object here ("Expecting JSON array").
        j.key("distortion"); j.arr_open();
            j.obj_open();
                j.key("model"); j.str("Brown-Conrady");
                j.key("radial"); j.arr_open();
                    j.number(0.0); j.number(0.0); j.number(0.0);
                j.arr_close();
                j.key("tangential"); j.arr_open();
                    j.number(0.0); j.number(0.0);
                j.arr_close();
            j.obj_close();
        j.arr_close();
    j.obj_close();

    // tracker (per-frame state of the tracking system)
    j.key("tracker"); j.obj_open();
        j.key("notes");     j.str("OpenTrackIO sine-wave demo producer");
        j.key("recording"); j.boolean(false);
        j.key("slate");     j.str("Demo");
        j.key("status");    j.str("Optical Good");
    j.obj_close();

    // static — unchanging identity of the producer / rig.
    //
    // NOTE: UE5.7's FLiveLinkOpenTrackIOStaticCamera::IsValid() requires
    // make/model/serialNumber/**label** to ALL be non-empty before the plugin
    // will register a Live Link subject. Drop any of these and the plugin
    // will say "Receiving" but no subject will populate. ConvertTypeToFName()
    // uses Label (preferred) or Make_Model as the subject's display name.
    j.key("static"); j.obj_open();
        j.rational("duration", 0, 1);
        j.key("camera"); j.obj_open();
            j.key("make");             j.str("OpenTrackIO-SineCam");
            j.key("model");            j.str("Demo-1");
            j.key("serialNumber");     j.str("0000-DEMO");
            j.key("firmwareVersion");  j.str("0.1.0");
            j.key("label");            j.str("SineCam");
            j.key("activeSensorPhysicalDimensions"); j.obj_open();
                j.key("height"); j.number(24.0);
                j.key("width");  j.number(36.0);
            j.obj_close();
            j.key("activeSensorResolution"); j.obj_open();
                j.key("height"); j.integer(2160);
                j.key("width");  j.integer(3840);
            j.obj_close();
            j.rational("captureFrameRate", rate_int, 1);
            j.rational("anamorphicSqueeze", 1, 1);
            j.key("isoSpeed");     j.integer(400);
            j.key("shutterAngle"); j.number(180.0);
        j.obj_close();
        j.key("lens"); j.obj_open();
            j.key("make");            j.str("OpenTrackIO-SineLens");
            j.key("model");           j.str("Zoom 24-70");
            j.key("serialNumber");    j.str("0000-LENS");
            j.key("firmwareVersion"); j.str("0.1.0");
            j.key("nominalFocalLength");      j.number(35.0);
            j.key("distortionOverscanMax");   j.number(1.0);
            j.key("undistortionOverscanMax"); j.number(1.0);
        j.obj_close();
        j.key("tracker"); j.obj_open();
            j.key("make");            j.str("OpenTrackIO-SineTracker");
            j.key("model");           j.str("Tracker-1");
            j.key("serialNumber");    j.str("0000-TRK");
            j.key("firmwareVersion"); j.str("0.1.0");
        j.obj_close();
    j.obj_close();

    j.obj_close();
    return j.take();
}

// ---------------------------------------------------------------------------
// Socket setup
// ---------------------------------------------------------------------------
static socket_t make_multicast_sender(int ttl) {
    socket_t s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == kInvalidSocket) return s;

    unsigned char ttl_u = static_cast<unsigned char>(ttl);
    ::setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
                 reinterpret_cast<const char*>(&ttl_u), sizeof(ttl_u));

    unsigned char loop = 1;
    ::setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP,
                 reinterpret_cast<const char*>(&loop), sizeof(loop));

    return s;
}

static socket_t make_unicast_sender() {
    return ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
struct Args {
    int         source  = 1;
    int         port    = kDefaultPort;
    double      rate    = 60.0;
    int         ttl     = 1;
    std::string unicast;            // empty => multicast
    bool        verbose = false;
    bool        no_header = false;  // true => send raw JSON (no 'OTrk' wrapper)
};

static void print_usage(const char* argv0) {
    std::fprintf(stderr,
        "Usage: %s [options]\n"
        "  --source N        OpenTrackIO Source Number (1..200). Default: 1\n"
        "  --port P          UDP port. Default: %d\n"
        "  --rate HZ         Sample rate in Hz. Default: 60\n"
        "  --ttl N           Multicast TTL. Default: 1\n"
        "  --unicast HOST    Send to HOST instead of multicast\n"
        "  -v, --verbose     Print one summary per second\n"
        "  --no-header       Send raw JSON with no OpenTrackIO packet header\n"
        "                    (default: header is included)\n"
        "  -h, --help        Show this help\n",
        argv0, kDefaultPort);
}

static bool parse_args(int argc, char** argv, Args& a) {
    auto need = [&](int& i) -> const char* {
        if (i + 1 >= argc) {
            std::fprintf(stderr, "error: %s requires an argument\n", argv[i]);
            return nullptr;
        }
        return argv[++i];
    };
    for (int i = 1; i < argc; ++i) {
        std::string opt = argv[i];
        if (opt == "-h" || opt == "--help") { print_usage(argv[0]); std::exit(0); }
        else if (opt == "-v" || opt == "--verbose") { a.verbose = true; }
        else if (opt == "--source")  { auto v = need(i); if (!v) return false; a.source = std::atoi(v); }
        else if (opt == "--port")    { auto v = need(i); if (!v) return false; a.port   = std::atoi(v); }
        else if (opt == "--rate")    { auto v = need(i); if (!v) return false; a.rate   = std::atof(v); }
        else if (opt == "--ttl")     { auto v = need(i); if (!v) return false; a.ttl    = std::atoi(v); }
        else if (opt == "--unicast") { auto v = need(i); if (!v) return false; a.unicast = v; }
        else if (opt == "--no-header") { a.no_header = true; }
        else {
            std::fprintf(stderr, "error: unknown option %s\n", opt.c_str());
            print_usage(argv[0]);
            return false;
        }
    }
    if (a.unicast.empty() && (a.source < kSourceMin || a.source > kSourceMax)) {
        std::fprintf(stderr, "error: --source must be in [%d,%d]\n", kSourceMin, kSourceMax);
        return false;
    }
    if (a.rate <= 0.0) {
        std::fprintf(stderr, "error: --rate must be > 0\n");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) return 2;

    NetStartup winsock_guard;

    socket_t sock;
    std::string dest_host;
    std::string mode_descr;
    if (!args.unicast.empty()) {
        sock = make_unicast_sender();
        dest_host = args.unicast;
        mode_descr = "unicast to " + dest_host + ":" + std::to_string(args.port);
    } else {
        sock = make_multicast_sender(args.ttl);
        dest_host = std::string(kMulticastBase) + std::to_string(args.source);
        mode_descr = "multicast to " + dest_host + ":" + std::to_string(args.port)
                   + " (source number " + std::to_string(args.source)
                   + ", TTL " + std::to_string(args.ttl) + ")";
    }
    if (sock == kInvalidSocket) {
        std::fprintf(stderr, "socket() failed: %d\n", sock_errno());
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<unsigned short>(args.port));
    if (::inet_pton(AF_INET, dest_host.c_str(), &addr.sin_addr) != 1) {
        std::fprintf(stderr, "invalid destination address: %s\n", dest_host.c_str());
        close_socket(sock);
        return 1;
    }

    const std::string source_id = make_uuid_v4();
    const WaveTable waves{};

    std::printf("[opentrackio-server] streaming %s\n", mode_descr.c_str());
    std::printf("[opentrackio-server] sourceId urn:uuid:%s\n", source_id.c_str());
    std::printf("[opentrackio-server] rate %.1f Hz -- Ctrl+C to stop\n", args.rate);
    std::fflush(stdout);

    using clock = std::chrono::steady_clock;
    const auto start = clock::now();
    const auto period = std::chrono::duration_cast<clock::duration>(
        std::chrono::duration<double>(1.0 / args.rate));

    long long count = 0;
    while (true) {
        const auto now = clock::now();
        const double t = std::chrono::duration<double>(now - start).count();

        std::string payload = build_sample_json(
            source_id, args.source, count, args.rate, t, waves);

        const uint8_t* datagram_ptr;
        size_t         datagram_size;
        std::vector<uint8_t> wrapped;
        if (args.no_header) {
            datagram_ptr  = reinterpret_cast<const uint8_t*>(payload.data());
            datagram_size = payload.size();
        } else {
            wrapped = build_packet(payload,
                                   static_cast<uint16_t>(count & 0xFFFF));
            datagram_ptr  = wrapped.data();
            datagram_size = wrapped.size();
        }

        int sent = ::sendto(sock,
                            reinterpret_cast<const char*>(datagram_ptr),
#if defined(_WIN32)
                            static_cast<int>(datagram_size),
#else
                            datagram_size,
#endif
                            0,
                            reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (sent < 0) {
            std::fprintf(stderr, "sendto failed: %d\n", sock_errno());
            // Keep going: on some sandboxes multicast isn't reachable but the
            // program is still useful output-wise. Print once, then throttle.
            if (count == 0) std::fflush(stderr);
        }

        if (args.verbose && (count % std::max<long long>(1, static_cast<long long>(args.rate)) == 0)) {
            // Recompute the dynamic numbers for display (cheap).
            std::printf(
                "[%06lld] t=%7.3fs  pos=(%+.3f,%+.3f,%+.3f)  "
                "rot=(p%+.2f,t%+.2f,r%+.2f)  fl=%.2fmm  fd=%.2fm  T%.2f  bytes=%zu\n",
                count, t,
                waves.tx.at(t), waves.ty.at(t), waves.tz.at(t),
                waves.pan.at(t), waves.tilt.at(t), waves.roll.at(t),
                waves.focalLength.at(t), waves.focusDistance.at(t),
                waves.fStop.at(t),
                datagram_size);
            std::fflush(stdout);
        }

        ++count;
        const auto next_tick = start + count * period;
        std::this_thread::sleep_until(next_tick);
    }

    // Unreachable under normal use (Ctrl+C); kept for clean-shutdown paths.
    close_socket(sock);
    return 0;
}
