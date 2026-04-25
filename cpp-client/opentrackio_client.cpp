// opentrackio_client.cpp
//
// Cross-platform C++17 OpenTrackIO consumer with a terminal dashboard.
//
// Joins the OpenTrackIO multicast group (or listens on plain unicast),
// auto-detects wrapped (OTrk header) vs bare-JSON datagrams, parses
// each JSON sample, and renders a live VT100/ANSI dashboard with:
//
//   - connection status, packet rate, sequence counter
//   - SMPTE timecode + sample / source URN
//   - subject identity from static.camera (label / make / model / sn)
//   - rigid-body translation (x/y/z) with auto-scaled sparkline history
//   - rigid-body rotation    (pan/tilt/roll) with auto-scaled sparkline history
//   - lens encoders          (focus/iris/zoom) as percentage bar gauges
//   - derived lens params    (focal length, focus distance, fStop, entrance pupil)
//   - tracker block          (recording/slate/status)
//
// No third-party dependencies. Builds with the same one-liner as the
// C++ server:
//
//     # Linux / macOS
//     c++ -std=c++17 -O2 -o opentrackio_client opentrackio_client.cpp
//
//     # Windows (MSVC developer prompt)
//     cl /std:c++17 /O2 opentrackio_client.cpp ws2_32.lib

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Cross-platform sockets shim
// ---------------------------------------------------------------------------

#if defined(_WIN32)
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #pragma comment(lib, "ws2_32.lib")
  using socket_t = SOCKET;
  static constexpr socket_t kInvalidSocket = INVALID_SOCKET;
  inline int  close_socket(socket_t s) { return ::closesocket(s); }
  inline int  sock_errno()              { return WSAGetLastError(); }
  inline bool sock_init() {
      WSADATA wsa;
      return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
  }
  inline void sock_shutdown()           { WSACleanup(); }
  inline bool sock_set_nonblocking(socket_t s) {
      u_long mode = 1;
      return ::ioctlsocket(s, FIONBIO, &mode) == 0;
  }
  inline bool sock_would_block(int e) {
      return e == WSAEWOULDBLOCK;
  }
  using socklen_t_ = int;
#else
  #include <arpa/inet.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <signal.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <unistd.h>
  using socket_t = int;
  static constexpr socket_t kInvalidSocket = -1;
  inline int  close_socket(socket_t s) { return ::close(s); }
  inline int  sock_errno()              { return errno; }
  inline bool sock_init()               { return true; }
  inline void sock_shutdown()           {}
  inline bool sock_set_nonblocking(socket_t s) {
      int flags = ::fcntl(s, F_GETFL, 0);
      if (flags < 0) return false;
      return ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
  }
  inline bool sock_would_block(int e) {
      return e == EAGAIN || e == EWOULDBLOCK;
  }
  using socklen_t_ = socklen_t;
#endif

// ---------------------------------------------------------------------------
// Protocol constants (must mirror the server byte-for-byte)
// ---------------------------------------------------------------------------

static constexpr int         kDefaultPort         = 55555;
static constexpr int         kSourceMin           = 1;
static constexpr int         kSourceMax           = 200;
static constexpr const char* kMulticastBase       = "239.135.1.";

static constexpr size_t      kHeaderSize          = 16;
static constexpr uint32_t    kHeaderIdentifierU32 = 0x4F54726Bu;   // 'OTrk'
static constexpr uint16_t    kLastSegmentFlag     = 0x8000;
static constexpr uint16_t    kPayloadLenMask      = 0x7FFF;
static constexpr uint8_t     kEncodingJson        = 0x01;

// ---------------------------------------------------------------------------
// Fletcher-16 (mod 256) over header[0:14] + payload, exactly as UE does.
// ---------------------------------------------------------------------------

static uint16_t fletcher16(const uint8_t* hdr, size_t hdrlen,
                           const uint8_t* pay, size_t plen) {
    uint32_t c0 = 0, c1 = 0;
    auto acc = [&](const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            c0 = (c0 + p[i]) & 0xFFu;
            c1 = (c1 + c0)   & 0xFFu;
        }
    };
    acc(hdr, hdrlen);
    acc(pay, plen);
    return static_cast<uint16_t>((c1 << 8) | c0);
}

// ---------------------------------------------------------------------------
// Parsed datagram (header + payload). Auto-detects wrapped vs raw JSON.
// ---------------------------------------------------------------------------

struct OtrkPacket {
    bool     wrapped       = false;
    uint16_t sequence      = 0;
    uint32_t segment_off   = 0;
    bool     last_segment  = true;
    uint16_t checksum_recv = 0;
    uint16_t checksum_calc = 0;
    bool     checksum_ok   = true;
    const uint8_t* payload = nullptr;
    size_t   payload_len   = 0;
};

static bool parse_packet(const uint8_t* buf, size_t n, OtrkPacket& out) {
    if (n < kHeaderSize) {
        // Too short to be wrapped, treat as raw JSON.
        out.wrapped     = false;
        out.payload     = buf;
        out.payload_len = n;
        return true;
    }
    const uint32_t ident = (uint32_t(buf[0]) << 24)
                         | (uint32_t(buf[1]) << 16)
                         | (uint32_t(buf[2]) << 8)
                         |  uint32_t(buf[3]);
    if (ident != kHeaderIdentifierU32) {
        // Not OTrk-wrapped, treat as raw JSON.
        out.wrapped     = false;
        out.payload     = buf;
        out.payload_len = n;
        return true;
    }
    // Wrapped. Decode the rest of the 16-byte header.
    out.wrapped     = true;
    out.sequence    = uint16_t((uint16_t(buf[6]) << 8) | buf[7]);
    out.segment_off = (uint32_t(buf[8])  << 24)
                    | (uint32_t(buf[9])  << 16)
                    | (uint32_t(buf[10]) <<  8)
                    |  uint32_t(buf[11]);
    const uint16_t fal = uint16_t((uint16_t(buf[12]) << 8) | buf[13]);
    out.last_segment   = (fal & kLastSegmentFlag) != 0;
    const uint16_t plen = fal & kPayloadLenMask;
    out.checksum_recv  = uint16_t((uint16_t(buf[14]) << 8) | buf[15]);

    if (kHeaderSize + plen > n) {
        // Header claims more payload than the datagram carries.
        return false;
    }
    out.payload     = buf + kHeaderSize;
    out.payload_len = plen;

    out.checksum_calc = fletcher16(buf, kHeaderSize - 2, out.payload, plen);
    out.checksum_ok   = (out.checksum_calc == out.checksum_recv);
    return true;
}

// ---------------------------------------------------------------------------
// Tiny JSON parser — just enough for the OpenTrackIO sample shape.
// Builds a JsonValue tree we can index with .get("key") / .idx(i).
// ---------------------------------------------------------------------------

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;
    bool b = false;
    double n = 0.0;
    std::string s;
    std::vector<JsonValue> a;
    std::vector<std::pair<std::string, JsonValue>> o;

    bool is_object() const { return type == Type::Object; }
    bool is_array () const { return type == Type::Array;  }
    bool is_number() const { return type == Type::Number; }
    bool is_string() const { return type == Type::String; }
    bool is_bool  () const { return type == Type::Bool;   }

    const JsonValue* get(const std::string& key) const {
        if (type != Type::Object) return nullptr;
        for (const auto& kv : o) if (kv.first == key) return &kv.second;
        return nullptr;
    }
    const JsonValue* idx(size_t i) const {
        if (type != Type::Array || i >= a.size()) return nullptr;
        return &a[i];
    }
    double      num (double def = 0.0) const { return type == Type::Number ? n : def; }
    bool        boo (bool def = false) const { return type == Type::Bool   ? b : def; }
    std::string str (std::string def = "") const { return type == Type::String ? s : def; }
};

class JsonParser {
public:
    JsonParser(const char* p, size_t n) : p_(p), end_(p + n) {}

    bool parse(JsonValue& out) {
        skip();
        if (!parseValue(out)) return false;
        skip();
        return p_ == end_;
    }

private:
    const char* p_;
    const char* end_;

    void skip() {
        while (p_ < end_) {
            char c = *p_;
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++p_;
            else break;
        }
    }
    bool parseValue(JsonValue& v) {
        skip();
        if (p_ == end_) return false;
        char c = *p_;
        if (c == '{') return parseObject(v);
        if (c == '[') return parseArray(v);
        if (c == '"') return parseString(v);
        if (c == 't' || c == 'f') return parseBool(v);
        if (c == 'n') return parseNull(v);
        return parseNumber(v);
    }
    bool parseObject(JsonValue& v) {
        v.type = JsonValue::Type::Object;
        ++p_; skip();
        if (p_ < end_ && *p_ == '}') { ++p_; return true; }
        while (p_ < end_) {
            skip();
            if (p_ >= end_ || *p_ != '"') return false;
            JsonValue keyv;
            if (!parseString(keyv)) return false;
            skip();
            if (p_ >= end_ || *p_ != ':') return false;
            ++p_; skip();
            JsonValue val;
            if (!parseValue(val)) return false;
            v.o.emplace_back(std::move(keyv.s), std::move(val));
            skip();
            if (p_ < end_ && *p_ == ',') { ++p_; continue; }
            if (p_ < end_ && *p_ == '}') { ++p_; return true; }
            return false;
        }
        return false;
    }
    bool parseArray(JsonValue& v) {
        v.type = JsonValue::Type::Array;
        ++p_; skip();
        if (p_ < end_ && *p_ == ']') { ++p_; return true; }
        while (p_ < end_) {
            JsonValue elem;
            if (!parseValue(elem)) return false;
            v.a.emplace_back(std::move(elem));
            skip();
            if (p_ < end_ && *p_ == ',') { ++p_; continue; }
            if (p_ < end_ && *p_ == ']') { ++p_; return true; }
            return false;
        }
        return false;
    }
    bool parseString(JsonValue& v) {
        v.type = JsonValue::Type::String;
        if (p_ >= end_ || *p_ != '"') return false;
        ++p_;
        while (p_ < end_ && *p_ != '"') {
            if (*p_ == '\\') {
                ++p_;
                if (p_ >= end_) return false;
                char esc = *p_++;
                switch (esc) {
                    case '"':  v.s.push_back('"');  break;
                    case '\\': v.s.push_back('\\'); break;
                    case '/':  v.s.push_back('/');  break;
                    case 'b':  v.s.push_back('\b'); break;
                    case 'f':  v.s.push_back('\f'); break;
                    case 'n':  v.s.push_back('\n'); break;
                    case 'r':  v.s.push_back('\r'); break;
                    case 't':  v.s.push_back('\t'); break;
                    case 'u': {
                        if (end_ - p_ < 4) return false;
                        unsigned cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = *p_++;
                            cp <<= 4;
                            if      (h >= '0' && h <= '9') cp |= unsigned(h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= unsigned(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= unsigned(h - 'A' + 10);
                            else return false;
                        }
                        // Encode as UTF-8 (no surrogate-pair handling — fine for
                        // OpenTrackIO since the schema only uses ASCII identifiers).
                        if (cp < 0x80) {
                            v.s.push_back(char(cp));
                        } else if (cp < 0x800) {
                            v.s.push_back(char(0xC0 | (cp >> 6)));
                            v.s.push_back(char(0x80 | (cp & 0x3F)));
                        } else {
                            v.s.push_back(char(0xE0 | (cp >> 12)));
                            v.s.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
                            v.s.push_back(char(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: return false;
                }
            } else {
                v.s.push_back(*p_++);
            }
        }
        if (p_ >= end_) return false;
        ++p_;   // consume closing quote
        return true;
    }
    bool parseBool(JsonValue& v) {
        v.type = JsonValue::Type::Bool;
        if (end_ - p_ >= 4 && std::strncmp(p_, "true", 4) == 0)  { v.b = true;  p_ += 4; return true; }
        if (end_ - p_ >= 5 && std::strncmp(p_, "false", 5) == 0) { v.b = false; p_ += 5; return true; }
        return false;
    }
    bool parseNull(JsonValue& v) {
        v.type = JsonValue::Type::Null;
        if (end_ - p_ >= 4 && std::strncmp(p_, "null", 4) == 0) { p_ += 4; return true; }
        return false;
    }
    bool parseNumber(JsonValue& v) {
        v.type = JsonValue::Type::Number;
        const char* start = p_;
        if (p_ < end_ && *p_ == '-') ++p_;
        bool sawDigit = false;
        while (p_ < end_) {
            char c = *p_;
            bool ok = (c >= '0' && c <= '9') || c == '.'
                   ||  c == 'e' || c == 'E' || c == '+' || c == '-';
            if (!ok) break;
            if (c >= '0' && c <= '9') sawDigit = true;
            ++p_;
        }
        if (!sawDigit) return false;
        std::string buf(start, size_t(p_ - start));
        try { v.n = std::stod(buf); } catch (...) { return false; }
        return true;
    }
};

// ---------------------------------------------------------------------------
// One decoded sample. We only pull out the fields the dashboard renders.
// ---------------------------------------------------------------------------

struct Sample {
    bool valid = false;

    // Timecode
    int hours = 0, minutes = 0, seconds = 0, frames = 0;

    // Camera rigid body
    double tx = 0, ty = 0, tz = 0;
    double pan = 0, tilt = 0, roll = 0;

    // Lens
    double focus = 0, iris = 0, zoom = 0;
    double focal_length = 0;          // mm
    double focus_distance = 0;        // m
    double fstop = 0;
    double entrance_pupil = 0;        // m

    // Identity
    std::string label;
    std::string camera_make, camera_model, camera_serial;
    std::string source_id, sample_id;

    // Tracker (per-frame)
    std::string tracker_status, tracker_slate;
    bool        tracker_recording = false;

    // Diagnostics
    int sequence = 0;
};

static double getNum(const JsonValue* o, const char* key, double def = 0.0) {
    if (!o) return def;
    const JsonValue* v = o->get(key);
    return v ? v->num(def) : def;
}
static std::string getStr(const JsonValue* o, const char* key, std::string def = "") {
    if (!o) return def;
    const JsonValue* v = o->get(key);
    return v ? v->str(def) : def;
}
static bool getBool(const JsonValue* o, const char* key, bool def = false) {
    if (!o) return def;
    const JsonValue* v = o->get(key);
    return v ? v->boo(def) : def;
}

static Sample sample_from_json(const JsonValue& root) {
    Sample s;
    s.valid     = true;
    s.source_id = getStr(&root, "sourceId");
    s.sample_id = getStr(&root, "sampleId");

    if (const JsonValue* timing = root.get("timing")) {
        if (const JsonValue* tc = timing->get("timecode")) {
            s.hours   = int(getNum(tc, "hours"));
            s.minutes = int(getNum(tc, "minutes"));
            s.seconds = int(getNum(tc, "seconds"));
            s.frames  = int(getNum(tc, "frames"));
        }
        s.sequence = int(getNum(timing, "sequenceNumber"));
    }

    if (const JsonValue* xforms = root.get("transforms"); xforms && xforms->is_array()) {
        // Take the first transform — that's the camera rigid body in our sample.
        const JsonValue* first = xforms->idx(0);
        if (first) {
            const JsonValue* tr  = first->get("translation");
            const JsonValue* rot = first->get("rotation");
            s.tx   = getNum(tr,  "x");
            s.ty   = getNum(tr,  "y");
            s.tz   = getNum(tr,  "z");
            s.pan  = getNum(rot, "pan");
            s.tilt = getNum(rot, "tilt");
            s.roll = getNum(rot, "roll");
        }
    }

    if (const JsonValue* lens = root.get("lens")) {
        if (const JsonValue* enc = lens->get("encoders")) {
            s.focus = getNum(enc, "focus");
            s.iris  = getNum(enc, "iris");
            s.zoom  = getNum(enc, "zoom");
        }
        s.focal_length   = getNum(lens, "pinholeFocalLength");
        s.focus_distance = getNum(lens, "focusDistance");
        s.fstop          = getNum(lens, "fStop");
        s.entrance_pupil = getNum(lens, "entrancePupilOffset");
    }

    if (const JsonValue* st = root.get("static")) {
        if (const JsonValue* cam = st->get("camera")) {
            s.label         = getStr(cam, "label");
            s.camera_make   = getStr(cam, "make");
            s.camera_model  = getStr(cam, "model");
            s.camera_serial = getStr(cam, "serialNumber");
        }
    }

    if (const JsonValue* tr = root.get("tracker")) {
        s.tracker_recording = getBool(tr, "recording", false);
        s.tracker_slate     = getStr (tr, "slate");
        s.tracker_status    = getStr (tr, "status");
    }

    return s;
}

// ---------------------------------------------------------------------------
// Terminal helpers (ANSI / VT100). Works on Linux/macOS and on Windows
// Terminal / Win10+ conhost (we explicitly enable VT processing below).
// ---------------------------------------------------------------------------

static const char* kAnsiReset      = "\033[0m";
static const char* kAnsiDim        = "\033[2m";
static const char* kAnsiYellow     = "\033[33m";
static const char* kAnsiGreen      = "\033[32m";
static const char* kAnsiRed        = "\033[31m";

static std::atomic<bool> g_running{true};

static void on_signal(int) {
    g_running.store(false, std::memory_order_relaxed);
}

class Terminal {
public:
    static void enter() {
#if defined(_WIN32)
        // Enable VT processing on Windows so escape sequences work.
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(hOut, &mode)) {
                SetConsoleMode(hOut,
                    mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                         | ENABLE_PROCESSED_OUTPUT);
            }
        }
        SetConsoleOutputCP(CP_UTF8);
#endif
        // Switch to alt screen, hide cursor, clear, home.
        std::fputs("\033[?1049h\033[?25l\033[2J\033[H", stdout);
        std::fflush(stdout);
    }
    static void leave() {
        // Restore default style, show cursor, leave alt screen.
        std::fputs("\033[0m\033[?25h\033[?1049l", stdout);
        std::fflush(stdout);
    }
    static void home()         { std::fputs("\033[H", stdout); }
    static void clear_to_eos() { std::fputs("\033[J", stdout); }
};

static std::string make_pct_bar(double value01, size_t width) {
    if (value01 < 0) value01 = 0;
    if (value01 > 1) value01 = 1;
    size_t fill = size_t(std::lround(value01 * double(width)));
    std::string out;
    out.reserve(width * 4);
    for (size_t i = 0; i < width; ++i) {
        out += (i < fill) ? u8"█" : u8"░";  // █ vs ░
    }
    return out;
}

// ---------------------------------------------------------------------------
// Dashboard model — live state + history.
// ---------------------------------------------------------------------------

struct Dashboard {
    static constexpr size_t kHistorySize  = 60;

    Sample latest;
    bool   has_sample = false;

    // Per-channel history (newest at the back).
    std::deque<double> hx, hy, hz;
    std::deque<double> hpan, htilt, hroll;

    // Statistics
    uint64_t total_packets    = 0;
    uint64_t bad_checksum     = 0;
    uint64_t parse_failures   = 0;
    uint64_t last_packet_seq  = 0;

    // Smoothed packet rate (alpha-filtered EMA over 1-second windows)
    double  ema_rate_hz       = 0;
    uint64_t window_packets   = 0;
    std::chrono::steady_clock::time_point window_start =
        std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point last_packet_time =
        std::chrono::steady_clock::now();

    std::string listen_descr;

    void on_sample(const Sample& s) {
        latest     = s;
        has_sample = true;
        ++total_packets;
        ++window_packets;
        last_packet_time = std::chrono::steady_clock::now();

        auto push = [](std::deque<double>& d, double v) {
            d.push_back(v);
            while (d.size() > kHistorySize) d.pop_front();
        };
        push(hx, s.tx);    push(hy, s.ty);    push(hz, s.tz);
        push(hpan, s.pan); push(htilt, s.tilt); push(hroll, s.roll);
    }

    void tick_rate() {
        using namespace std::chrono;
        auto now   = steady_clock::now();
        auto elapsed_ms = duration_cast<milliseconds>(now - window_start).count();
        if (elapsed_ms >= 1000) {
            double inst = double(window_packets) * 1000.0 / double(elapsed_ms);
            // First sample seeds the EMA exactly so the displayed rate
            // matches reality immediately rather than ramping in from 0.
            const double alpha = (ema_rate_hz <= 0.0) ? 1.0 : 0.4;
            ema_rate_hz = alpha * inst + (1.0 - alpha) * ema_rate_hz;
            window_packets = 0;
            window_start   = now;
        }
    }

    bool is_live() const {
        using namespace std::chrono;
        auto since_packet = steady_clock::now() - last_packet_time;
        return has_sample && since_packet < seconds(2);
    }
};

// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------

// Returns the visible width (column count) of a UTF-8 byte string,
// counting each codepoint as 1 column. The dashboard only uses ASCII +
// box-drawing + block glyphs which are all single-width so this is
// sufficient for our padding calculations.
static size_t utf8_visible_width(const std::string& s) {
    size_t w = 0;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if      ((c & 0x80) == 0x00) { i += 1; ++w; }
        else if ((c & 0xE0) == 0xC0) { i += 2; ++w; }
        else if ((c & 0xF0) == 0xE0) { i += 3; ++w; }
        else if ((c & 0xF8) == 0xF0) { i += 4; ++w; }
        else                         { i += 1; ++w; }
    }
    return w;
}

static std::string pad_right(std::string s, size_t cols) {
    size_t w = utf8_visible_width(s);
    if (w < cols) s.append(cols - w, ' ');
    return s;
}

// Drop the "urn:uuid:" prefix and keep just the first two UUID groups
// ("xxxxxxxx-xxxx"), which are plenty for on-screen disambiguation and
// keep the dashboard inside its 86-cell-wide row body.
static std::string short_uuid(const std::string& urn) {
    static constexpr const char* kPrefix = "urn:uuid:";
    static constexpr size_t kPrefixLen   = 9;   // strlen("urn:uuid:")
    std::string body = urn;
    if (body.size() >= kPrefixLen && body.compare(0, kPrefixLen, kPrefix) == 0) {
        body.erase(0, kPrefixLen);
    }
    if (body.size() > 13) return body.substr(0, 13) + "...";
    return body;
}


static void render(const Dashboard& d) {
    // Buffer the whole frame in a single string and emit at once so we
    // never tear visibly even if stdout is line-buffered.
    std::string out;
    out.reserve(8192);

    auto put = [&](const std::string& s) { out += s; };
    auto endl = [&]() { out += "\033[K\n"; };  // clear-to-EOL + newline

    auto rule_top  = [&]() {
        put(kAnsiDim);
        put(u8"╔"); for (int i = 0; i < 88; ++i) put(u8"═"); put(u8"╗");
        put(kAnsiReset);
        endl();
    };
    auto rule_mid  = [&]() {
        put(kAnsiDim);
        put(u8"╠"); for (int i = 0; i < 88; ++i) put(u8"═"); put(u8"╣");
        put(kAnsiReset);
        endl();
    };
    auto rule_bot  = [&]() {
        put(kAnsiDim);
        put(u8"╚"); for (int i = 0; i < 88; ++i) put(u8"═"); put(u8"╝");
        put(kAnsiReset);
        endl();
    };
    auto row = [&](const std::string& body) {
        // Body is plain ASCII for the inner columns; we wrap with vertical
        // bars to keep the right edge tidy.
        put(kAnsiDim); put(u8"║"); put(kAnsiReset);
        put(" ");
        put(pad_right(body, 86));
        put(" ");
        put(kAnsiDim); put(u8"║"); put(kAnsiReset);
        endl();
    };

    Terminal::home();

    // ---- title bar ----
    rule_top();
    {
        const char* state_color = d.is_live() ? kAnsiGreen
                                              : (d.has_sample ? kAnsiYellow : kAnsiRed);
        const char* state_text  = d.is_live() ? "live"
                                              : (d.has_sample ? "stale" : "waiting");
        // ANSI colour escapes don't consume cells, so pad by visible width
        // rather than byte count.
        std::string body = "OpenTrackIO Client     ";
        body += state_color; body += state_text; body += kAnsiReset;
        char tail[160];
        std::snprintf(tail, sizeof(tail),
                      "   %.1f Hz   pkts %llu   bad-cksum %llu",
                      d.ema_rate_hz,
                      static_cast<unsigned long long>(d.total_packets),
                      static_cast<unsigned long long>(d.bad_checksum));
        body += tail;

        size_t visible = 23 + std::string(state_text).size()
                       + utf8_visible_width(tail);
        if (visible < 86) body.append(86 - visible, ' ');

        put(kAnsiDim); put(u8"║"); put(kAnsiReset);
        put(" "); put(body); put(" ");
        put(kAnsiDim); put(u8"║"); put(kAnsiReset);
        endl();
    }
    rule_mid();

    // ---- identity ----
    {
        char b[256];
        std::snprintf(b, sizeof(b),
                      "Subject  : %-24s     Camera : %s / %s",
                      d.latest.label.empty() ? "(no label)" : d.latest.label.c_str(),
                      d.latest.camera_make.c_str(),
                      d.latest.camera_model.c_str());
        row(b);
        std::snprintf(b, sizeof(b),
                      "Timecode : %02d:%02d:%02d:%02d           Source : %s",
                      d.latest.hours, d.latest.minutes,
                      d.latest.seconds, d.latest.frames,
                      short_uuid(d.latest.source_id).c_str());
        row(b);
        std::snprintf(b, sizeof(b),
                      "Listen   : %-32s Sample : %s",
                      d.listen_descr.c_str(),
                      short_uuid(d.latest.sample_id).c_str());
        row(b);
    }
    rule_mid();

    // ---- translation + rotation bar charts -----------------------------
    //
    // Each row is laid out the same way as the lens-encoder rows below
    // (label, numeric value, █/░ filled bar, percent-of-range). Because
    // X/Y/Z and pan/tilt/roll aren't normalised to 0..1 like the lens
    // encoders are, the bar's range is auto-scaled from each channel's
    // recent history with a small pad on either side, so the marker
    // doesn't sit pinned at 0% / 100% during steady-state oscillation.
    auto bar_row = [&](const char* name,
                       double value,
                       const std::deque<double>& hist,
                       const char* unit) {
        double mn = value, mx = value;
        for (double v : hist) {
            if (v < mn) mn = v;
            if (v > mx) mx = v;
        }
        if (mx - mn < 1e-9) {
            // Degenerate range (no history yet, or value never moved).
            // Centre the marker in a unit-wide window so the bar shows
            // something useful instead of pinning to one edge.
            mn = value - 0.5;
            mx = value + 0.5;
        }
        const double r   = mx - mn;
        const double pad = r * 0.05;
        mn -= pad;
        mx += pad;

        double frac = (value - mn) / (mx - mn);
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;

        std::string bar = make_pct_bar(frac, 32);
        char head[64];
        std::snprintf(head, sizeof(head), "%-6s %+8.3f %-3s ", name, value, unit);
        char tail[64];
        std::snprintf(tail, sizeof(tail),
                      "  %3d%%  [%+7.2f, %+7.2f]",
                      int(std::lround(frac * 100.0)), mn, mx);
        row(std::string(head) + bar + tail);
    };

    row("Position (m)");
    bar_row("X", d.latest.tx, d.hx, "m");
    bar_row("Y", d.latest.ty, d.hy, "m");
    bar_row("Z", d.latest.tz, d.hz, "m");
    rule_mid();
    row("Rotation (deg)");
    bar_row("pan",  d.latest.pan,  d.hpan,  "deg");
    bar_row("tilt", d.latest.tilt, d.htilt, "deg");
    bar_row("roll", d.latest.roll, d.hroll, "deg");
    rule_mid();

    // ---- lens encoders + lens parameters ----
    row("Lens encoders");
    auto enc_row = [&](const char* name, double v01) {
        std::string bar = make_pct_bar(v01, 32);
        char head[64];
        std::snprintf(head, sizeof(head), "%-6s %5.2f  ", name, v01);
        std::string tail;
        char buf[16];
        std::snprintf(buf, sizeof(buf), "  %3d%%", int(std::lround(v01 * 100.0)));
        tail = buf;
        row(std::string(head) + bar + tail);
    };
    enc_row("focus", d.latest.focus);
    enc_row("iris",  d.latest.iris);
    enc_row("zoom",  d.latest.zoom);
    rule_mid();

    row("Lens parameters");
    {
        char b[160];
        std::snprintf(b, sizeof(b),
                      "  focal length    : %7.2f mm     focus distance : %6.3f m",
                      d.latest.focal_length, d.latest.focus_distance);
        row(b);
        std::snprintf(b, sizeof(b),
                      "  fStop           :  T %6.3f      entrance pupil : %6.3f m",
                      d.latest.fstop, d.latest.entrance_pupil);
        row(b);
    }
    rule_mid();

    // ---- tracker + footer ----
    {
        char b[256];
        std::snprintf(b, sizeof(b),
                      "Tracker  : recording=%-5s  slate=\"%s\"  status=\"%s\"",
                      d.latest.tracker_recording ? "true" : "false",
                      d.latest.tracker_slate.c_str(),
                      d.latest.tracker_status.c_str());
        row(b);
    }
    rule_bot();
    put(kAnsiDim);
    put(" Press Ctrl+C to quit.");
    put(kAnsiReset);
    endl();

    Terminal::clear_to_eos();
    std::fputs(out.c_str(), stdout);
    std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// Socket setup
// ---------------------------------------------------------------------------

struct ClientArgs {
    int         source     = 1;
    int         port       = kDefaultPort;
    std::string iface      = "0.0.0.0";
    bool        unicast    = false;
    bool        raw_dump   = false;
    bool        print_only = false;     // CLI-only mode: text lines, no dashboard
    std::string unicast_bind = "0.0.0.0";
};

static std::string make_multicast_address(int source) {
    if (source < kSourceMin || source > kSourceMax) {
        std::fprintf(stderr,
            "[opentrackio-client] source number must be %d..%d, got %d\n",
            kSourceMin, kSourceMax, source);
        std::exit(2);
    }
    return std::string(kMulticastBase) + std::to_string(source);
}

static socket_t open_listening_socket(const ClientArgs& args, std::string& descr) {
    socket_t sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kInvalidSocket) {
        std::fprintf(stderr,
            "[opentrackio-client] socket() failed (errno=%d)\n", sock_errno());
        return kInvalidSocket;
    }

    // Non-blocking, so the drain-pending-packets inner loop in run() can
    // exit cleanly with EWOULDBLOCK once the kernel queue is empty,
    // instead of blocking inside recvfrom waiting for the next packet
    // and starving the dashboard render path.
    if (!sock_set_nonblocking(sock)) {
        std::fprintf(stderr,
            "[opentrackio-client] failed to set socket non-blocking (errno=%d)\n",
            sock_errno());
        close_socket(sock);
        return kInvalidSocket;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#endif

    sockaddr_in bind_addr{};
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_port        = htons(uint16_t(args.port));
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(sock, reinterpret_cast<sockaddr*>(&bind_addr),
               sizeof(bind_addr)) != 0) {
        std::fprintf(stderr,
            "[opentrackio-client] bind(:%d) failed (errno=%d)\n",
            args.port, sock_errno());
        close_socket(sock);
        return kInvalidSocket;
    }

    if (args.unicast) {
        descr = "unicast 0.0.0.0:" + std::to_string(args.port);
    } else {
        std::string mcast = make_multicast_address(args.source);
        ip_mreq mreq{};
        if (inet_pton(AF_INET, mcast.c_str(), &mreq.imr_multiaddr) != 1) {
            std::fprintf(stderr,
                "[opentrackio-client] invalid multicast address %s\n",
                mcast.c_str());
            close_socket(sock);
            return kInvalidSocket;
        }
        if (inet_pton(AF_INET, args.iface.c_str(), &mreq.imr_interface) != 1) {
            std::fprintf(stderr,
                "[opentrackio-client] invalid --iface %s\n",
                args.iface.c_str());
            close_socket(sock);
            return kInvalidSocket;
        }
        if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       reinterpret_cast<const char*>(&mreq),
                       sizeof(mreq)) != 0) {
            std::fprintf(stderr,
                "[opentrackio-client] IP_ADD_MEMBERSHIP %s on %s failed (errno=%d)\n",
                mcast.c_str(), args.iface.c_str(), sock_errno());
            close_socket(sock);
            return kInvalidSocket;
        }
        descr = "multicast " + mcast + ":" + std::to_string(args.port);
    }
    return sock;
}

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

static void print_usage(const char* prog) {
    std::fprintf(stderr,
"Usage: %s [options]\n"
"\n"
"Joins the OpenTrackIO multicast group (or listens on plain unicast),\n"
"auto-detects wrapped (OTrk) vs raw JSON datagrams, and renders a live\n"
"VT100/ANSI dashboard with the camera transform and lens data.\n"
"\n"
"Options:\n"
"  --source N        Multicast group %s<N> (1..200). Default 1.\n"
"  --port P          UDP port. Default %d.\n"
"  --iface IP        Local interface for the multicast join. Default 0.0.0.0.\n"
"  --unicast         Listen on plain unicast on --port (no multicast join).\n"
"  --raw             Pretty-print every received sample as JSON (no dashboard).\n"
"  --print           CLI mode: print one summary line per sample (no dashboard).\n"
"  -h, --help        Show this help.\n",
        prog, kMulticastBase, kDefaultPort);
}

static bool parse_args(int argc, char** argv, ClientArgs& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "[opentrackio-client] %s requires a value\n", flag);
                std::exit(2);
            }
            return argv[++i];
        };
        if      (s == "--source")  a.source  = std::atoi(next("--source").c_str());
        else if (s == "--port")    a.port    = std::atoi(next("--port").c_str());
        else if (s == "--iface")   a.iface   = next("--iface");
        else if (s == "--unicast") a.unicast = true;
        else if (s == "--raw")     a.raw_dump = true;
        else if (s == "--print")   a.print_only = true;
        else if (s == "-h" || s == "--help") { print_usage(argv[0]); std::exit(0); }
        else {
            std::fprintf(stderr, "[opentrackio-client] unknown arg %s\n", s.c_str());
            print_usage(argv[0]);
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// CLI/raw helpers (for --print and --raw modes)
// ---------------------------------------------------------------------------

static void print_summary_line(const Sample& s) {
    std::printf(
        "TC %02d:%02d:%02d:%02d  pos=(%+.3f,%+.3f,%+.3f)  rot=(p%+.2f t%+.2f r%+.2f)  "
        "enc(f%.3f i%.3f z%.3f)  fl=%.2fmm  fd=%.2fm  T%.2f%s\n",
        s.hours, s.minutes, s.seconds, s.frames,
        s.tx, s.ty, s.tz, s.pan, s.tilt, s.roll,
        s.focus, s.iris, s.zoom,
        s.focal_length, s.focus_distance, s.fstop,
        s.label.empty() ? "" : ("  [" + s.label + "]").c_str());
    std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

static int run(int argc, char** argv) {
    ClientArgs args;
    if (!parse_args(argc, argv, args)) return 2;

    if (!sock_init()) {
        std::fprintf(stderr, "[opentrackio-client] socket subsystem init failed\n");
        return 1;
    }
    struct WsaGuard { ~WsaGuard() { sock_shutdown(); } } wsa_guard;

    std::string descr;
    socket_t sock = open_listening_socket(args, descr);
    if (sock == kInvalidSocket) return 1;

    Dashboard dash;
    dash.listen_descr = descr;

    const bool dashboard_mode = !(args.raw_dump || args.print_only);
    if (dashboard_mode) {
        Terminal::enter();
        std::atexit([]{ Terminal::leave(); });
    } else {
        std::fprintf(stderr, "[opentrackio-client] listening %s\n", descr.c_str());
    }

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    using clock = std::chrono::steady_clock;
    auto last_paint = clock::now();
    constexpr auto paint_period = std::chrono::milliseconds(100);

    std::vector<uint8_t> buf(65536);

    while (g_running.load(std::memory_order_relaxed)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        timeval tv{0, 50 * 1000};   // 50 ms
        int n = select(int(sock) + 1, &rfds, nullptr, nullptr, &tv);

        if (n < 0) {
#if defined(_WIN32)
            // Win32 select() returns SOCKET_ERROR on Ctrl+C; bail out cleanly.
            if (sock_errno() == WSAEINTR) break;
#else
            if (errno == EINTR) continue;
#endif
            std::fprintf(stderr,
                "[opentrackio-client] select() failed (errno=%d)\n", sock_errno());
            break;
        }

        if (n > 0 && FD_ISSET(sock, &rfds)) {
            // Drain everything ready right now to avoid backlogging packets.
            // The socket is non-blocking, so once the kernel queue is empty
            // recvfrom returns -1 with EWOULDBLOCK and we fall through to
            // render(). Blocking sockets would starve the render path
            // because the *next* packet arrival (~16ms at 60Hz) would be
            // serviced before select() got another chance.
            for (;;) {
                sockaddr_in from{};
                socklen_t_ fromlen = sizeof(from);
                int r = ::recvfrom(sock,
                                   reinterpret_cast<char*>(buf.data()),
                                   int(buf.size()), 0,
                                   reinterpret_cast<sockaddr*>(&from), &fromlen);
                if (r < 0) {
                    if (sock_would_block(sock_errno())) break;   // queue drained
                    break;                                        // any other error
                }
                if (r == 0) break;

                OtrkPacket pkt;
                if (!parse_packet(buf.data(), size_t(r), pkt)) continue;
                if (pkt.wrapped && !pkt.checksum_ok) {
                    ++dash.bad_checksum;
                    continue;
                }
                // We don't currently support segmented payloads. The server
                // never produces them for our sample size, so treat
                // last_segment=false as a soft-fail.
                if (pkt.wrapped && !pkt.last_segment) {
                    continue;
                }

                JsonValue root;
                JsonParser jp(reinterpret_cast<const char*>(pkt.payload),
                              pkt.payload_len);
                if (!jp.parse(root)) {
                    ++dash.parse_failures;
                    continue;
                }

                Sample s = sample_from_json(root);
                s.sequence = int(pkt.sequence);

                if (args.raw_dump) {
                    std::fwrite(pkt.payload, 1, pkt.payload_len, stdout);
                    std::fputc('\n', stdout);
                    std::fflush(stdout);
                } else if (args.print_only) {
                    print_summary_line(s);
                }

                dash.on_sample(s);
            }
        }

        dash.tick_rate();

        if (dashboard_mode) {
            auto now = clock::now();
            if (now - last_paint >= paint_period) {
                render(dash);
                last_paint = now;
            }
        }
    }

    if (dashboard_mode) Terminal::leave();
    close_socket(sock);
    std::fprintf(stderr,
        "\n[opentrackio-client] %llu packets received "
        "(%llu bad checksum, %llu parse failures)\n",
        static_cast<unsigned long long>(dash.total_packets),
        static_cast<unsigned long long>(dash.bad_checksum),
        static_cast<unsigned long long>(dash.parse_failures));
    return 0;
}

int main(int argc, char** argv) {
    return run(argc, argv);
}
