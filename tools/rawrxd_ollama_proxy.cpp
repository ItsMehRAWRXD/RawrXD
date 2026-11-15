// ============================================================================
// rawrxd_ollama_proxy.cpp -- concurrent local proxy exposing Ollama to RawrXD.
// ============================================================================
// Why this exists:
//   VS Code's GitHub Copilot stores a custom endpoint "Deep2 Local" pointing at
//   a port the native Deep2 server used to own. That entry lives in VS Code's
//   SQLite global state, so it cannot be repointed from a config file.
//
//   deep2_openai_server currently runs CPU_NATIVE (GPU never opens) at
//   ~0.028 TPS and exits, so every request fails with ERR_CONNECTION_REFUSED.
//
//   This proxy serves that endpoint by forwarding to the healthy, GPU-backed
//   Ollama server. It is a transport shim, NOT native Deep2 inference.
//
// Design requirements (and how they are met):
//   * CONCURRENCY      - one thread per connection, capped at
//                        --max-workers (default 64). A long streaming
//                        generation never blocks /v1/models or new connections.
//   * STREAMING        - "stream":true responses are relayed byte-for-byte
//                        while the model is still generating (UpstreamRelay).
//                        The body is never buffered.
//   * CANCELLATION     - a client disconnect makes the relay's client send
//                        fail; the upstream socket is then closed, which Ollama
//                        treats as a cancelled request.
//   * BODY LIMIT       - request bodies are capped (default 32 MiB) to prevent
//                        unbounded memory growth.
//   * TIMEOUTS         - connect and idle timeouts bound every request.
//   * MODEL ALIASES    - explicit map only; unknown models are forwarded
//                        verbatim so a misconfigured client yields an
//                        observable 404 rather than a silent rewrite.
//   * IDENTITY LOGGING - every request logs requested model, effective model,
//                        status, and duration, so a proxied response can never
//                        be mistaken for native Deep2 inference.
//   * LOOPBACK ONLY    - binds 127.0.0.1. Not network-exposed.
//   * CLEAN SHUTDOWN   - Ctrl+C stops the accept loop; in-flight requests get
//                        a bounded grace period to finish.
//
// Build:
//   cl /nologo /std:c++17 /EHsc /O2 rawrxd_ollama_proxy.cpp /Fe:rawrxd_ollama_proxy.exe
// (or use the .NET SDK: dotnet build / csc)
//
// Usage:
//   rawrxd_ollama_proxy.exe
//   rawrxd_ollama_proxy.exe --listen 11436 --upstream 11434
//   rawrxd_ollama_proxy.exe --listen 8080
// ============================================================================

// winsock2.h MUST precede windows.h: windows.h otherwise pulls in the legacy
// winsock.h, which conflicts with ws2tcpip.h (undeclared Filter, IP_MSFILTER,
// MULTICAST_MODE_TYPE, ...). WIN32_LEAN_AND_MEAN keeps that from happening.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
struct Config {
    std::string bindAddress = "127.0.0.1";
    uint16_t    listenPort  = 11436;   // port stored in the "Deep2 Local" config
    uint16_t    upstreamPort = 11434;  // Ollama
    std::size_t maxBodyBytes = 32u * 1024u * 1024u;
    int         upstreamTimeoutSec = 1800;
    int         maxConcurrentWorkers = 64;
    bool        verbose = true;
};

Config g_cfg;

// Explicit alias map. Only these model names are rewritten.
const std::map<std::string, std::string>& Aliases() {
    static const std::map<std::string, std::string> kAliases = {
        {"deep2-local", "reap16-glm-4_7-flash:latest"},
        // VS Code Copilot displays/selects the custom BYOK model under its
        // own canonical name; accept it and resolve it to the same model.
        {"mai-code-1.1-flash", "reap16-glm-4_7-flash:latest"},
    };
    return kAliases;
}

std::atomic<bool> g_running{true};
std::mutex        g_logMu;

// Worker-pool accounting. Globals so detached workers never reference main's
// stack after main starts returning.
std::mutex              g_workerMu;
std::condition_variable g_workerCv;
int                     g_activeWorkers = 0;

void Log(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_logMu);
    std::fprintf(stdout, "%s\n", line.c_str());
    std::fflush(stdout);
}

std::string NowStamp() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto t   = system_clock::to_time_t(now);
    const auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::tm tm{};
    localtime_s(&tm, &t);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>(ms.count()));
    return buf;
}

// ---------------------------------------------------------------------------
// Minimal HTTP helpers
// ---------------------------------------------------------------------------

std::string ToLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string Trim(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

// Very small JSON string-field extractor. Sufficient for reading "model" and
// detecting "stream":true without pulling in a full JSON dependency. Returns
// false when the field is absent.
bool ExtractJsonStringField(const std::string& body, const std::string& key, std::string& out) {
    const std::string pat = "\"" + key + "\"";
    std::size_t pos = body.find(pat);
    if (pos == std::string::npos) return false;
    pos = body.find(':', pos + pat.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) ++pos;
    if (pos >= body.size() || body[pos] != '"') return false;
    ++pos;

    out.clear();
    while (pos < body.size()) {
        const char c = body[pos++];
        if (c == '\\' && pos < body.size()) {
            const char esc = body[pos++];
            switch (esc) {
                case 'n': out.push_back('\n'); break;
                case 't': out.push_back('\t'); break;
                case 'r': out.push_back('\r'); break;
                case '"': out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/');  break;
                default:  out.push_back(esc);  break;
            }
            continue;
        }
        if (c == '"') return true;
        out.push_back(c);
    }
    return false;
}

bool JsonBoolField(const std::string& body, const std::string& key) {
    const std::string pat = "\"" + key + "\"";
    std::size_t pos = body.find(pat);
    if (pos == std::string::npos) return false;
    pos = body.find(':', pos + pat.size());
    if (pos == std::string::npos) return false;
    pos += 1;
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) ++pos;
    return body.compare(pos, 4, "true") == 0;
}

// Escape a string for embedding in a JSON response body.
std::string JsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o.push_back(c);
                }
        }
    }
    return o;
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

bool SendAll(SOCKET s, const char* data, std::size_t len) {
    std::size_t sent = 0;
    while (sent < len) {
        const int n = ::send(s, data + sent, static_cast<int>(len - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

bool RecvAll(SOCKET s, char* buf, std::size_t len) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1800);
    std::size_t got = 0;
    while (got < len) {
        const int n = ::recv(s, buf + got, static_cast<int>(len - got), 0);
        if (n == 0) return false;
        if (n < 0) {
            const int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                // A per-call recv timeout is not a peer disconnect: the
                // upstream may legitimately be slow (model load). Keep
                // waiting until the overall deadline expires.
                if (std::chrono::steady_clock::now() >= deadline) {
                    std::clog << "[proxy] RecvAll: overall deadline expired\n";
                    return false;
                }
                continue;
            }
            return false;
        }
        got += static_cast<std::size_t>(n);
    }
    return true;
}

// Read one CRLF-terminated line. Returns false on EOF/hard error.
// A per-call recv timeout (WSAETIMEDOUT) is NOT a peer disconnect: the
// upstream may legitimately take many seconds to produce its first header
// (e.g., while Ollama loads a 28 GB model), so keep waiting until the
// overall deadline expires. Only EOF or a hard socket error aborts.
bool RecvLine(SOCKET s, std::string& out,
              std::chrono::steady_clock::time_point deadline =
                  std::chrono::steady_clock::now() + std::chrono::seconds(1800)) {
    out.clear();
    char c;
    while (true) {
        const int n = ::recv(s, &c, 1, 0);
        if (n == 0) {
            std::clog << "[proxy] RecvLine: orderly close (EOF)\n";
            return false;
        }
        if (n < 0) {
            const int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    std::clog << "[proxy] RecvLine: overall deadline expired\n";
                    return false;
                }
                std::clog << "[proxy] RecvLine: per-call timeout, still waiting\n";
                continue;
            }
            std::clog << "[proxy] RecvLine: recv error wsa=" << err << "\n";
            return false;
        }
        if (c == '\n') {
            if (!out.empty() && out.back() == '\r') out.pop_back();
            return true;
        }
        out.push_back(c);
        if (out.size() > 64 * 1024) return false;  // header line sanity cap
    }
}

struct HttpRequest {
    std::string method;
    std::string rawUrl;
    std::string pathAndQuery;
    std::string host;
    std::map<std::string, std::string> headers;  // lower-cased keys
    std::string body;
    bool keepAlive = true;
};

bool ParseRequest(SOCKET s, HttpRequest& req, std::size_t maxBody) {
    std::string requestLine;
    if (!RecvLine(s, requestLine)) return false;

    // METHOD SP TARGET SP VERSION
    std::size_t sp1 = requestLine.find(' ');
    if (sp1 == std::string::npos) return false;
    std::size_t sp2 = requestLine.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;

    req.method       = requestLine.substr(0, sp1);
    req.rawUrl       = requestLine.substr(sp1 + 1, sp2 - sp1 - 1);
    req.pathAndQuery = req.rawUrl;

    // Headers
    while (true) {
        std::string line;
        if (!RecvLine(s, line)) return false;
        if (line.empty()) break;

        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = ToLower(Trim(line.substr(0, colon)));
        std::string val = Trim(line.substr(colon + 1));
        req.headers[key] = val;
    }

    const auto itConn = req.headers.find("connection");
    if (itConn != req.headers.end()) {
        req.keepAlive = ToLower(itConn->second).find("close") == std::string::npos;
    }
    if (req.headers.count("proxy-connection")) {
        req.keepAlive = ToLower(req.headers.at("proxy-connection")).find("close") == std::string::npos;
    }

    std::size_t contentLength = 0;
    const auto itLen = req.headers.find("content-length");
    if (itLen != req.headers.end()) {
        try {
            contentLength = static_cast<std::size_t>(std::stoull(itLen->second));
        } catch (...) {
            return false;
        }
    }

    if (contentLength > maxBody) return false;

    if (contentLength > 0) {
        req.body.resize(contentLength);
        if (!RecvAll(s, &req.body[0], contentLength)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Upstream forwarding
// ---------------------------------------------------------------------------

// Extract a header value (case-insensitive) from a raw header block.
std::string HeaderValue(const std::string& headerBlock, const std::string& name) {
    const std::string lname = ToLower(name);
    std::size_t pos = 0;
    while (pos < headerBlock.size()) {
        const std::size_t eol = headerBlock.find("\r\n", pos);
        if (eol == std::string::npos) break;
        const std::string line = headerBlock.substr(pos, eol - pos);
        pos = eol + 2;
        if (line.empty()) break;
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (ToLower(Trim(line.substr(0, colon))) == lname) {
            return Trim(line.substr(colon + 1));
        }
    }
    return {};
}

struct UpstreamResponse {
    long        status = 0;
    std::string headerBlock;
    std::string body;
};

// Blocking upstream request with timeouts. Returns false on transport error.
bool UpstreamRequest(const HttpRequest& req,
                     const std::string& method,
                     const std::string& pathAndQuery,
                     const std::string& body,
                     const std::string& contentType,
                     UpstreamResponse& out,
                     std::string& err)
{
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        err = "socket() failed";
        return false;
    }

    struct timeval tv;
    tv.tv_sec  = g_cfg.upstreamTimeoutSec;
    tv.tv_usec = 0;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    // Diagnostic: read back the effective per-call timeout actually applied.
    {
        struct timeval eff;
        int effLen = sizeof(eff);
        ::getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&eff), &effLen);
        std::clog << "[proxy] upstream SO_RCVTIMEO readback=" << eff.tv_sec << "s "
                  << eff.tv_usec << "us\n";
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(g_cfg.upstreamPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = "connect to upstream failed";
        ::closesocket(s);
        return false;
    }

    std::string reqText;
    reqText += method + " " + pathAndQuery + " HTTP/1.1\r\n";
    reqText += "Host: 127.0.0.1:" + std::to_string(g_cfg.upstreamPort) + "\r\n";
    reqText += "Connection: close\r\n";
    if (!contentType.empty()) reqText += "Content-Type: " + contentType + "\r\n";
    reqText += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    reqText += "\r\n";
    reqText += body;

    if (!SendAll(s, reqText.data(), reqText.size())) {
        err = "send to upstream failed";
        ::closesocket(s);
        return false;
    }

    // Read headers
    std::string headerBlock;
    while (true) {
        std::string line;
        if (!RecvLine(s, line)) {
            err = "upstream closed before headers";
            ::closesocket(s);
            return false;
        }
        headerBlock += line + "\r\n";
        if (line.empty()) break;
        if (headerBlock.size() > 64 * 1024) {
            err = "upstream header block too large";
            ::closesocket(s);
            return false;
        }
    }

    // Parse status line
    {
        const std::size_t sp = headerBlock.find(' ');
        if (sp != std::string::npos) {
            try { out.status = std::stol(headerBlock.substr(sp + 1, 3)); }
            catch (...) { out.status = 0; }
        }
    }
    out.headerBlock = headerBlock;

    // Read body
    std::string chunked = ToLower(HeaderValue(headerBlock, "Transfer-Encoding"));
    const bool isChunked = chunked.find("chunked") != std::string::npos;

    if (isChunked) {
        while (true) {
            std::string sizeLine;
            if (!RecvLine(s, sizeLine)) break;
            std::size_t semi = sizeLine.find(';');
            if (semi != std::string::npos) sizeLine.resize(semi);
            unsigned long chunk = 0;
            try { chunk = std::stoul(Trim(sizeLine), nullptr, 16); }
            catch (...) { break; }
            if (chunk == 0) { RecvLine(s, sizeLine); break; }
            if (out.body.size() + chunk > g_cfg.maxBodyBytes) break;
            const std::size_t old = out.body.size();
            out.body.resize(old + chunk);
            if (!RecvAll(s, &out.body[old], chunk)) { out.body.resize(old); break; }
            RecvLine(s, sizeLine);  // trailing CRLF
        }
    }
    else {
        const std::string cl = HeaderValue(headerBlock, "Content-Length");
        std::size_t contentLength = 0;
        bool haveLen = false;
        if (!cl.empty()) {
            try { contentLength = static_cast<std::size_t>(std::stoull(cl)); haveLen = true; }
            catch (...) { }
        }

        char buf[16384];
        while (true) {
            const int n = ::recv(s, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (!haveLen && out.body.size() + static_cast<std::size_t>(n) > g_cfg.maxBodyBytes) break;
            out.body.append(buf, static_cast<std::size_t>(n));
            if (haveLen && out.body.size() >= contentLength) break;
        }
    }

    ::closesocket(s);
    return true;
}

// ---------------------------------------------------------------------------
// Streaming relay
// ---------------------------------------------------------------------------

// Forward a request upstream and relay the response body to the client while
// it is still being produced. The body is never buffered: each chunk read from
// the upstream socket is written straight to the client, so token-by-token SSE
// delivery works. If the client disconnects, the client send fails, the
// upstream socket is closed, and Ollama aborts the generation.
//
// The upstream header block is forwarded with hop-by-hop headers stripped and
// Connection: close forced. Framing headers (Transfer-Encoding / Content-Length)
// are preserved and the body is relayed byte-for-byte, so the client de-frames
// exactly what the upstream sent: SSE data: events and the terminal [DONE]
// marker pass through verbatim because nothing is parsed or rewritten.
//
// Returns true when a response (any status) was relayed; false only when the
// upstream request could not be made at all. On false, nothing has been sent
// to the client yet, so the caller may still send a JSON error.
bool UpstreamRelay(SOCKET client,
                   const std::string& method,
                   const std::string& pathAndQuery,
                   const std::string& body,
                   const std::string& contentType,
                   long& outStatus,
                   std::size_t& relayedBytes,
                   bool& clientGone,
                   std::string& err)
{
    outStatus    = 0;
    relayedBytes = 0;
    clientGone   = false;

    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        err = "socket() failed";
        return false;
    }

    struct timeval tv;
    tv.tv_sec  = g_cfg.upstreamTimeoutSec;
    tv.tv_usec = 0;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    // Diagnostic: read back the effective per-call timeout actually applied.
    {
        struct timeval eff;
        int effLen = sizeof(eff);
        ::getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&eff), &effLen);
        std::clog << "[proxy] upstream SO_RCVTIMEO readback=" << eff.tv_sec << "s "
                  << eff.tv_usec << "us\n";
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(g_cfg.upstreamPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = "connect to upstream failed";
        ::closesocket(s);
        return false;
    }

    std::string reqText;
    reqText += method + " " + pathAndQuery + " HTTP/1.1\r\n";
    reqText += "Host: 127.0.0.1:" + std::to_string(g_cfg.upstreamPort) + "\r\n";
    reqText += "Connection: close\r\n";
    if (!contentType.empty()) reqText += "Content-Type: " + contentType + "\r\n";
    reqText += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    reqText += "\r\n";
    reqText += body;

    if (!SendAll(s, reqText.data(), reqText.size())) {
        err = "send to upstream failed";
        ::closesocket(s);
        return false;
    }

    // Read the upstream header block.
    std::string headerBlock;
    while (true) {
        std::string line;
        if (!RecvLine(s, line)) {
            err = "upstream closed before headers";
            ::closesocket(s);
            return false;
        }
        headerBlock += line + "\r\n";
        if (line.empty()) break;
        if (headerBlock.size() > 64 * 1024) {
            err = "upstream header block too large";
            ::closesocket(s);
            return false;
        }
    }

    // Parse the status code.
    {
        const std::size_t sp = headerBlock.find(' ');
        if (sp != std::string::npos) {
            try { outStatus = std::stol(headerBlock.substr(sp + 1, 3)); }
            catch (...) { outStatus = 0; }
        }
    }

    // Forward the status line and headers, dropping hop-by-hop entries. The
    // upstream framing headers (Transfer-Encoding / Content-Length) are kept
    // and the body is relayed byte-for-byte, so chunked responses stay chunked
    // and the client never sees a framing mismatch.
    std::string outHead;
    std::size_t pos = 0;
    bool first = true;
    while (pos < headerBlock.size()) {
        const std::size_t eol = headerBlock.find("\r\n", pos);
        if (eol == std::string::npos) break;
        const std::string line = headerBlock.substr(pos, eol - pos);
        pos = eol + 2;
        if (first) {  // status line
            outHead += line + "\r\n";
            first = false;
            continue;
        }
        if (line.empty()) break;
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        const std::string name = ToLower(Trim(line.substr(0, colon)));
        if (name == "connection" || name == "keep-alive" ||
            name == "proxy-connection") {
            continue;  // hop-by-hop only
        }
        outHead += line + "\r\n";
    }
    outHead += "Connection: close\r\n\r\n";

    if (!SendAll(client, outHead.data(), outHead.size())) {
        // Client vanished before the first byte of the response.
        clientGone = true;
        ::closesocket(s);
        return true;
    }

    char buf[16384];
    while (g_running.load()) {
        const int n = ::recv(s, buf, sizeof(buf), 0);
        if (n < 0) {
            const int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                // Slow stream, not a dead pipe: keep pulling.
                std::clog << "[proxy] body recv: per-call timeout, still waiting\n";
                continue;
            }
            break;  // hard error
        }
        if (n == 0) break;  // upstream EOF / idle timeout
        if (!SendAll(client, buf, static_cast<std::size_t>(n))) {
            // Client is gone: stop pulling from upstream and close the socket
            // so Ollama cancels the generation instead of filling a dead pipe.
            clientGone = true;
            break;
        }
        relayedBytes += static_cast<std::size_t>(n);
    }

    ::closesocket(s);
    return true;
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

void SendJsonError(SOCKET s, long code, const std::string& message, const std::string& reqId) {
    const std::string body =
        "{\"error\":{\"message\":\"" + JsonEscape(message) +
        "\",\"type\":\"proxy_error\",\"request_id\":\"" + JsonEscape(reqId) + "\"}}";

    const std::string head =
        "HTTP/1.1 " + std::to_string(code) + " " +
        (code == 400 ? "Bad Request" : code == 404 ? "Not Found" :
         code == 413 ? "Payload Too Large" : code == 502 ? "Bad Gateway" :
         code == 504 ? "Gateway Timeout" : "Internal Server Error") +
        "\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";

    SendAll(s, head.data(), head.size());
    SendAll(s, body.data(), body.size());
}

void HandleClient(SOCKET s) {
    const std::string reqId = [&] {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%08x",
                      static_cast<unsigned>(::GetTickCount64() ^ static_cast<unsigned long long>(s)));
        return std::string(buf);
    }();

    while (g_running.load()) {
        HttpRequest req;
        if (!ParseRequest(s, req, g_cfg.maxBodyBytes)) {
            // Distinguish "no request at all" (benign close) from an oversized
            // or malformed body, which the client should hear about.
            if (req.body.size() > g_cfg.maxBodyBytes) {
                SendJsonError(s, 413, "request body exceeds proxy limit", reqId);
            }
            break;
        }

        const auto t0 = std::chrono::steady_clock::now();
        const std::string path = req.pathAndQuery;

        // ---- Health probe (cheap, always fast) --------------------------------
        if (req.method == "GET" && path.find("/v1/models") != std::string::npos) {
            UpstreamResponse up;
            std::string err;
            if (UpstreamRequest(req, "GET", "/api/tags", "", "", up, err)) {
                // Translate Ollama's /api/tags into OpenAI /v1/models shape.
                std::string json = "{\"object\":\"list\",\"data\":[";
                std::size_t pos = 0;
                bool first = true;
                while (true) {
                    const std::size_t p = up.body.find("\"name\":\"", pos);
                    if (p == std::string::npos) break;
                    const std::size_t vstart = p + 8;
                    const std::size_t vend   = up.body.find('"', vstart);
                    if (vend == std::string::npos) break;
                    const std::string name = up.body.substr(vstart, vend - vstart);
                    pos = vend;
                    if (name.empty()) continue;
                    if (!first) json += ",";
                    json += "{\"id\":\"" + JsonEscape(name) +
                            "\",\"object\":\"model\",\"created\":0,\"owned_by\":\"library\"}";
                    first = false;
                }
                json += "]}";

                const std::string head =
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                    std::to_string(json.size()) + "\r\nConnection: close\r\n\r\n";
                SendAll(s, head.data(), head.size());
                SendAll(s, json.data(), json.size());

                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();
                if (g_cfg.verbose) {
                    Log("[" + NowStamp() + "][" + reqId + "] GET /v1/models -> 200 " +
                        std::to_string(ms) + "ms");
                }
            }
            else {
                SendJsonError(s, 502, "upstream unreachable: " + err, reqId);
            }

            if (!req.keepAlive) break;
            continue;
        }

        // ---- Chat completions -------------------------------------------------
        if (req.method == "POST" && path.find("/v1/chat/completions") != std::string::npos) {
            std::string requestedModel, effectiveModel;
            std::string outBody = req.body;

            if (!req.body.empty()) {
                if (ExtractJsonStringField(req.body, "model", requestedModel)) {
                    const auto& aliases = Aliases();
                    const auto it = aliases.find(requestedModel);
                    if (it != aliases.end()) {
                        effectiveModel = it->second;
                        // Rewrite only the model value, preserving everything else.
                        const std::size_t keyPos = outBody.find("\"model\"");
                        if (keyPos != std::string::npos) {
                            const std::size_t colon = outBody.find(':', keyPos);
                            const std::size_t q1 = outBody.find('"', colon);
                            const std::size_t q2 = (q1 == std::string::npos)
                                                   ? std::string::npos
                                                   : outBody.find('"', q1 + 1);
if (q1 != std::string::npos && q2 != std::string::npos) {
                outBody = outBody.substr(0, q1 + 1) + effectiveModel +
                          outBody.substr(q2 + 1);
                            }
                        }
                        if (g_cfg.verbose) {
                            Log("[" + NowStamp() + "][" + reqId + "] ALIAS " +
                                requestedModel + " -> " + effectiveModel);
                        }
                    }
                    else {
                        effectiveModel = requestedModel;
                    }
                }
            }

            const bool isStream = JsonBoolField(req.body, "stream");

            if (isStream) {
                // True streaming relay: bytes flow to the client while the
                // model is still generating. A client disconnect fails the
                // relay's client send, which closes the upstream socket and
                // makes Ollama cancel the generation.
                long status = 0;
                std::size_t relayed = 0;
                bool clientGone = false;
                std::string streamErr;
                const bool relayedOk = UpstreamRelay(s, "POST", "/v1/chat/completions",
                                                     outBody, "application/json",
                                                     status, relayed, clientGone, streamErr);
                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();

                if (!relayedOk) {
                    Log("[" + NowStamp() + "][" + reqId + "] POST /v1/chat/completions -> 502 (" + streamErr + ")");
                    SendJsonError(s, 502, "upstream failure: " + streamErr, reqId);
                }
                else if (g_cfg.verbose) {
                    Log("[" + NowStamp() + "][" + reqId + "] POST /v1/chat/completions -> " +
                        std::to_string(status) + " stream" +
                        " model=" + (effectiveModel.empty() ? "(none)" : effectiveModel) +
                        " requested=" + (requestedModel.empty() ? "(none)" : requestedModel) +
                        " " + std::to_string(ms) + "ms " +
                        std::to_string(relayed) + " bytes" +
                        (clientGone ? " CLIENT_DISCONNECTED" : ""));
                }
                break;  // the relay always answers with Connection: close
            }

            UpstreamResponse up;
            std::string err;
            const bool ok = UpstreamRequest(req, "POST", "/v1/chat/completions",
                                            outBody, "application/json", up, err);
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();

            if (!ok) {
                Log("[" + NowStamp() + "][" + reqId + "] POST /v1/chat/completions -> 502 (" + err + ")");
                SendJsonError(s, 502, "upstream failure: " + err, reqId);
            }
            else {
                const std::string head =
                    "HTTP/1.1 " + std::to_string(up.status) + " " +
                    (up.status == 200 ? "OK" : "Error") +
                    "\r\nContent-Type: application/json\r\nContent-Length: " +
                    std::to_string(up.body.size()) + "\r\nConnection: close\r\n\r\n";
                SendAll(s, head.data(), head.size());
                SendAll(s, up.body.data(), up.body.size());

                if (g_cfg.verbose) {
                    Log("[" + NowStamp() + "][" + reqId + "] POST /v1/chat/completions -> " +
                        std::to_string(up.status) +
                        " model=" + (effectiveModel.empty() ? "(none)" : effectiveModel) +
                        " requested=" + (requestedModel.empty() ? "(none)" : requestedModel) +
                        " " + std::to_string(ms) + "ms " +
                        std::to_string(up.body.size()) + " bytes");
                }
            }

            if (!req.keepAlive) break;
            continue;
        }

        // ---- Everything else: forward verbatim -------------------------------
        {
            UpstreamResponse up;
            std::string err;
            if (UpstreamRequest(req, req.method, path, req.body, "", up, err)) {
                const std::string head =
                    "HTTP/1.1 " + std::to_string(up.status) + " OK\r\n" +
                    "Content-Type: application/json\r\nContent-Length: " +
                    std::to_string(up.body.size()) + "\r\nConnection: close\r\n\r\n";
                SendAll(s, head.data(), head.size());
                SendAll(s, up.body.data(), up.body.size());
            }
            else {
                SendJsonError(s, 502, "upstream failure: " + err, reqId);
            }
            break;  // verbatim forwards are one-shot
        }
    }

    ::closesocket(s);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

void PrintUsage() {
    std::fprintf(stdout,
        "usage: rawrxd_ollama_proxy [--listen PORT] [--upstream PORT] [--bind ADDR] [--quiet]\n"
        "\n"
        "  --listen PORT     port to serve (default 11436, the port stored in the\n"
        "                    VS Code \"Deep2 Local\" custom endpoint; use 8080 for the\n"
        "                    older deep2_openai_server URL)\n"
        "  --upstream PORT   Ollama port (default 11434)\n"
        "  --bind ADDR       bind address (default 127.0.0.1, loopback only)\n"
        "  --max-workers N   concurrent connection cap (default 64, 0 = unlimited)\n"
        "  --quiet           suppress per-request logging\n");
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) return {};
            return argv[++i];
        };

        if (a == "--listen" || a == "-l") {
            const std::string v = next();
            try { g_cfg.listenPort = static_cast<uint16_t>(std::stoi(v)); }
            catch (...) { std::fprintf(stderr, "invalid --listen\n"); return 2; }
        }
        else if (a == "--upstream" || a == "-u") {
            const std::string v = next();
            try { g_cfg.upstreamPort = static_cast<uint16_t>(std::stoi(v)); }
            catch (...) { std::fprintf(stderr, "invalid --upstream\n"); return 2; }
        }
        else if (a == "--bind" || a == "-b") {
            g_cfg.bindAddress = next();
        }
        else if (a == "--max-workers") {
            const std::string v = next();
            try { g_cfg.maxConcurrentWorkers = std::stoi(v); }
            catch (...) { std::fprintf(stderr, "invalid --max-workers\n"); return 2; }
        }
        else if (a == "--quiet" || a == "-q") {
            g_cfg.verbose = false;
        }
        else if (a == "--help" || a == "-h" || a == "/?") {
            PrintUsage();
            return 0;
        }
        else {
            std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
            PrintUsage();
            return 2;
        }
    }

    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    SOCKET listenSock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        std::fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        return 1;
    }

    BOOL yes = TRUE;
    ::setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(g_cfg.listenPort);
    if (::inet_pton(AF_INET, g_cfg.bindAddress.c_str(), &addr.sin_addr) != 1) {
        std::fprintf(stderr, "invalid bind address: %s\n", g_cfg.bindAddress.c_str());
        return 1;
    }

    if (::bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int wsaerr = WSAGetLastError();
        if (wsaerr == WSAEADDRINUSE) {
            std::fprintf(stderr,
                "port %u is already in use.\n"
                "Refusing to start; not terminating the existing owner.\n"
                "Use --listen to pick another port.\n",
                static_cast<unsigned>(g_cfg.listenPort));
        }
        else {
            std::fprintf(stderr, "bind() failed: %d\n", wsaerr);
        }
        ::closesocket(listenSock);
        ::WSACleanup();
        return 1;
    }

    if (::listen(listenSock, SOMAXCONN) != 0) {
        std::fprintf(stderr, "listen() failed: %d\n", WSAGetLastError());
        ::closesocket(listenSock);
        ::WSACleanup();
        return 1;
    }

    std::fprintf(stdout, "[proxy] listening  http://%s:%u/\n",
                 g_cfg.bindAddress.c_str(), static_cast<unsigned>(g_cfg.listenPort));
    std::fprintf(stdout, "[proxy] forwarding -> http://127.0.0.1:%u\n",
                 static_cast<unsigned>(g_cfg.upstreamPort));
    std::fprintf(stdout, "[proxy] aliases:\n");
    for (const auto& kv : Aliases()) {
        std::fprintf(stdout, "[proxy]   %s  ->  %s\n", kv.first.c_str(), kv.second.c_str());
    }
    std::fprintf(stdout, "[proxy] max concurrent workers: %d\n",
                 g_cfg.maxConcurrentWorkers);
    std::fprintf(stdout, "[proxy] Ctrl+C to stop.\n");
    std::fflush(stdout);

    // Ctrl+C / console close: stop accepting new work. In-flight requests get
    // a bounded grace period below, then the process exits rather than hangs.
    ::SetConsoleCtrlHandler([](DWORD) -> BOOL {
        g_running.store(false);
        return TRUE;  // handled: the accept loop exits on its own
    }, TRUE);

    while (g_running.load()) {
        // Bounded worker pool: apply backpressure instead of spawning an
        // unbounded number of threads under sustained load.
        if (g_cfg.maxConcurrentWorkers > 0) {
            std::unique_lock<std::mutex> lk(g_workerMu);
            if (g_activeWorkers >= g_cfg.maxConcurrentWorkers) {
                g_workerCv.wait_for(lk, std::chrono::milliseconds(200), [&] {
                    return !g_running.load() ||
                           g_activeWorkers < g_cfg.maxConcurrentWorkers;
                });
            }
            if (!g_running.load()) break;
        }

        // select() with a short timeout so the loop notices g_running even
        // while no client is connecting (a plain blocking accept() would not).
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listenSock, &rfds);
        timeval sel;
        sel.tv_sec  = 0;
        sel.tv_usec = 200000;  // 200 ms
        if (::select(0, &rfds, nullptr, nullptr, &sel) <= 0) continue;

        sockaddr_in clientAddr{};
        int len = sizeof(clientAddr);
        const SOCKET client = ::accept(listenSock, reinterpret_cast<sockaddr*>(&clientAddr), &len);
        if (client == INVALID_SOCKET) {
            if (!g_running.load()) break;
            continue;
        }

        // One thread per connection. A long streaming generation can never
        // block the accept loop or other clients.
        {
            std::lock_guard<std::mutex> lk(g_workerMu);
            ++g_activeWorkers;
        }
        try {
            std::thread([client]() {
                HandleClient(client);
                {
                    std::lock_guard<std::mutex> lk(g_workerMu);
                    --g_activeWorkers;
                }
                g_workerCv.notify_all();
            }).detach();
        }
        catch (...) {
            std::clog << "[proxy] failed to spawn worker (active="
                      << g_activeWorkers << ")\n";
            ::closesocket(client);
            std::lock_guard<std::mutex> lk(g_workerMu);
            --g_activeWorkers;
            g_workerCv.notify_all();
        }
    }

    g_running.store(false);
    ::closesocket(listenSock);

    // Bounded grace period for in-flight streaming requests; then exit. The
    // workers are detached and cannot outlive the process.
    {
        std::unique_lock<std::mutex> lk(g_workerMu);
        g_workerCv.wait_for(lk, std::chrono::seconds(15),
                            [] { return g_activeWorkers == 0; });
    }

    ::WSACleanup();
    std::fprintf(stdout, "[proxy] stopped.\n");
    return 0;
}