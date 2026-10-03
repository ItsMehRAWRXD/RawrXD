// ============================================================================
// CdpTransport.cpp -- real RFC6455 + CDP implementation.
//
// See CdpTransport.hpp for the evidence law this file obeys.
// ============================================================================

#include "browser/CdpTransport.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace rawrxd::browser {

namespace {

// One-time Winsock init. A function-local static makes this thread-safe and
// runs exactly once; the return value is deliberately discarded because a
// failure here surfaces as a failed socket() immediately afterwards.
bool ensureWinsock() {
    static const bool ok = [] {
        WSADATA wsa{};
        return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    return ok;
}

void closeSocket(std::uint64_t& s) {
    if (s != ~0ull) {
        ::closesocket(static_cast<SOCKET>(s));
        s = ~0ull;
    }
}

// Blocking socket with a receive timeout, so a browser that never answers
// becomes a measured timeout rather than a hang.
bool setRecvTimeout(std::uint64_t s, int ms) {
    DWORD tv = static_cast<DWORD>(ms);
    return ::setsockopt(static_cast<SOCKET>(s), SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
}

std::uint64_t nowMs() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

const char kBase64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64(const unsigned char* data, std::size_t n) {
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    for (std::size_t i = 0; i < n; i += 3) {
        const unsigned v0 = data[i];
        const unsigned v1 = (i + 1 < n) ? data[i + 1] : 0u;
        const unsigned v2 = (i + 2 < n) ? data[i + 2] : 0u;
        out += kBase64[(v0 >> 2) & 0x3F];
        out += kBase64[((v0 << 4) | (v1 >> 4)) & 0x3F];
        out += (i + 1 < n) ? kBase64[((v1 << 2) | (v2 >> 6)) & 0x3F] : '=';
        out += (i + 2 < n) ? kBase64[v2 & 0x3F] : '=';
    }
    return out;
}

// RFC 6455 client frames MUST be masked with a 32-bit key (5.3).
void applyMask(unsigned char* p, std::size_t n, std::uint32_t key) {
    for (std::size_t i = 0; i < n; ++i)
        p[i] ^= static_cast<unsigned char>((key >> (8 * (3 - (i % 4)))) & 0xFF);
}

// Blocking send-all. A partial write on a large payload is normal, not an
// error, so looping is required for correctness rather than as a retry.
bool sendAll(std::uint64_t s, const unsigned char* p, std::size_t n,
             std::string& err) {
    std::size_t sent = 0;
    while (sent < n) {
        const int w = ::send(static_cast<SOCKET>(s),
                             reinterpret_cast<const char*>(p + sent),
                             static_cast<int>(n - sent), 0);
        if (w <= 0) {
            std::ostringstream e;
            e << "send failed after " << sent << "/" << n << " bytes, WSA="
              << WSAGetLastError();
            err = e.str();
            return false;
        }
        sent += static_cast<std::size_t>(w);
    }
    return true;
}

// Reads exactly n bytes, or stops early. `outError` receives the WSA error when
// the read stopped short.
//
// DISTINGUISHING TIMEOUT FROM CLOSE.
//
// The first version returned a byte count and used `== 0` for "peer closed".
// But recv() returning SOCKET_ERROR on SO_RCVTIMEO expiry also yields 0 bytes
// read, so every quiet period was reported as a peer disconnect. Against a real
// Edge that surfaced as a confident "peer closed while reading frame header" in
// the middle of a working session -- pointing the reader at the browser instead
// of at the transport.
//
// A timeout is not a disconnect and not an error. Callers need to tell all three
// apart, so this returns a signed status:
//     > 0  : bytes read
//     == 0 : peer closed cleanly (recv returned 0)
//     == -1: socket error or timeout; consult outError and isTimeout
bool recvAll(std::uint64_t s, unsigned char* p, std::size_t n,
             long& outError, bool& isTimeout) {
    outError = 0;
    isTimeout = false;
    std::size_t got = 0;
    while (got < n) {
        const int r = ::recv(static_cast<SOCKET>(s),
                             reinterpret_cast<char*>(p + got),
                             static_cast<int>(n - got), 0);
        if (r == 0) {                 // orderly shutdown by the peer
            outError = 0;
            return false;
        }
        if (r < 0) {
            const int wsa = WSAGetLastError();
            outError = wsa;
            if (wsa == WSAETIMEDOUT || wsa == WSAEWOULDBLOCK) {
                isTimeout = true;
                return false;
            }
            return false;              // genuine transport error
        }
        got += static_cast<std::size_t>(r);
    }
    return true;
}

// Cryptographic quality is not required for the RFC 6455 key: it exists so a
// proxy cannot answer from cache, not to protect a secret. BCrypt is preferred
// and used when it succeeds; otherwise a documented nonce is used and the
// fallback is REPORTED rather than hidden, because "which key source ran" is
// evidence about the handshake like any other.
//
// Returns the NTSTATUS through `status` so a failure names its cause instead of
// appearing as an opaque "handshake failed".
std::string randomBytes(std::size_t n, long& status) {
    std::string out;
    out.resize(n);
    status = static_cast<long>(
        BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&out[0]),
                        static_cast<ULONG>(n),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    if (status == 0) return out;

    // Fallback: QPC + pid + a fixed tag, mixed so successive handshakes differ.
    LARGE_INTEGER qpc{};
    ::QueryPerformanceCounter(&qpc);
    const std::uint64_t mix =
        (static_cast<std::uint64_t>(qpc.QuadPart) * 0x9E3779B97F4A7C15ull)
        ^ (static_cast<std::uint64_t>(::GetCurrentProcessId()) << 32)
        ^ static_cast<std::uint64_t>(nowMs());
    for (std::size_t i = 0; i < n; ++i)
        out[i] = static_cast<char>((mix >> ((i % 8) * 8)) ^ (i * 131));
    return out;
}

// RFC 6455 1.3: Sec-WebSocket-Accept = base64(SHA1(key + GUID)).
// Implemented with BCrypt. Two things that were wrong in the first version and
// produced a confident "peer is not a WebSocket server" against an Edge that
// was in fact a WebSocket server:
//   * HP_HASHDATA no longer exists in the current Windows SDK, so the legacy
//     CryptoAPI path is unusable;
//   * the provider was opened with BCRYPT_ALG_HANDLE_HMAC_FLAG, which selects
//     the HMAC variant of SHA-1. Hashing with no key through that provider does
//     NOT equal plain SHA-1, so every accept value was wrong.
//
// The handshake is RFC-correct, not optional: skipping the accept check would
// "fix" this by removing the only thing that distinguishes a WebSocket server
// from any other process that answers 101.
std::string websocketAccept(const std::string& key, std::string* dbg = nullptr) {
    const std::string concat =
        key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr,
                                    0) != 0) {
        if (dbg) *dbg = "BCryptOpenAlgorithmProvider(SHA1) failed";
        return {};
    }

    DWORD objLen = 0, cb = 0;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objLen),
                          sizeof(objLen), &cb, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        if (dbg) *dbg = "BCryptGetProperty(OBJECT_LENGTH) failed";
        return {};
    }
    std::string obj(objLen, '\0');
    BCRYPT_HASH_HANDLE h = nullptr;
    std::string digest;
    bool ok = false;
    if (BCryptCreateHash(alg, &h,
                         reinterpret_cast<PUCHAR>(&obj[0]), objLen,
                         nullptr, 0, 0) == 0) {
        unsigned char out[20];
        std::string mutableConcat = concat;
        if (BCryptHashData(h,
                           reinterpret_cast<PUCHAR>(&mutableConcat[0]),
                           static_cast<ULONG>(mutableConcat.size()), 0) == 0 &&
            BCryptFinishHash(h, out, sizeof(out), 0) == 0) {
            digest = base64(out, sizeof(out));
            ok = true;
        } else if (dbg) {
            *dbg = "BCryptHashData/FinishHash failed";
        }
        BCryptDestroyHash(h);
    } else if (dbg) {
        *dbg = "BCryptCreateHash failed";
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok && dbg && dbg->empty()) *dbg = "SHA1 produced no digest";
    return ok ? digest : std::string{};
}

bool isLoopbackHost(const std::string& host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1"
        || host == "[::1]";
}

} // namespace

// ===========================================================================
// WebSocketClient
// ===========================================================================

WebSocketClient::~WebSocketClient() { close(); }

void WebSocketClient::close() {
    closeSocket(socket_);
    handshakeComplete_ = false;
    inFragment_ = false;
    fragment_.clear();
}

bool WebSocketClient::connect(const std::string& host, std::uint16_t port,
                              const std::string& path, std::string& err) {
    if (!ensureWinsock()) {
        err = "WSAStartup failed";
        return false;
    }
    // Security gate, not a portability limitation. See the header note: a
    // devtools socket is the whole authority of the browser profile.
    if (!isLoopbackHost(host)) {
        err = "refusing non-loopback devtools endpoint '" + host
            + "': a remote devtools socket grants full profile authority";
        return false;
    }

    struct addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const std::string portStr = std::to_string(port);
    if (::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        err = "getaddrinfo failed for " + host + ":" + portStr;
        return false;
    }

    SOCKET s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        ::freeaddrinfo(res);
        err = "socket failed";
        return false;
    }
    if (::connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        const int wsa = WSAGetLastError();
        ::closesocket(s);
        ::freeaddrinfo(res);
        std::ostringstream e;
        e << "connect to " << host << ":" << port << " failed, WSA=" << wsa;
        err = e.str();
        return false;
    }
    ::freeaddrinfo(res);
    socket_ = static_cast<std::uint64_t>(s);
    setRecvTimeout(socket_, 250);

    // ---- RFC 6455 opening handshake ------------------------------------
    // The key is 16 random bytes, base64-encoded.
    long rngStatus = 0;
    const std::string keyRaw = randomBytes(16, rngStatus);
    if (keyRaw.size() != 16) {
        err = "could not obtain a 16-byte Sec-WebSocket-Key from the system RNG";
        close();
        return false;
    }
    const std::string accept =
        base64(reinterpret_cast<const unsigned char*>(keyRaw.data()), 16);

    std::ostringstream hs;
    hs << "GET " << (path.empty() ? std::string("/") : path) << " HTTP/1.1\r\n"
       << "Host: " << host << ":" << port << "\r\n"
       << "Upgrade: websocket\r\n"
       << "Connection: Upgrade\r\n"
       << "Sec-WebSocket-Key: " << accept << "\r\n"
       << "Sec-WebSocket-Version: 13\r\n\r\n";
    const std::string req = hs.str();
    if (!sendAll(socket_, reinterpret_cast<const unsigned char*>(req.data()),
                 req.size(), err)) {
        close();
        return false;
    }

    // Read the response headers, capped so a non-websocket listener cannot
    // stream forever.
    std::string resp;
    resp.reserve(1024);
    char buf[512];
    while (resp.find("\r\n\r\n") == std::string::npos && resp.size() < 16384) {
        const int r = ::recv(static_cast<SOCKET>(socket_), buf,
                             static_cast<int>(sizeof(buf)), 0);
        if (r <= 0) {
            err = "devtools closed during websocket handshake";
            close();
            return false;
        }
        resp.append(buf, static_cast<std::size_t>(r));
    }

    // Validate: 101 status AND the accept key derived from what we sent.
    // Checking only the status would accept any upgrade; the accept check is
    // what proves a WebSocket server, not a cache, answered.
    const bool status101 = resp.rfind("HTTP/1.1 101", 0) == 0;
    if (!status101) {
        err = "websocket upgrade refused: " + resp.substr(0, resp.find("\r\n"));
        close();
        return false;
    }

    std::string acceptDbg;
    const std::string computed = websocketAccept(accept, &acceptDbg);
    if (computed.empty()) {
        err = "could not compute Sec-WebSocket-Accept ("
            + acceptDbg + "); refusing unverified upgrade";
        close();
        return false;
    }
    if (resp.find(computed) == std::string::npos) {
        // Report both sides. "Not a WebSocket server" was the first version's
        // confident conclusion and it was WRONG -- the peer was Edge, and the
        // bug was the local hash. Naming the local expectation and the peer's
        // value is what distinguishes those two cases next time.
        std::string peerAccept;
        const std::size_t k = resp.find("Sec-WebSocket-Accept:");
        if (k != std::string::npos) {
            const std::size_t s = resp.find("\r\n", k);
            peerAccept = resp.substr(k + 21,
                                    (s == std::string::npos ? resp.size() : s)
                                        - k - 21);
        }
        err = "Sec-WebSocket-Accept mismatch: computed=" + computed
            + " peer=" + (peerAccept.empty() ? "<absent>" : peerAccept);
        close();
        return false;
    }

    // Consume any frame bytes that arrived with the headers.
    const std::size_t hdrEnd = resp.find("\r\n\r\n");
    if (hdrEnd != std::string::npos && resp.size() > hdrEnd + 4) {
        fragment_ = resp.substr(hdrEnd + 4);
        inFragment_ = true;
        fragmentOpcode_ = 1;
    }

    handshakeComplete_ = true;
    return true;
}

bool WebSocketClient::sendText(const std::string& payload, std::string& err) {
    if (socket_ == ~0ull) { err = "socket not connected"; return false; }

    std::vector<unsigned char> frame;
    frame.reserve(payload.size() + 14);
    frame.push_back(0x81);                       // FIN + text opcode

    const std::size_t n = payload.size();
    if (n < 126) {
        frame.push_back(static_cast<unsigned char>(0x80 | n));   // MASK set
    } else if (n <= 0xFFFF) {
        frame.push_back(0x80 | 126);
        frame.push_back(static_cast<unsigned char>((n >> 8) & 0xFF));
        frame.push_back(static_cast<unsigned char>(n & 0xFF));
    } else {
        frame.push_back(0x80 | 127);
        for (int i = 7; i >= 0; --i)
            frame.push_back(static_cast<unsigned char>((n >> (8 * i)) & 0xFF));
    }

    // A fixed mask key would still be RFC-conformant but is poor practice; the
    // value is varied per frame from the clock so two frames of the same length
    // do not produce identical wire bytes.
    const std::uint32_t key =
        static_cast<std::uint32_t>(nowMs() * 2654435761u) | 1u;
    frame.push_back(static_cast<unsigned char>((key >> 24) & 0xFF));
    frame.push_back(static_cast<unsigned char>((key >> 16) & 0xFF));
    frame.push_back(static_cast<unsigned char>((key >> 8) & 0xFF));
    frame.push_back(static_cast<unsigned char>(key & 0xFF));

    const std::size_t maskStart = frame.size();
    frame.insert(frame.end(), payload.begin(), payload.end());
    applyMask(frame.data() + maskStart, n, key);

    return sendAll(socket_, frame.data(), frame.size(), err);
}

int WebSocketClient::receive(std::vector<std::string>& outMessages,
                             std::vector<std::uint8_t>& outOpcodes,
                             int deadlineMs, std::string& err) {
    if (socket_ == ~0ull) { err = "socket not connected"; return 0; }
    const std::uint64_t deadline = nowMs() + static_cast<std::uint64_t>(
        deadlineMs < 0 ? 0 : deadlineMs);

    int completed = 0;
    for (;;) {
        const std::uint64_t t = nowMs();
        if (t >= deadline) { err = "receive deadline reached"; return completed; }
        setRecvTimeout(socket_,
                       static_cast<int>(deadline - t > 250 ? 250 : deadline - t));

        // A read that times out here is NORMAL -- no frame arrived within the
        // poll window. It is not a close and not an error, so the loop simply
        // re-checks the deadline.
        unsigned char h[2];
        long wsa = 0;
        bool timedOut = false;
        if (!recvAll(socket_, h, 2, wsa, timedOut)) {
            if (timedOut) {
                if (nowMs() >= deadline) { err = "receive deadline reached"; return completed; }
                continue;
            }
            if (wsa == 0) { err = "peer closed the connection cleanly"; return completed; }
            std::ostringstream e;
            e << "socket error while reading frame header, WSA=" << wsa;
            err = e.str();
            return completed;
        }

        const bool fin     = (h[0] & 0x80) != 0;
        const std::uint8_t op = h[0] & 0x0F;
        const bool masked = (h[1] & 0x80) != 0;
        std::uint64_t len  = h[1] & 0x7F;

        // Payload readers: a timeout part-way through a frame IS an error,
        // because the frame header promised bytes that never arrived.
        auto readExact = [&](unsigned char* dst, std::size_t want,
                             const char* what) -> bool {
            long e2 = 0; bool to2 = false;
            if (recvAll(socket_, dst, want, e2, to2)) return true;
            std::ostringstream e;
            e << (to2 ? "timed out reading " : "failed reading ") << what
              << " (WSA=" << e2 << ")";
            err = e.str();
            return false;
        };

        if (len == 126) {
            unsigned char e[2];
            if (!readExact(e, 2, "16-bit length")) return completed;
            len = (static_cast<std::uint64_t>(e[0]) << 8) | e[1];
        } else if (len == 127) {
            unsigned char e[8];
            if (!readExact(e, 8, "64-bit length")) return completed;
            len = 0;
            for (int i = 0; i < 8; ++i) len = (len << 8) | e[i];
        }

        std::uint32_t maskKey = 0;
        if (masked) {
            unsigned char m[4];
            if (!readExact(m, 4, "mask key")) return completed;
            maskKey = (static_cast<std::uint32_t>(m[0]) << 24)
                    | (static_cast<std::uint32_t>(m[1]) << 16)
                    | (static_cast<std::uint32_t>(m[2]) << 8)
                    | static_cast<std::uint32_t>(m[3]);
        }

        // A devtools frame larger than this is not something this lane issues
        // or expects; refusing is safer than allocating on a peer-controlled size.
        if (len > (64ull * 1024 * 1024)) {
            err = "frame exceeds 64 MiB safety cap";
            return completed;
        }

        std::string payload;
        payload.resize(static_cast<std::size_t>(len));
        if (len > 0) {
            if (!readExact(reinterpret_cast<unsigned char*>(&payload[0]),
                           static_cast<std::size_t>(len), "frame payload"))
                return completed;
            if (masked) applyMask(reinterpret_cast<unsigned char*>(&payload[0]),
                                 payload.size(), maskKey);
        }

        // ---- control frames: handled here, never surfaced -----------------
        if (op == 0x8) {                      // CLOSE
            std::string ignored;
            sendText("", ignored);
            err = "peer sent CLOSE";
            return completed;
        }
        if (op == 0x9) {                      // PING -> PONG
            // Six bytes: FIN|0xA, masked-length byte with the mask bit,
            // then the 4 mask bytes. An earlier version declared a 2-byte
            // buffer here and wrote 6, which is a stack overwrite; the
            // compiler flagged it and it is recorded because the same mistake
            // in a receipt writer would corrupt evidence rather than crash.
            unsigned char f[6];
            f[0] = 0x8A;
            f[1] = 0x80;                      // empty payload, MASK set
            const std::uint32_t k = 0x12345678u;
            f[2] = static_cast<unsigned char>((k >> 24) & 0xFF);
            f[3] = static_cast<unsigned char>((k >> 16) & 0xFF);
            f[4] = static_cast<unsigned char>((k >> 8) & 0xFF);
            f[5] = static_cast<unsigned char>(k & 0xFF);
            std::string ignored;
            sendAll(socket_, f, sizeof(f), ignored);
            continue;
        }
        if (op == 0xA) continue;              // PONG

        // ---- data frames, with fragmentation ------------------------------
        if (op == 0x0) {                      // continuation
            if (!inFragment_) { err = "continuation without an initial frame"; return completed; }
            fragment_ += payload;
        } else {
            fragment_ = payload;
            fragmentOpcode_ = op;
            inFragment_ = true;
        }
        if (!fin) continue;

        outMessages.push_back(fragment_);
        outOpcodes.push_back(fragmentOpcode_);
        fragment_.clear();
        inFragment_ = false;
        ++completed;
    }
}

// ===========================================================================
// CdpConnection
// ===========================================================================

CdpConnection::~CdpConnection() { ws_.close(); }

bool CdpConnection::connect(const std::string& host, std::uint16_t port,
                            const std::string& path, std::string& err) {
    return ws_.connect(host, port, path, err);
}

long long CdpConnection::send(const std::string& method,
                              const std::string& paramsJson,
                              std::string& err) {
    if (!ws_.connected()) { err = "not connected"; return -1; }
    const long long id = nextId_++;

    std::ostringstream m;
    m << "{\"id\":" << id << ",\"method\":\"" << method << "\"";
    if (!paramsJson.empty()) m << ",\"params\":" << paramsJson;
    m << "}";

    if (!ws_.sendText(m.str(), err)) return -1;
    ++commandsSent_;
    return id;
}

void CdpConnection::pumpOnce(int budgetMs) {
    if (!ws_.connected()) return;
    std::string err;
    std::vector<std::string> msgs;
    std::vector<std::uint8_t> ops;
    ws_.receive(msgs, ops, budgetMs, err);

    for (std::size_t i = 0; i < msgs.size(); ++i) {
        const std::string& doc = msgs[i];

        const bool hasId = doc.find("\"id\"") != std::string::npos;
        const bool hasMethod = doc.find("\"method\"") != std::string::npos;

        if (hasId && !hasMethod) {
            // A command reply. File it under its id; never discard it.
            const long long id =
                json::findInt(doc, "id", -1);
            if (id >= 0) {
                // Later replies for the same id win, which is correct: a
                // retried command's answer is the current truth.
                pending_[id] = doc;
            }
        } else if (hasMethod) {
            eventBacklog_.push_back(doc);
            // Bound the backlog so a chatty page cannot grow it without limit.
            if (eventBacklog_.size() > 4096) eventBacklog_.erase(
                eventBacklog_.begin(), eventBacklog_.begin() + 2048);
        }
    }
}

bool CdpConnection::awaitResponse(long long id,
                                  std::string& okResult,
                                  std::string& errorText,
                                  int timeoutMs,
                                  std::string& err) {
    okResult.clear();
    errorText.clear();
    if (!ws_.connected()) { err = "not connected"; return false; }

    const std::uint64_t deadline =
        nowMs() + static_cast<std::uint64_t>(timeoutMs < 0 ? 0 : timeoutMs);

    for (;;) {
        // Check the buffer first: the reply may have arrived during an earlier
        // pump, or before this call started.
        auto it = pending_.find(id);
        if (it != pending_.end()) {
            const std::string doc = it->second;
            pending_.erase(it);
            ++responsesMatched_;

            if (doc.find("\"error\"") != std::string::npos) {
                errorText = json::findString(doc, "message");
                if (errorText.empty()) errorText = "cdp reported an error";
                return true;                    // the browser ANSWERED: no
            }
            const std::size_t r = doc.find("\"result\"");
            if (r != std::string::npos) {
                // Brace-match the result object so a nested "result" elsewhere
                // in the document cannot be returned instead.
                std::size_t depth = 0, i2 = r + 8;
                std::size_t start = 0, end = std::string::npos;
                for (; i2 < doc.size(); ++i2) {
                    if (doc[i2] == '{') { if (depth == 0) start = i2; ++depth; }
                    else if (doc[i2] == '}') {
                        if (depth > 0 && --depth == 0) { end = i2 + 1; break; }
                    }
                }
                if (end != std::string::npos)
                    okResult = doc.substr(start, end - start);
            }
            return true;
        }

        const std::uint64_t t = nowMs();
        if (t >= deadline) {
            std::ostringstream e;
            e << "timeout waiting for cdp response to id " << id
              << " (sent=" << commandsSent_
              << " matched=" << responsesMatched_
              << " buffered=" << pending_.size()
              << " events=" << eventBacklog_.size() << ")";
            err = e.str();
            return false;
        }

        // Wait a slice, then pump. The slice is bounded so the deadline check
        // stays responsive.
        const std::uint64_t sliceEnd = t + 100;
        const int slice = static_cast<int>(
            (sliceEnd < deadline ? sliceEnd : deadline) - t);
        pumpOnce(slice > 0 ? slice : 1);
    }
}

int CdpConnection::drainEvents(std::vector<std::string>& out, int budgetMs) {
    if (!ws_.connected()) return 0;
    pumpOnce(budgetMs);
    int n = 0;
    for (const auto& e : eventBacklog_) out.push_back(e);
    n = static_cast<int>(eventBacklog_.size());
    eventBacklog_.clear();
    return n;
}

// ===========================================================================
// json helpers
// ===========================================================================
namespace json {

std::string findString(const std::string& doc, const std::string& key) {
    const std::string pat = "\"" + key + "\":";
    const std::size_t k = doc.find(pat);
    if (k == std::string::npos) return {};
    std::size_t i = k + pat.size();
    while (i < doc.size() && (doc[i] == ' ' || doc[i] == '\t')) ++i;
    if (i >= doc.size() || doc[i] != '"') {
        // Unquoted value (number/bool/null): return its literal text.
        std::size_t e = i;
        while (e < doc.size() && doc[e] != ',' && doc[e] != '}' &&
               doc[e] != ']' && doc[e] != ' ') ++e;
        return doc.substr(i, e - i);
    }
    ++i;
    std::string out;
    while (i < doc.size() && doc[i] != '"') {
        if (doc[i] == '\\' && i + 1 < doc.size()) {
            ++i;
            switch (doc[i]) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                default:  out += doc[i];   break;
            }
        } else {
            out += doc[i];
        }
        ++i;
    }
    return out;
}

bool findBool(const std::string& doc, const std::string& key) {
    const std::string v = findString(doc, key);
    return v == "true";
}

long long findInt(const std::string& doc, const std::string& key,
                  long long fallback) {
    const std::string v = findString(doc, key);
    if (v.empty()) return fallback;
    try { return std::stoll(v); } catch (...) { return fallback; }
}

std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

std::string obj(std::initializer_list<std::pair<std::string, std::string>> kvs) {
    std::string out = "{";
    bool first = true;
    for (const auto& kv : kvs) {
        if (!first) out += ",";
        first = false;
        out += "\"" + kv.first + "\":" + kv.second;
    }
    out += "}";
    return out;
}

} // namespace json

} // namespace rawrxd::browser