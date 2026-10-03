// ============================================================================
// CdpTransport.hpp
//
// RAWRXD_BROWSER_AUTHORITY_001 -- real Chrome DevTools Protocol transport.
//
// ZERO-G FINDING THAT MOTIVATED THIS FILE (measured, not assumed):
//
//     Edge v154.0.4258.53 present at
//         C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
//     src/collab/websocket_hub.cpp        = 1 line   (stub)
//     no CDP client anywhere in the tree
//     no RFC6455 implementation anywhere in the tree
//
// So there was no transport to reuse. A browser authority that cannot reach a
// browser is a browser-shaped document. This file is the transport that makes
// the difference, and it is deliberately the ONLY place in the browser lane
// that speaks a wire protocol.
//
// ---------------------------------------------------------------------------
// THE LAW
// ---------------------------------------------------------------------------
//   BROWSER_ACTION_ASSERTED = 0
//   BROWSER_ACTION_OBSERVED = 1
//
// A CDP command that was SENT is not an action that happened. This transport
// therefore reports only what it can prove:
//
//   * send() returning true means the frame reached the socket
//   * a completed CDP response with a resolved `id` means the browser
//     acknowledged that command
//   * anything else is UNOBSERVED
//
// No function here reports a page state, an element, or a navigation success.
// Those are produced by BrowserAction and BrowserObservation, from responses
// the browser actually returned.
// ============================================================================

#ifndef RAWRXD_BROWSER_CDP_TRANSPORT_HPP
#define RAWRXD_BROWSER_CDP_TRANSPORT_HPP

#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <vector>

namespace rawrxd::browser {

// ---------------------------------------------------------------------------
// Minimal RFC6455 client.
//
// Scope is deliberately narrow and stated, because a "WebSocket client" that
// silently omits continuation frames or 64-bit lengths is a client that will
// work against small devtools payloads and fail against real ones:
//
//   supported : text frames, binary frames, ping/pong, close
//   supported : client-side masking (REQUIRED by RFC 6455 5.3)
//   supported : 7-bit, 16-bit and 64-bit payload lengths
//   supported : continuation frames (fragmented messages)
//   NOT supported: permessage-deflate (never negotiated; we send no extensions)
//   NOT supported: TLS (devtools on loopback is plaintext, which is why the
//                  endpoint is refused unless it is a loopback address)
//
// Refusing a non-loopback endpoint is a security decision, not a limitation:
// devtools carries the full authority of the browser session, so an unauthenticated
// remote devtools socket is equivalent to handing over the profile.
// ---------------------------------------------------------------------------
class WebSocketClient {
public:
    WebSocketClient() = default;
    ~WebSocketClient();
    WebSocketClient(const WebSocketClient&) = delete;
    WebSocketClient& operator=(const WebSocketClient&) = delete;

    // Connects to ws://host:port/path and performs the RFC 6455 handshake.
    bool connect(const std::string& host, std::uint16_t port,
                 const std::string& path, std::string& err);

    // Sends one text message. Frames it, masks it, writes it fully.
    bool sendText(const std::string& payload, std::string& err);

    // Reads messages until `deadlineMs` elapses. `opcodes` collects the opcode
    // of each complete message so the caller can distinguish text from close.
    // Returns the number of complete messages appended to `outMessages`.
    //
    // Control frames are handled here and never surface as messages:
    //   PING -> answered with PONG
    //   CLOSE -> echoed, and the loop stops
    int receive(std::vector<std::string>& outMessages,
                std::vector<std::uint8_t>& outOpcodes,
                int deadlineMs, std::string& err);

    bool handshakeComplete() const noexcept { return handshakeComplete_; }
    bool connected() const noexcept { return socket_ != INVALID_SOCKET; }
    void close();

private:
    static constexpr std::uint64_t INVALID_SOCKET = ~0ull;
    std::uint64_t socket_ = INVALID_SOCKET;
    bool handshakeComplete_ = false;
    std::string fragment_;      // accumulated continuation payload
    std::uint8_t fragmentOpcode_ = 0;
    bool inFragment_ = false;
};

// ---------------------------------------------------------------------------
// One CDP connection: request/response correlation by monotonic id.
//
// CDP multiplexes commands over the socket and replies with {"id":N,"result":...}
// or {"id":N,"error":...}. Events arrive interleaved with no id and are
// returned by receiveEvent() rather than being mistaken for command replies.
// ---------------------------------------------------------------------------
class CdpConnection {
public:
    CdpConnection() = default;
    ~CdpConnection();
    CdpConnection(const CdpConnection&) = delete;
    CdpConnection& operator=(const CdpConnection&) = delete;

    bool connect(const std::string& host, std::uint16_t port,
                 const std::string& path, std::string& err);

    // Sends a CDP command. Returns the assigned id, or -1 on failure.
    // Sending is not success: only awaitResponse() proves the browser acted.
    long long send(const std::string& method,
                   const std::string& paramsJson,
                   std::string& err);

    // Waits for the reply to `id`. Sets `okResult` on success and `errorText`
    // on a protocol-level error. Returns false on timeout or transport error,
    // and in both cases says which, because "did not answer" and "answered no"
    // are different facts and only one of them is a browser decision.
    bool awaitResponse(long long id,
                       std::string& okResult,
                       std::string& errorText,
                       int timeoutMs,
                       std::string& err);

    // Drains any CDP events (no id) into `out`, so the caller can observe real
    // page lifecycle rather than assuming one.
    int drainEvents(std::vector<std::string>& out, int budgetMs);

    bool connected() const noexcept { return ws_.connected(); }
    void close() { ws_.close(); }

    long long commandsSent() const noexcept { return commandsSent_; }
    long long responsesMatched() const noexcept { return responsesMatched_; }

private:
    WebSocketClient ws_;
    long long nextId_ = 1;
    long long commandsSent_ = 0;
    long long responsesMatched_ = 0;

    // Replies that arrived while awaiting a DIFFERENT id.
    //
    // This buffer is not an optimisation. CDP multiplexes replies over one
    // socket, and a command can be answered after its caller already timed out
    // or moved on. The first version skipped any message whose id did not
    // match, which DESTROYED that reply: awaiting its id later could never
    // succeed, and the connection desynchronised. That is why
    // Input.dispatchMouseEvent looked unanswered while the browser had replied.
    std::map<long long, std::string> pending_;
    std::vector<std::string> eventBacklog_;

    // Reads whatever frames are available within `budgetMs` and files them.
    void pumpOnce(int budgetMs);
};

// ---------------------------------------------------------------------------
// Extraction helpers.
//
// JSON is parsed by scanning for the fields this lane needs. That is a real
// limitation and is recorded rather than hidden: a nested "result" object can
// contain the same key names, so a scanner can in principle pick the wrong one.
// Every use below therefore prefers the FIRST match at depth 1 and the callers
// cross-check the semantic field they actually need.
// ---------------------------------------------------------------------------
namespace json {

// Returns the raw text of the first occurrence of "key": anywhere in `doc`,
// or "" when absent.
std::string findString(const std::string& doc, const std::string& key);

// Returns true when the first occurrence of "key": is the literal `true`.
bool findBool(const std::string& doc, const std::string& key);

// Returns the first integer value for "key":, or `fallback`.
long long findInt(const std::string& doc, const std::string& key,
                  long long fallback);

// Escapes a string for embedding as a JSON string literal (without quotes).
std::string escape(const std::string& s);

// Minimal object builder: {"k":<v>} with string/int/bool values.
std::string obj(std::initializer_list<std::pair<std::string, std::string>> kvs);

} // namespace json

} // namespace rawrxd::browser

#endif // RAWRXD_BROWSER_CDP_TRANSPORT_HPP