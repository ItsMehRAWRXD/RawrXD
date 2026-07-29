// Omega1IPCClient.h
// RawrXD Win32IDE → OMEGA-1 Engine IPC Client
// Production-grade, async I/O, zero-copy where possible

#pragma once
#include "omega1_ipc_protocol.h"
#include <string>
#include <vector>
#include <functional>

// ─── Callback Types ───
using StreamTokenCallback = std::function<void(const O1StreamTokenResponse&, const std::string&)>;
using StatusUpdateCallback = std::function<void(const O1StatusTelemetry&, const std::string&)>;
using ErrorCallback = std::function<void(O1ErrorCode, const std::string&)>;

// ─── IPC Client Class ───
class Omega1IPCClient {
public:
    Omega1IPCClient() noexcept;
    ~Omega1IPCClient();

    // No copy/move (handles are not transferable)
    Omega1IPCClient(const Omega1IPCClient&) = delete;
    Omega1IPCClient& operator=(const Omega1IPCClient&) = delete;
    Omega1IPCClient(Omega1IPCClient&&) = delete;
    Omega1IPCClient& operator=(Omega1IPCClient&&) = delete;

    // ─── Connection ───
    bool Connect(const wchar_t* pipeName = L"\\\\.\\pipe\\RawrXD_Omega1_v2", 
                 uint32_t timeoutMs = 5000);
    void Disconnect() noexcept;
    bool IsConnected() const noexcept { return m_connected; }

    // ─── Synchronous Requests ───
    bool Ping(uint64_t& outLatencyUs);
    
    bool RequestCompletion(const O1CompletionRequest& request,
                          const std::string& context,
                          O1GhostTextResponse& outResponse,
                          std::string& outText);
    
    bool SwitchModel(const O1ModelSwitchRequest& request);
    bool QueryStatus(O1StatusTelemetry& outStatus, std::string& outModelName);

    // ─── Streaming ───
    bool StartStream(const O1StreamRequest& request, const std::string& context);
    bool CancelStream();
    bool IsStreaming() const noexcept { return m_streaming; }
    
    // Non-blocking token receive for streaming
    bool TryReceiveStreamToken(O1StreamTokenResponse& outToken, 
                               std::string& outText,
                               uint32_t timeoutMs = 100);

    // ─── Callbacks ───
    void SetStreamTokenCallback(StreamTokenCallback cb) { m_onToken = cb; }
    void SetStatusCallback(StatusUpdateCallback cb) { m_onStatus = cb; }
    void SetErrorCallback(ErrorCallback cb) { m_onError = cb; }

private:
    void Cleanup() noexcept;
    bool SendMessage(const O1MessageHeader* header, const void* payload, size_t payloadLen);
    bool ReceiveMessage(O1MessageHeader& outHeader, std::vector<uint8_t>& outPayload);

    HANDLE m_hPipe;
    HANDLE m_hEventRead;
    HANDLE m_hEventWrite;
    OVERLAPPED m_overlappedRead;
    OVERLAPPED m_overlappedWrite;
    
    uint32_t m_requestId;
    bool m_connected;
    bool m_streaming;

    // Callbacks
    StreamTokenCallback m_onToken;
    StatusUpdateCallback m_onStatus;
    ErrorCallback m_onError;
};
