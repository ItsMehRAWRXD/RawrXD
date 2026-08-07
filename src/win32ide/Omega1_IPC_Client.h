// ============================================================================
// Omega1 IPC Client - Win32IDE Integration
// Non-blocking client for ghost text streaming
// ============================================================================

#pragma once
#include "Omega1_IPC_Protocol.h"
#include <windows.h>
#include <string>
#include <functional>
#include <atomic>

namespace RawrXD {
namespace Omega1 {

// Callback types
using TokenCallback = std::function<void(const wchar_t* token, size_t len, bool isFinal)>;
using TelemetryCallback = std::function<void(const Omega1StatusResponse& status)>;
using ErrorCallback = std::function<void(Omega1Status code, const wchar_t* message)>;

// IPC Client state
class IPCClient {
public:
    IPCClient();
    ~IPCClient();

    // Connection management
    bool Connect();
    void Disconnect();
    bool IsConnected() const { return m_connected; }

    // Request methods (async)
    bool RequestCompletion(const wchar_t* context, 
                          const wchar_t* systemPrompt,
                          uint32_t maxTokens = 256,
                          float temperature = 0.7f);
    bool CancelGeneration();
    bool LoadModel(const wchar_t* modelPath);
    bool UnloadModel();
    bool GetStatus();
    bool SetParameters(float temperature, float topP);

    // Callback registration
    void SetTokenCallback(TokenCallback cb) { m_tokenCallback = cb; }
    void SetTelemetryCallback(TelemetryCallback cb) { m_telemetryCallback = cb; }
    void SetErrorCallback(ErrorCallback cb) { m_errorCallback = cb; }

    // Poll for responses (call from main thread periodically)
    void Poll();

    // Blocking wait for completion (for sync operations)
    bool WaitForCompletion(DWORD timeoutMs = 30000);

    // Current telemetry (cached from last update)
    const Omega1StatusResponse& GetCachedStatus() const { return m_cachedStatus; }

private:
    // Pipe handles
    HANDLE m_hPipe = INVALID_HANDLE_VALUE;
    HANDLE m_hSHM = nullptr;
    void* m_pSHM = nullptr;
    Omega1SHMHeader* m_pSHMHeader = nullptr;
    uint8_t* m_pRingBuffer = nullptr;
    HANDLE m_hDataReady = nullptr;

    // Connection state
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_running{false};
    uint32_t m_nextRequestId = 1;
    uint32_t m_currentRequestId = 0;

    // Callbacks
    TokenCallback m_tokenCallback;
    TelemetryCallback m_telemetryCallback;
    ErrorCallback m_errorCallback;

    // Cached status
    Omega1StatusResponse m_cachedStatus{};

    // Worker thread
    HANDLE m_hWorkerThread = nullptr;
    static DWORD WINAPI WorkerThreadProc(LPVOID param);
    void WorkerThread();

    // Internal methods
    bool SendRequest(Omega1MsgType type, const void* payload, size_t payloadSize);
    bool SendRequest(Omega1MsgType type); // No payload
    void ProcessResponse(const Omega1RequestHeader& header, const uint8_t* payload);
    void ProcessRingBuffer();
    bool ConnectPipe();
    bool ConnectSHM();
};

// Ghost text integration helper
class GhostTextIntegration {
public:
    GhostTextIntegration(IPCClient& client);
    
    // Trigger ghost text from editor
    void TriggerCompletion(HWND hEditor);
    
    // Cancel current generation
    void Cancel();
    
    // Check if generation is active
    bool IsGenerating() const { return m_generating; }
    
    // Get accumulated ghost text
    std::wstring GetGhostText() const { return m_accumulatedText; }
    
    // Clear ghost text
    void Clear();

private:
    IPCClient& m_client;
    std::wstring m_accumulatedText;
    std::atomic<bool> m_generating{false};
    uint32_t m_currentRequestId = 0;

    void OnToken(const wchar_t* token, size_t len, bool isFinal);
    void OnError(Omega1Status code, const wchar_t* message);
};

} // namespace Omega1
} // namespace RawrXD
