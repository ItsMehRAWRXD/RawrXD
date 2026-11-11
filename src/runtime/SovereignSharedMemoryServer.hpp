/*===========================================================================
 * SovereignSharedMemoryServer.hpp
 * Runtime server for local AI inference via shared memory IPC
 * 
 * Architecture:
 *   IDE (Client) <---> Shared Memory <---> Runtime Server <---> Deep2
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <cstdint>
#include <atomic>
#include <functional>

namespace RawrXD {
namespace Runtime {

/*===========================================================================
 * Shared Memory Protocol
 * Zero-copy request/response structure
 *=========================================================================*/

#pragma pack(push, 1)

struct SovereignRequest {
    uint64_t requestId;         // Monotonic sequence
    uint64_t timestamp;       // Request start time
    uint32_t version;         // Protocol version
    uint32_t promptLength;    // Actual prompt bytes
    uint32_t maxTokens;       // Generation limit
    float temperature;          // Sampling temperature
    char prompt[8192];        // Input text
    char context[4096];       // Conversation context
};

struct SovereignResponse {
    uint64_t requestId;         // Matches request
    uint64_t timestamp;       // Response time
    uint32_t tokenCount;      // Generated tokens
    uint32_t status;          // 0=success, 1=error
    float confidence;         // Average token probability
    uint32_t latencyMs;       // Generation time
    float tps;                // Tokens per second
    char text[16384];         // Generated completion
    char errorMessage[256];   // Error details if status != 0
    
    // Execution provenance - distinguishes synthetic vs real model execution
    char modelName[128];      // Model identifier (e.g., "phi-3-mini-Q4_K_M")
    char executionMode[32];   // "synthetic" or "gguf-backed"
    char backend[32];         // Backend type (e.g., "Sovereign CPU AVX512")
    uint64_t runtimeVersion;  // Runtime version for compatibility
    uint32_t flags;           // Bit flags: bit0=synthetic, bit1=quantized, etc.
    
    // Atomic sequence counter for detecting torn reads
    // Incremented atomically before responseReady is set
    std::atomic<uint32_t> sequenceNumber;
};

struct SovereignSharedBlock {
    // Request section (written by IDE, read by runtime)
    alignas(64) SovereignRequest request;
    std::atomic<uint32_t> requestReady;  // 0=idle, 1=pending
    
    // Response section (written by runtime, read by IDE)
    alignas(64) SovereignResponse response;
    std::atomic<uint32_t> responseReady; // 0=idle, 1=complete
    
    // Telemetry counters
    alignas(64) struct {
        uint64_t requestsReceived;
        uint64_t responsesSent;
        uint64_t errors;
        uint64_t totalTokens;
        uint64_t totalLatencyMs;
    } stats;
};

#pragma pack(pop)

/*===========================================================================
 * Runtime Server Interface
 *=========================================================================*/

class SovereignSharedMemoryServer {
public:
    using TokenCallback = std::function<void(const char* token, uint32_t index)>;
    using CompletionCallback = std::function<void(const SovereignResponse& response)>;

    SovereignSharedMemoryServer();
    ~SovereignSharedMemoryServer();

    // Lifecycle
    bool Initialize(const wchar_t* sharedMemoryName = L"RawrXD_SharedMem_Alpha");
    void Shutdown();
    bool IsRunning() const { return m_running; }

    // Worker control
    bool StartWorker();
    void StopWorker();
    bool IsWorkerActive() const;

    // Configuration
    void SetTokenCallback(TokenCallback callback);
    void SetCompletionCallback(CompletionCallback callback);
    void SetMaxTokens(uint32_t maxTokens) { m_maxTokens = maxTokens; }
    void SetTemperature(float temp) { m_temperature = temp; }

    // Statistics
    struct Telemetry {
        uint64_t requestsReceived;
        uint64_t responsesSent;
        uint64_t errors;
        uint64_t totalTokens;
        double avgLatencyMs;
        double avgTps;
        uint32_t activeRequests;
    };
    Telemetry GetTelemetry() const;

    // Manual request processing (for testing)
    bool ProcessRequest(const SovereignRequest& request, SovereignResponse& response);

private:
    // Shared memory
    HANDLE m_hSharedMemory;
    HANDLE m_hRequestEvent;
    HANDLE m_hResponseEvent;
    SovereignSharedBlock* m_pSharedBlock;
    
    // Worker thread
    HANDLE m_hWorkerThread;
    std::atomic<bool> m_running;
    std::atomic<bool> m_workerActive;
    
    // Configuration
    uint32_t m_maxTokens;
    float m_temperature;
    TokenCallback m_tokenCallback;
    CompletionCallback m_completionCallback;
    
    // Worker thread function
    static DWORD WINAPI WorkerThreadProc(LPVOID param);
    void WorkerLoop();
    
    // Real inference integration - uses InferenceEngine
    bool CallDeep2Inference(const SovereignRequest& request, SovereignResponse& response);
    
    // Cleanup
    void CleanupSharedMemory();
};

} // namespace Runtime
} // namespace RawrXD

// C-compatible exports for runtime executable
extern "C" {
    __declspec(dllexport) void* SovereignRuntime_Create();
    __declspec(dllexport) void SovereignRuntime_Destroy(void* server);
    __declspec(dllexport) int SovereignRuntime_Initialize(void* server, const wchar_t* name);
    __declspec(dllexport) int SovereignRuntime_Start(void* server);
    __declspec(dllexport) void SovereignRuntime_Stop(void* server);
    __declspec(dllexport) int SovereignRuntime_IsRunning(void* server);
}
