#pragma once
// ============================================================================
// SovereignSharedMemoryBridge.hpp
// High-performance shared memory bridge between IDE and Sovereign Runtime
// Replaces process-based communication with memory-mapped files
// ============================================================================

#include <windows.h>
#include <string>
#include <atomic>

namespace RawrXD {
namespace IDE {

// Shared memory layout for IPC
#pragma pack(push, 1)
struct SovereignSharedMemory {
    // Header - control signals
    std::atomic<uint32_t> magic;           // 0x52415752 ('RAWR')
    std::atomic<uint32_t> version;         // Protocol version
    std::atomic<uint32_t> sequence;        // Request sequence number
    std::atomic<uint32_t> status;          // 0=idle, 1=processing, 2=complete, 3=error
    
    // Request data
    uint32_t requestType;                  // 1=completion, 2=chat, 3=validation
    uint32_t maxTokens;
    uint32_t temperature;                  // Fixed point: divide by 100
    uint32_t flags;                        // Autonomous, validate, etc.
    char modelPath[256];
    
    // Context window (8KB for prompt)
    uint32_t promptLength;
    char prompt[8192];
    
    // Response data (16KB for completion)
    uint32_t responseLength;
    uint32_t tokensGenerated;
    uint32_t generationTimeMs;
    float confidence;
    char response[16384];
    
    // Telemetry
    uint64_t requestTimestamp;
    uint64_t responseTimestamp;
    uint32_t cacheHits;
    uint32_t cacheMisses;
};
#pragma pack(pop)

// Request types
#define REQ_TYPE_COMPLETION     1
#define REQ_TYPE_CHAT           2
#define REQ_TYPE_VALIDATION     3
#define REQ_TYPE_EMBEDDING      4

// Status codes
#define STATUS_IDLE             0
#define STATUS_PROCESSING       1
#define STATUS_COMPLETE         2
#define STATUS_ERROR            3
#define STATUS_TIMEOUT          4

// Shared memory bridge for high-performance IPC
class SovereignSharedMemoryBridge
{
public:
    SovereignSharedMemoryBridge();
    ~SovereignSharedMemoryBridge();
    
    // Attach to existing shared memory (IDE side)
    bool AttachToRuntime(const char* shmName = "RawrXD_SharedMem_Alpha");
    
    // Create shared memory (Runtime side)
    bool CreateRuntime(const char* shmName = "RawrXD_SharedMem_Alpha");
    
    // Detach from shared memory
    void Detach();
    
    // Check if bridge is connected
    bool IsConnected() const { return m_connected; }
    
    // Send completion request and wait for response
    bool RequestCompletion(
        const std::string& prompt,
        const std::string& modelPath,
        int maxTokens,
        float temperature,
        std::string& outResponse,
        float& outConfidence,
        int timeoutMs = 10000
    );
    
    // Send heartbeat to check runtime health
    bool SendHeartbeat(int timeoutMs = 1000);
    
    // Get last error message
    const char* GetLastError() const { return m_lastError; }
    
    // Get shared memory stats
    void GetStats(uint32_t& cacheHits, uint32_t& cacheMisses, uint64_t& latencyUs);
    
    // Get bridge mode for telemetry
    const char* GetBridgeMode() const { return "Zero-copy IPC"; }
    
    // Get transport latency (microseconds)
    uint64_t GetLastTransportLatencyUs() const { return m_lastTransportLatencyUs; }
    
    // Get total requests processed
    uint64_t GetTotalRequests() const { return m_totalRequests; }
    
    // Get cancelled requests
    uint64_t GetCancelledRequests() const { return m_cancelledRequests; }

private:
    uint64_t m_lastTransportLatencyUs;
    uint64_t m_totalRequests;
    uint64_t m_cancelledRequests;
    HANDLE m_hMapFile;
    HANDLE m_hRequestEvent;      // IDE signals runtime
    HANDLE m_hResponseEvent;     // Runtime signals IDE
    SovereignSharedMemory* m_shm;
    bool m_connected;
    bool m_isServer;
    char m_lastError[256];
    uint32_t m_sequence;
    
    // Event names derived from shm name
    char m_requestEventName[64];
    char m_responseEventName[64];
    
    bool CreateEvents(const char* baseName);
    bool WaitForResponse(int timeoutMs);
    void SetError(const char* fmt, ...);
};

} // namespace IDE
} // namespace RawrXD
