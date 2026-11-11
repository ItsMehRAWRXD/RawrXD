// ============================================================================
// Omega1 IPC Protocol v2.0 - Zero-Copy Binary Protocol for IDE Integration
// Length-prefixed structs, no JSON parsing in hot path
// ============================================================================

#pragma once
#include <windows.h>
#include <cstdint>

// Pipe and SHM names
#define OMEGA1_PIPE_NAME        L"\\\\.\\pipe\\RawrXD_Omega1_v2"
#define OMEGA1_SHM_NAME         L"Global\\OMEGA1_SHM_RING_v2"
#define OMEGA1_EVENT_NAME       L"Global\\OMEGA1_DATA_READY"

// Protocol version
constexpr uint32_t OMEGA1_PROTOCOL_VERSION = 0x00020000; // v2.0

// Message types (control channel)
enum class Omega1MsgType : uint32_t {
    // Client -> Server
    REQUEST_COMPLETION = 0x1001,
    CANCEL_GENERATION  = 0x1002,
    LOAD_MODEL         = 0x1003,
    UNLOAD_MODEL       = 0x1004,
    GET_STATUS         = 0x1005,
    SET_PARAMETERS     = 0x1006,
    
    // Server -> Client
    COMPLETION_TOKEN   = 0x2001,
    COMPLETION_DONE    = 0x2002,
    STATUS_RESPONSE    = 0x2003,
    ERROR_RESPONSE     = 0x2004,
    TELEMETRY_UPDATE   = 0x2005,
};

// Status codes
enum class Omega1Status : uint32_t {
    OK = 0,
    ERROR_NO_MODEL = 1,
    ERROR_GPU_BUSY = 2,
    ERROR_OUT_OF_MEMORY = 3,
    ERROR_INVALID_REQUEST = 4,
    ERROR_PIPE_DISCONNECTED = 5,
};

// GPU info struct
#pragma pack(push, 1)
struct Omega1GPUInfo {
    wchar_t name[128];
    uint64_t vramTotal;
    uint64_t vramUsed;
    uint32_t computeUnits;
    float tpsCurrent;
    float temperature;
    float powerDraw;
    bool isPrimary;
};

// Request header (control channel)
struct Omega1RequestHeader {
    uint32_t magic;           // 'OM1\0' = 0x4F4D3100
    uint32_t version;
    Omega1MsgType type;
    uint32_t requestId;
    uint32_t payloadSize;
};

// Completion request payload
struct Omega1CompletionRequest {
    uint32_t maxTokens;
    float temperature;
    float topP;
    uint32_t contextLinesBefore;
    uint32_t contextLinesAfter;
    wchar_t systemPrompt[512];
    // Context follows (variable length)
};

// Token response (control channel for metadata, actual tokens in SHM)
struct Omega1TokenResponse {
    uint32_t requestId;
    uint32_t tokenIndex;
    uint32_t tokenLength;     // Length in SHM
    bool isFinal;
    Omega1Status status;
};

// Status response
struct Omega1StatusResponse {
    Omega1Status status;
    uint32_t activeRequests;
    uint32_t gpuCount;
    Omega1GPUInfo gpus[4];      // Up to 4 GPUs
    wchar_t modelName[256];
    uint32_t contextLength;
    float avgPromptTPS;
    float avgEvalTPS;
};

// Error response
struct Omega1ErrorResponse {
    Omega1Status code;
    wchar_t message[512];
};

// SHM Ring Buffer Layout
// Total size: 1MB (configurable)
constexpr size_t OMEGA1_SHM_SIZE = 1024 * 1024;
constexpr size_t OMEGA1_RING_SIZE = 1024 * 1024 - 256; // Reserve header

struct Omega1SHMHeader {
    uint32_t magic;           // 'SHM\0'
    uint32_t version;
    volatile uint32_t writeIndex;
    volatile uint32_t readIndex;
    volatile uint32_t sequenceNumber;
    HANDLE hDataReady;        // Event handle (duplicated)
    uint8_t reserved[224];    // Pad to 256 bytes
};

struct Omega1RingEntry {
    uint32_t sequence;
    uint32_t type;            // 0=token, 1=telemetry, 2=control
    uint32_t length;
    uint32_t requestId;
    // Data follows immediately
};
#pragma pack(pop)

// Magic values
constexpr uint32_t OMEGA1_MAGIC_REQUEST = 0x4F4D3100; // 'OM1\0'
constexpr uint32_t OMEGA1_MAGIC_SHM = 0x53484D00;     // 'SHM\0'

// Helper to calculate ring buffer entry size
inline size_t Omega1RingEntrySize(size_t dataLen) {
    return sizeof(Omega1RingEntry) + dataLen;
}
