// =============================================================================
// sovereign_ide_ipc_bridge.cpp
// Named Pipe IPC Bridge between RawrXD IDE and Sovereign Engine
//
// Phase 15: IDE Integration - Communication Layer
// Protocol: Binary message format with JSON payload
// Transport: Windows Named Pipes (\\.\pipe\SovereignIPC)
// =============================================================================

#include "sovereign_ide_ipc_bridge.h"
#include <windows.h>
#include <string>
#include <cstdio>
#include <json/json.h>

// =============================================================================
// Constants
// =============================================================================

#define SOVEREIGN_PIPE_NAME     "\\\\.\\pipe\\SovereignIPC"
#define SOVEREIGN_PIPE_BUFFER   (1024 * 1024)  // 1MB buffer
#define SOVEREIGN_MAX_MESSAGE   (512 * 1024)   // 512KB max message
#define SOVEREIGN_TIMEOUT_MS    5000           // 5 second timeout

// =============================================================================
// Message Types
// =============================================================================

enum class IPCMessageType : uint32_t {
    // IDE → Sovereign
    COMPLETION_REQUEST      = 0x01,  // Request code completion
    CANCEL_REQUEST          = 0x02,  // Cancel ongoing generation
    PREFETCH_LAYER          = 0x03,  // Prefetch specific layer
    GET_STATUS              = 0x04,  // Get engine status
    
    // Sovereign → IDE
    COMPLETION_TOKEN        = 0x10,  // Single token from stream
    COMPLETION_COMPLETE     = 0x11,  // Generation finished
    COMPLETION_CANCELLED    = 0x12,  // Generation was cancelled
    ERROR_RESPONSE          = 0x13,  // Error occurred
    STATUS_RESPONSE         = 0x14,  // Status information
};

#pragma pack(push, 1)
struct IPCMessageHeader {
    uint32_t magic;           // 'SOVE' = 0x534F5645
    uint32_t version;         // Protocol version (1)
    IPCMessageType type;      // Message type
    uint32_t payload_size;    // Size of JSON payload
    uint64_t timestamp;       // Unix timestamp (microseconds)
    uint32_t request_id;      // Unique request ID
};
#pragma pack(pop)

#define IPC_MAGIC   0x534F5645  // 'SOVE'
#define IPC_VERSION 1

// =============================================================================
// Internal State
// =============================================================================

struct IPCBridgeState {
    HANDLE hPipe;
    bool isConnected;
    bool isServer;
    uint32_t nextRequestId;
    
    // Callbacks
    CompletionTokenCallback onToken;
    CompletionCompleteCallback onComplete;
    ErrorCallback onError;
};

static IPCBridgeState g_ipc_state = {};

// =============================================================================
// Helper Functions
// =============================================================================

static uint64_t get_timestamp_us() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // Convert from 100-nanosecond intervals to microseconds
    // Subtract Windows epoch (1601) to Unix epoch (1970)
    return (uli.QuadPart / 10) - 11644473600000000ULL;
}

static bool send_message_internal(const IPCMessageHeader* header, const char* payload) {
    if (!g_ipc_state.isConnected || g_ipc_state.hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD bytesWritten;
    BOOL success;
    
    // Send header
    success = WriteFile(
        g_ipc_state.hPipe,
        header,
        sizeof(IPCMessageHeader),
        &bytesWritten,
        nullptr
    );
    
    if (!success || bytesWritten != sizeof(IPCMessageHeader)) {
        return false;
    }
    
    // Send payload if present
    if (payload && header->payload_size > 0) {
        success = WriteFile(
            g_ipc_state.hPipe,
            payload,
            header->payload_size,
            &bytesWritten,
            nullptr
        );
        
        if (!success || bytesWritten != header->payload_size) {
            return false;
        }
    }
    
    // Flush to ensure immediate delivery
    FlushFileBuffers(g_ipc_state.hPipe);
    
    return true;
}

static bool receive_message_internal(IPCMessageHeader* header, std::string& payload) {
    if (!g_ipc_state.isConnected || g_ipc_state.hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD bytesRead;
    BOOL success;
    
    // Read header
    success = ReadFile(
        g_ipc_state.hPipe,
        header,
        sizeof(IPCMessageHeader),
        &bytesRead,
        nullptr
    );
    
    if (!success || bytesRead != sizeof(IPCMessageHeader)) {
        return false;
    }
    
    // Validate header
    if (header->magic != IPC_MAGIC || header->version != IPC_VERSION) {
        return false;
    }
    
    // Read payload if present
    if (header->payload_size > 0) {
        if (header->payload_size > SOVEREIGN_MAX_MESSAGE) {
            return false;  // Payload too large
        }
        
        payload.resize(header->payload_size);
        
        success = ReadFile(
            g_ipc_state.hPipe,
            &payload[0],
            header->payload_size,
            &bytesRead,
            nullptr
        );
        
        if (!success || bytesRead != header->payload_size) {
            return false;
        }
    }
    
    return true;
}

// =============================================================================
// Public API
// =============================================================================

extern "C" {

__declspec(dllexport) bool Sovereign_IPC_Init(bool asServer) {
    g_ipc_state.isServer = asServer;
    g_ipc_state.nextRequestId = 1;
    
    if (asServer) {
        // Server: Create named pipe
        g_ipc_state.hPipe = CreateNamedPipeA(
            SOVEREIGN_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            SOVEREIGN_PIPE_BUFFER,
            SOVEREIGN_PIPE_BUFFER,
            SOVEREIGN_TIMEOUT_MS,
            nullptr
        );
        
        if (g_ipc_state.hPipe == INVALID_HANDLE_VALUE) {
            printf("[Sovereign_IPC] Failed to create pipe: %lu\n", GetLastError());
            return false;
        }
        
        printf("[Sovereign_IPC] Server pipe created: %s\n", SOVEREIGN_PIPE_NAME);
        
        // Wait for client connection
        printf("[Sovereign_IPC] Waiting for client connection...\n");
        BOOL connected = ConnectNamedPipe(g_ipc_state.hPipe, nullptr);
        
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            printf("[Sovereign_IPC] Failed to connect: %lu\n", GetLastError());
            CloseHandle(g_ipc_state.hPipe);
            return false;
        }
        
        g_ipc_state.isConnected = true;
        printf("[Sovereign_IPC] Client connected\n");
        
    } else {
        // Client: Connect to existing pipe
        g_ipc_state.hPipe = CreateFileA(
            SOVEREIGN_PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        
        if (g_ipc_state.hPipe == INVALID_HANDLE_VALUE) {
            printf("[Sovereign_IPC] Failed to connect to pipe: %lu\n", GetLastError());
            return false;
        }
        
        // Set message mode
        DWORD mode = PIPE_READMODE_MESSAGE;
        BOOL success = SetNamedPipeHandleState(
            g_ipc_state.hPipe,
            &mode,
            nullptr,
            nullptr
        );
        
        if (!success) {
            printf("[Sovereign_IPC] Failed to set pipe mode: %lu\n", GetLastError());
            CloseHandle(g_ipc_state.hPipe);
            return false;
        }
        
        g_ipc_state.isConnected = true;
        printf("[Sovereign_IPC] Connected to server\n");
    }
    
    return true;
}

__declspec(dllexport) void Sovereign_IPC_Shutdown() {
    if (g_ipc_state.hPipe != INVALID_HANDLE_VALUE) {
        if (g_ipc_state.isServer && g_ipc_state.isConnected) {
            DisconnectNamedPipe(g_ipc_state.hPipe);
        }
        CloseHandle(g_ipc_state.hPipe);
        g_ipc_state.hPipe = INVALID_HANDLE_VALUE;
    }
    
    g_ipc_state.isConnected = false;
    printf("[Sovereign_IPC] Shutdown complete\n");
}

__declspec(dllexport) bool Sovereign_IPC_SendCompletionRequest(
    const char* file_path,
    const char* content,
    uint32_t cursor_line,
    uint32_t cursor_column,
    const char* language
) {
    if (!g_ipc_state.isConnected) return false;
    
    // Build JSON payload
    Json::Value root;
    root["file_path"] = file_path;
    root["content"] = content;
    root["cursor_line"] = cursor_line;
    root["cursor_column"] = cursor_column;
    root["language"] = language;
    root["max_tokens"] = 256;  // Limit suggestion length
    root["temperature"] = 0.7;
    
    Json::StreamWriterBuilder builder;
    std::string payload = Json::writeString(builder, root);
    
    // Build header
    IPCMessageHeader header = {};
    header.magic = IPC_MAGIC;
    header.version = IPC_VERSION;
    header.type = IPCMessageType::COMPLETION_REQUEST;
    header.payload_size = static_cast<uint32_t>(payload.size());
    header.timestamp = get_timestamp_us();
    header.request_id = g_ipc_state.nextRequestId++;
    
    return send_message_internal(&header, payload.c_str());
}

__declspec(dllexport) bool Sovereign_IPC_SendCancelRequest() {
    if (!g_ipc_state.isConnected) return false;
    
    IPCMessageHeader header = {};
    header.magic = IPC_MAGIC;
    header.version = IPC_VERSION;
    header.type = IPCMessageType::CANCEL_REQUEST;
    header.payload_size = 0;
    header.timestamp = get_timestamp_us();
    header.request_id = g_ipc_state.nextRequestId++;
    
    return send_message_internal(&header, nullptr);
}

__declspec(dllexport) void Sovereign_IPC_SetCallbacks(
    CompletionTokenCallback onToken,
    CompletionCompleteCallback onComplete,
    ErrorCallback onError
) {
    g_ipc_state.onToken = onToken;
    g_ipc_state.onComplete = onComplete;
    g_ipc_state.onError = onError;
}

__declspec(dllexport) void Sovereign_IPC_Poll() {
    if (!g_ipc_state.isConnected) return;
    
    // Check if data available (non-blocking)
    DWORD bytesAvailable;
    BOOL success = PeekNamedPipe(
        g_ipc_state.hPipe,
        nullptr,
        0,
        nullptr,
        &bytesAvailable,
        nullptr
    );
    
    if (!success || bytesAvailable == 0) {
        return;  // No data available
    }
    
    // Receive message
    IPCMessageHeader header;
    std::string payload;
    
    if (!receive_message_internal(&header, payload)) {
        if (g_ipc_state.onError) {
            g_ipc_state.onError("Failed to receive message");
        }
        return;
    }
    
    // Process based on message type
    switch (header.type) {
        case IPCMessageType::COMPLETION_TOKEN: {
            if (g_ipc_state.onToken) {
                // Parse token from payload
                Json::Value root;
                Json::CharReaderBuilder builder;
                std::string errors;
                
                std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
                if (reader->parse(payload.c_str(), payload.c_str() + payload.size(), &root, &errors)) {
                    const char* token = root["token"].asCString();
                    bool isFinal = root["is_final"].asBool();
                    g_ipc_state.onToken(token, isFinal);
                }
            }
            break;
        }
        
        case IPCMessageType::COMPLETION_COMPLETE: {
            if (g_ipc_state.onComplete) {
                Json::Value root;
                Json::CharReaderBuilder builder;
                std::string errors;
                
                std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
                if (reader->parse(payload.c_str(), payload.c_str() + payload.size(), &root, &errors)) {
                    uint32_t totalTokens = root["total_tokens"].asUInt();
                    float totalTimeMs = root["total_time_ms"].asFloat();
                    g_ipc_state.onComplete(totalTokens, totalTimeMs);
                }
            }
            break;
        }
        
        case IPCMessageType::ERROR_RESPONSE: {
            if (g_ipc_state.onError) {
                Json::Value root;
                Json::CharReaderBuilder builder;
                std::string errors;
                
                std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
                if (reader->parse(payload.c_str(), payload.c_str() + payload.size(), &root, &errors)) {
                    const char* errorMsg = root["error"].asCString();
                    g_ipc_state.onError(errorMsg);
                }
            }
            break;
        }
        
        default:
            break;
    }
}

__declspec(dllexport) bool Sovereign_IPC_IsConnected() {
    return g_ipc_state.isConnected;
}

} // extern "C"

// =============================================================================
// Server-Side Response Helpers
// =============================================================================

bool send_completion_token(const char* token, bool isFinal, uint32_t requestId) {
    Json::Value root;
    root["token"] = token;
    root["is_final"] = isFinal;
    
    Json::StreamWriterBuilder builder;
    std::string payload = Json::writeString(builder, root);
    
    IPCMessageHeader header = {};
    header.magic = IPC_MAGIC;
    header.version = IPC_VERSION;
    header.type = IPCMessageType::COMPLETION_TOKEN;
    header.payload_size = static_cast<uint32_t>(payload.size());
    header.timestamp = get_timestamp_us();
    header.request_id = requestId;
    
    return send_message_internal(&header, payload.c_str());
}

bool send_completion_complete(uint32_t totalTokens, float totalTimeMs, uint32_t requestId) {
    Json::Value root;
    root["total_tokens"] = totalTokens;
    root["total_time_ms"] = totalTimeMs;
    
    Json::StreamWriterBuilder builder;
    std::string payload = Json::writeString(builder, root);
    
    IPCMessageHeader header = {};
    header.magic = IPC_MAGIC;
    header.version = IPC_VERSION;
    header.type = IPCMessageType::COMPLETION_COMPLETE;
    header.payload_size = static_cast<uint32_t>(payload.size());
    header.timestamp = get_timestamp_us();
    header.request_id = requestId;
    
    return send_message_internal(&header, payload.c_str());
}
