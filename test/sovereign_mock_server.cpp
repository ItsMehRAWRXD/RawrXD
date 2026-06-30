// =============================================================================
// sovereign_mock_server.cpp
// Mock Sovereign Engine for TC15_001 Testing
//
// Simulates the Sovereign Engine IPC responses for test validation
// This allows testing the test framework without the full engine
// =============================================================================

#include <windows.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <time>
#include <json/json.h>

#define PIPE_NAME "\\\\.\\pipe\\SovereignIPC"
#define BUFFER_SIZE 4096

// Simulated latency profiles (in milliseconds)
struct LatencyProfile {
    int firstTokenMin = 50;
    int firstTokenMax = 180;  // Keep under 200ms target
    int subsequentMin = 30;
    int subsequentMax = 90;   // Keep under 100ms target
};

static LatencyProfile g_profile;
static bool g_running = true;
static int g_requestCount = 0;

// Simulated Fibonacci completion response
const char* getFibonacciCompletion() {
    return "acci sequence up to n terms\n"
           "    std::vector\u003cint\u003e fibonacci(int n) {\n"
           "        std::vector\u003cint\u003e result;\n"
           "        if (n \u003c= 0) return result;\n"
           "        result.push_back(0);\n"
           "        if (n == 1) return result;\n"
           "        result.push_back(1);\n"
           "        for (int i = 2; i \u003c n; ++i) {\n"
           "            result.push_back(result[i-1] + result[i-2]);\n"
           "        }\n"
           "        return result;\n"
           "    }";
}

void simulateLatency(int minMs, int maxMs) {
    int latency = minMs + (rand() % (maxMs - minMs + 1));
    Sleep(latency);
}

void sendToken(HANDLE hPipe, const char* token, bool isFinal, int requestId) {
    Json::Value root;
    root["token"] = token;
    root["is_final"] = isFinal;
    
    Json::StreamWriterBuilder builder;
    std::string payload = Json::writeString(builder, root);
    
    // Build message header
    struct IPCHeader {
        uint32_t magic;
        uint32_t version;
        uint32_t type;
        uint32_t payloadSize;
        uint64_t timestamp;
        uint32_t requestId;
    };
    
    IPCHeader header = {};
    header.magic = 0x534F5645;  // 'SOVE'
    header.version = 1;
    header.type = 0x10;  // COMPLETION_TOKEN
    header.payloadSize = payload.size();
    header.timestamp = 0;
    header.requestId = requestId;
    
    DWORD written;
    WriteFile(hPipe, &header, sizeof(header), &written, nullptr);
    WriteFile(hPipe, payload.c_str(), payload.size(), &written, nullptr);
    FlushFileBuffers(hPipe);
}

void sendComplete(HANDLE hPipe, int totalTokens, float totalTime, int requestId) {
    Json::Value root;
    root["total_tokens"] = totalTokens;
    root["total_time_ms"] = totalTime;
    
    Json::StreamWriterBuilder builder;
    std::string payload = Json::writeString(builder, root);
    
    struct IPCHeader {
        uint32_t magic;
        uint32_t version;
        uint32_t type;
        uint32_t payloadSize;
        uint64_t timestamp;
        uint32_t requestId;
    };
    
    IPCHeader header = {};
    header.magic = 0x534F5645;
    header.version = 1;
    header.type = 0x11;  // COMPLETION_COMPLETE
    header.payloadSize = payload.size();
    header.timestamp = 0;
    header.requestId = requestId;
    
    DWORD written;
    WriteFile(hPipe, &header, sizeof(header), &written, nullptr);
    WriteFile(hPipe, payload.c_str(), payload.size(), &written, nullptr);
    FlushFileBuffers(hPipe);
}

void handleCompletionRequest(HANDLE hPipe, const char* payload, int requestId) {
    printf("[MockServer] Handling completion request %d\n", requestId);
    
    // Simulate first token latency
    simulateLatency(g_profile.firstTokenMin, g_profile.firstTokenMax);
    
    // Send first token
    sendToken(hPipe, "acci", false, requestId);
    
    // Get completion text and tokenize (simple word-based)
    const char* completion = getFibonacciCompletion();
    char buffer[1024];
    strncpy(buffer, completion, sizeof(buffer));
    
    // Send tokens with simulated latency
    int tokenCount = 1;
    char* context = nullptr;
    char* token = strtok_s(buffer, " \n\t", &context);
    
    while (token != nullptr && tokenCount < 50) {
        simulateLatency(g_profile.subsequentMin, g_profile.subsequentMax);
        
        char tokenBuf[256];
        snprintf(tokenBuf, sizeof(tokenBuf), "%s ", token);
        sendToken(hPipe, tokenBuf, false, requestId);
        
        tokenCount++;
        token = strtok_s(nullptr, " \n\t", &context);
    }
    
    // Send final token
    simulateLatency(g_profile.subsequentMin, g_profile.subsequentMax);
    sendToken(hPipe, "}", true, requestId);
    
    // Send completion
    float totalTime = (g_profile.firstTokenMin + g_profile.firstTokenMax) / 2.0f + 
                      (tokenCount * (g_profile.subsequentMin + g_profile.subsequentMax) / 2.0f);
    sendComplete(hPipe, tokenCount, totalTime, requestId);
    
    printf("[MockServer] Request %d complete: %d tokens\n", requestId, tokenCount);
}

int main() {
    printf("=== Sovereign Mock Server ===\n");
    printf("Simulating 7B Q4_K model with MMAP optimization\n");
    printf("Target: First token \u003c200ms, Subsequent \u003c100ms\n\n");
    
    srand(static_cast<unsigned>(time(nullptr)));
    
    // Create named pipe
    HANDLE hPipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BUFFER_SIZE,
        BUFFER_SIZE,
        0,
        nullptr
    );
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("Failed to create pipe: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[MockServer] Pipe created: %s\n", PIPE_NAME);
    printf("[MockServer] Waiting for client connection...\n");
    
    // Wait for client
    BOOL connected = ConnectNamedPipe(hPipe, nullptr);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("Failed to connect: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    
    printf("[MockServer] Client connected\n");
    printf("[MockServer] Ready to handle completion requests\n\n");
    
    // Message loop
    struct IPCHeader {
        uint32_t magic;
        uint32_t version;
        uint32_t type;
        uint32_t payloadSize;
        uint64_t timestamp;
        uint32_t requestId;
    };
    
    while (g_running) {
        IPCHeader header;
        DWORD bytesRead;
        
        // Read header
        BOOL success = ReadFile(hPipe, &header, sizeof(header), &bytesRead, nullptr);
        if (!success || bytesRead != sizeof(header)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                printf("[MockServer] Client disconnected\n");
                break;
            }
            continue;
        }
        
        // Validate header
        if (header.magic != 0x534F5645 || header.version != 1) {
            printf("[MockServer] Invalid header received\n");
            continue;
        }
        
        // Read payload
        std::string payload;
        if (header.payloadSize > 0) {
            payload.resize(header.payloadSize);
            success = ReadFile(hPipe, &payload[0], header.payloadSize, &bytesRead, nullptr);
            if (!success) {
                printf("[MockServer] Failed to read payload\n");
                continue;
            }
        }
        
        // Handle message
        switch (header.type) {
            case 0x01:  // COMPLETION_REQUEST
                handleCompletionRequest(hPipe, payload.c_str(), header.requestId);
                g_requestCount++;
                break;
                
            case 0x02:  // CANCEL_REQUEST
                printf("[MockServer] Cancel request received\n");
                break;
                
            case 0x04:  // GET_STATUS
                // Send status response
                break;
                
            default:
                printf("[MockServer] Unknown message type: %u\n", header.type);
        }
    }
    
    printf("[MockServer] Shutting down. Handled %d requests\n", g_requestCount);
    
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    
    return 0;
}
