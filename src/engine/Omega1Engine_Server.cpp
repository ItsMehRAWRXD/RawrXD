// Omega1Engine_Server.cpp
// RawrXD OMEGA-1 Engine IPC Server
// Handles named pipe requests from Win32IDE

#include "../../include/omega1_ipc_protocol.h"
#include <windows.h>
#include <thread>
#include <atomic>
#include <cstring>

// Server state
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static HANDLE g_hStopEvent = nullptr;
static std::atomic<bool> g_running{false};
static std::thread g_serverThread;

// Function prototypes
static void ServerThreadFunc();
static bool HandleClient(HANDLE hPipe);
static bool ProcessRequest(const O1MessageHeader& header, const std::vector<uint8_t>& payload,
                           O1MessageHeader& responseHeader, std::vector<uint8_t>& responsePayload);

// Inference engine simulation (would be real in production)
static struct {
    bool modelLoaded = false;
    char modelPath[260] = {0};
    float tpsPrompt = 557.0f;
    float tpsGeneration = 344.0f;
    float gpu0Temp = 68.0f;
    float gpu1Temp = 72.0f;
    float gpu0VramUsed = 18.2f;
    float gpu0VramTotal = 32.0f;
    float gpu1VramUsed = 8.5f;
    float gpu1VramTotal = 16.0f;
    bool isGenerating = false;
} g_engineState;

// =============================================================================
// Public API
// =============================================================================

extern "C" {

__declspec(dllexport) bool Omega1Server_Start()
{
    if (g_running)
        return true; // Already running
    
    g_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_hStopEvent)
        return false;
    
    g_running = true;
    g_serverThread = std::thread(ServerThreadFunc);
    
    OutputDebugStringA("[Omega1Server] Started\n");
    return true;
}

__declspec(dllexport) void Omega1Server_Stop()
{
    if (!g_running)
        return;
    
    g_running = false;
    SetEvent(g_hStopEvent);
    
    // Disconnect pipe to unblock any waiting operations
    if (g_hPipe != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(g_hPipe);
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
    
    if (g_serverThread.joinable())
        g_serverThread.join();
    
    if (g_hStopEvent)
    {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = nullptr;
    }
    
    OutputDebugStringA("[Omega1Server] Stopped\n");
}

__declspec(dllexport) bool Omega1Server_IsRunning()
{
    return g_running;
}

__declspec(dllexport) void Omega1Server_SetModelLoaded(bool loaded, const char* modelPath)
{
    g_engineState.modelLoaded = loaded;
    if (modelPath)
    {
        strncpy_s(g_engineState.modelPath, modelPath, sizeof(g_engineState.modelPath) - 1);
    }
}

__declspec(dllexport) void Omega1Server_SetTelemetry(float tpsPrompt, float tpsGen,
                                                      float gpu0Temp, float gpu1Temp,
                                                      float gpu0VramUsed, float gpu0VramTotal,
                                                      float gpu1VramUsed, float gpu1VramTotal)
{
    g_engineState.tpsPrompt = tpsPrompt;
    g_engineState.tpsGeneration = tpsGen;
    g_engineState.gpu0Temp = gpu0Temp;
    g_engineState.gpu1Temp = gpu1Temp;
    g_engineState.gpu0VramUsed = gpu0VramUsed;
    g_engineState.gpu0VramTotal = gpu0VramTotal;
    g_engineState.gpu1VramUsed = gpu1VramUsed;
    g_engineState.gpu1VramTotal = gpu1VramTotal;
}

} // extern "C"

// =============================================================================
// Server Implementation
// =============================================================================

static void ServerThreadFunc()
{
    const wchar_t* pipeName = L"\\\\.\\pipe\\RawrXD_Omega1_v2";
    
    while (g_running)
    {
        // Create named pipe
        g_hPipe = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,  // Output buffer
            65536,  // Input buffer
            0,      // Default timeout
            nullptr // Default security
        );
        
        if (g_hPipe == INVALID_HANDLE_VALUE)
        {
            OutputDebugStringA("[Omega1Server] Failed to create pipe\n");
            Sleep(1000);
            continue;
        }
        
        // Wait for client connection
        HANDLE handles[2] = { g_hPipe, g_hStopEvent };
        DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        
        if (waitResult == WAIT_OBJECT_0 + 1) // Stop event
            break;
        
        if (waitResult == WAIT_OBJECT_0) // Client connected
        {
            OutputDebugStringA("[Omega1Server] Client connected\n");
            HandleClient(g_hPipe);
        }
        
        DisconnectNamedPipe(g_hPipe);
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}

static bool HandleClient(HANDLE hPipe)
{
    while (g_running)
    {
        // Read header
        O1MessageHeader header;
        DWORD bytesRead;
        BOOL success = ReadFile(hPipe, &header, sizeof(header), &bytesRead, nullptr);
        
        if (!success || bytesRead != sizeof(header))
            break;
        
        if (!header.Valid())
        {
            OutputDebugStringA("[Omega1Server] Invalid header received\n");
            break;
        }
        
        // Read payload if any
        std::vector<uint8_t> payload;
        if (header.payloadLen > 0)
        {
            payload.resize(header.payloadLen);
            success = ReadFile(hPipe, payload.data(), header.payloadLen, &bytesRead, nullptr);
            if (!success || bytesRead != header.payloadLen)
                break;
        }
        
        // Process request
        O1MessageHeader responseHeader;
        std::vector<uint8_t> responsePayload;
        
        if (ProcessRequest(header, payload, responseHeader, responsePayload))
        {
            // Send response
            DWORD bytesWritten;
            WriteFile(hPipe, &responseHeader, sizeof(responseHeader), &bytesWritten, nullptr);
            if (!responsePayload.empty())
            {
                WriteFile(hPipe, responsePayload.data(), (DWORD)responsePayload.size(), &bytesWritten, nullptr);
            }
        }
    }
    
    return true;
}

static bool ProcessRequest(const O1MessageHeader& header, const std::vector<uint8_t>& payload,
                           O1MessageHeader& responseHeader, std::vector<uint8_t>& responsePayload)
{
    // Initialize response header
    responseHeader.magic = O1IPC_MAGIC;
    responseHeader.version = O1IPC_VERSION;
    responseHeader.requestId = header.requestId;
    responseHeader.timestampUs = O1::QueryPerfCounterUs();
    responseHeader.checksum = 0;
    
    uint16_t msgType = header.msgType;
    
    switch (static_cast<O1RequestType>(msgType))
    {
        case O1RequestType::PING:
        {
            responseHeader.msgType = static_cast<uint16_t>(O1ResponseType::PONG);
            responseHeader.payloadLen = 0;
            return true;
        }
        
        case O1RequestType::STATUS_QUERY:
        {
            responseHeader.msgType = static_cast<uint16_t>(O1ResponseType::STATUS_UPDATE);
            
            O1StatusTelemetry telemetry;
            telemetry.timestampUs = O1::QueryPerfCounterUs();
            telemetry.tpsPrompt = g_engineState.tpsPrompt;
            telemetry.tpsGeneration = g_engineState.tpsGeneration;
            telemetry.gpu0TempC = g_engineState.gpu0Temp;
            telemetry.gpu1TempC = g_engineState.gpu1Temp;
            telemetry.gpu0VramUsedGb = g_engineState.gpu0VramUsed;
            telemetry.gpu0VramTotalGb = g_engineState.gpu0VramTotal;
            telemetry.gpu1VramUsedGb = g_engineState.gpu1VramUsed;
            telemetry.gpu1VramTotalGb = g_engineState.gpu1VramTotal;
            telemetry.activeModelLen = (uint32_t)strlen(g_engineState.modelPath);
            telemetry.kvCacheUsedTokens = 0;
            telemetry.kvCacheMaxTokens = 4096;
            telemetry.isGenerating = g_engineState.isGenerating ? 1 : 0;
            
            responsePayload.resize(sizeof(telemetry) + telemetry.activeModelLen);
            memcpy(responsePayload.data(), &telemetry, sizeof(telemetry));
            if (telemetry.activeModelLen > 0)
            {
                memcpy(responsePayload.data() + sizeof(telemetry), 
                       g_engineState.modelPath, telemetry.activeModelLen);
            }
            
            responseHeader.payloadLen = (uint32_t)responsePayload.size();
            responseHeader.checksum = O1::CRC32(responsePayload.data(), responsePayload.size());
            return true;
        }
        
        case O1RequestType::COMPLETION:
        {
            // Simulate completion
            responseHeader.msgType = static_cast<uint16_t>(O1ResponseType::GHOST_TEXT);
            
            const char* sampleCompletion = "// TODO: Implement completion";
            size_t completionLen = strlen(sampleCompletion);
            
            O1GhostTextResponse ghostResponse;
            ghostResponse.requestId = header.requestId;
            ghostResponse.insertLine = 0;
            ghostResponse.insertCol = 0;
            ghostResponse.replaceLen = 0;
            ghostResponse.confidence = 8500; // 85%
            ghostResponse.tokensGenerated = 5;
            ghostResponse.latencyUs = 15000; // 15ms
            
            responsePayload.resize(sizeof(ghostResponse) + completionLen);
            memcpy(responsePayload.data(), &ghostResponse, sizeof(ghostResponse));
            memcpy(responsePayload.data() + sizeof(ghostResponse), sampleCompletion, completionLen);
            
            responseHeader.payloadLen = (uint32_t)responsePayload.size();
            return true;
        }
        
        case O1RequestType::STREAM_START:
        {
            g_engineState.isGenerating = true;
            responseHeader.msgType = static_cast<uint16_t>(O1ResponseType::STREAM_TOKEN);
            responseHeader.payloadLen = 0;
            return true;
        }
        
        case O1RequestType::STREAM_CANCEL:
        {
            g_engineState.isGenerating = false;
            responseHeader.msgType = static_cast<uint16_t>(O1ResponseType::STREAM_ABORTED);
            responseHeader.payloadLen = 0;
            return true;
        }
        
        case O1RequestType::MODEL_SWITCH:
        {
            if (payload.size() >= sizeof(O1ModelSwitchRequest))
            {
                const O1ModelSwitchRequest* req = reinterpret_cast<const O1ModelSwitchRequest*>(payload.data());
                strncpy_s(g_engineState.modelPath, req->modelPath, sizeof(g_engineState.modelPath) - 1);
                g_engineState.modelLoaded = true;
            }
            
            responseHeader.msgType = static_cast<uint16_t>(O1ResponseType::PONG);
            responseHeader.payloadLen = 0;
            return true;
        }
        
        case O1RequestType::SHUTDOWN:
        {
            responseHeader.msgType = static_cast<uint16_t>(O1ResponseType::PONG);
            responseHeader.payloadLen = 0;
            g_running = false;
            return true;
        }
        
        default:
        {
            responseHeader.msgType = static_cast<uint16_t>(O1ResponseType::ERROR);
            
            O1ErrorResponse error;
            error.requestId = header.requestId;
            error.errorCode = static_cast<uint32_t>(O1ErrorCode::UNKNOWN_REQUEST);
            const char* msg = "Unknown request type";
            error.messageLen = (uint32_t)strlen(msg);
            
            responsePayload.resize(sizeof(error) + error.messageLen);
            memcpy(responsePayload.data(), &error, sizeof(error));
            memcpy(responsePayload.data() + sizeof(error), msg, error.messageLen);
            
            responseHeader.payloadLen = (uint32_t)responsePayload.size();
            return true;
        }
    }
}
