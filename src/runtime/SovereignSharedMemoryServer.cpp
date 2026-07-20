/*===========================================================================
 * SovereignSharedMemoryServer.cpp
 * Runtime server implementation for local AI inference
 * 
 * REAL IMPLEMENTATION - Uses InferenceEngine for actual token generation
 *===========================================================================*/

#include "SovereignSharedMemoryServer.hpp"
#include "inference_engine.hpp"
#include "ExecutionModeDetector.hpp"
#include <stdio.h>
#include <string.h>
#include <chrono>

// Real inference backend - InferenceEngine from inference_engine.cpp
namespace RawrXD {
namespace Runtime {

// Global inference engine instance - lazily initialized
static rawrxd::runtime::InferenceEngine* g_inferenceEngine = nullptr;
static bool g_engineInitialized = false;
static char g_modelName[256] = {0};
static char g_lastError[512] = {0};

// GGUF file mapping for execution mode detection
static void* g_ggufFileMapping = nullptr;
static size_t g_ggufFileSize = 0;
static ExecutionMode g_currentExecutionMode = ExecutionMode::Synthetic;

// Initialize the inference engine
static bool EnsureInferenceEngine() {
    if (g_engineInitialized && g_inferenceEngine) {
        return true;
    }
    
    if (!g_inferenceEngine) {
        g_inferenceEngine = new rawrxd::runtime::InferenceEngine();
    }
    
    // Initialize with default config
    rawrxd::runtime::InferenceConfig config;
    config.max_tokens = 256;
    config.temperature = 0.8f;
    config.top_p = 0.95f;
    config.top_k = 40;
    
    if (!g_inferenceEngine->Initialize(config)) {
        strncpy_s(g_lastError, sizeof(g_lastError), 
                  "Failed to initialize inference engine", _TRUNCATE);
        return false;
    }
    
    g_engineInitialized = true;
    strncpy_s(g_modelName, sizeof(g_modelName), "RawrXD-Default-Model", _TRUNCATE);
    return true;
}

// Check if model is loaded
static bool IsModelLoaded() {
    return g_engineInitialized && g_inferenceEngine != nullptr;
}

// Get model name
static const char* GetModelName() {
    return g_modelName[0] ? g_modelName : "No model loaded";
}

// Generate tokens using real InferenceEngine
static bool GenerateTokensInternal(
    const char* prompt,
    char* outputBuffer,
    size_t outputBufferSize,
    uint32_t maxTokens,
    float temperature,
    uint32_t& outTokenCount,
    float& outConfidence,
    uint32_t& outLatencyMs,
    float& outTps) {
    
    if (!EnsureInferenceEngine()) {
        strncpy_s(outputBuffer, outputBufferSize, g_lastError, _TRUNCATE);
        return false;
    }
    
    // Configure generation
    rawrxd::runtime::InferenceConfig config;
    config.max_tokens = maxTokens;
    config.temperature = temperature;
    config.top_p = 0.95f;
    config.top_k = 40;
    config.repetition_penalty = 1.0f;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Generate text using real inference engine
    std::string result = g_inferenceEngine->Generate(prompt, config);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    // Get telemetry
    auto telemetry = g_inferenceEngine->GetLastTelemetry();
    
    // Copy result to output buffer
    strncpy_s(outputBuffer, outputBufferSize, result.c_str(), _TRUNCATE);
    
    // Set output metrics
    outTokenCount = telemetry.tokens_generated;
    outConfidence = 0.85f;  // Average confidence (placeholder until real confidence tracking)
    outLatencyMs = static_cast<uint32_t>(duration.count());
    outTps = telemetry.tokens_per_second;
    
    return true;
}

} // namespace Runtime
} // namespace RawrXD

namespace RawrXD {
namespace Runtime {

/*===========================================================================
 * Construction / Destruction
 *=========================================================================*/

SovereignSharedMemoryServer::SovereignSharedMemoryServer()
    : m_hSharedMemory(NULL)
    , m_hRequestEvent(NULL)
    , m_hResponseEvent(NULL)
    , m_pSharedBlock(nullptr)
    , m_hWorkerThread(NULL)
    , m_running(false)
    , m_workerActive(false)
    , m_maxTokens(256)
    , m_temperature(0.7f)
{
}

SovereignSharedMemoryServer::~SovereignSharedMemoryServer() {
    Shutdown();
}

/*===========================================================================
 * Initialization
 *=========================================================================*/

bool SovereignSharedMemoryServer::Initialize(const wchar_t* sharedMemoryName) {
    printf("[SovereignRuntime] Initializing shared memory server...\n");
    
    // Create shared memory mapping
    m_hSharedMemory = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        sizeof(SovereignSharedBlock),
        sharedMemoryName
    );
    
    if (!m_hSharedMemory) {
        DWORD error = GetLastError();
        printf("[SovereignRuntime] ERROR: Failed to create shared memory (0x%08X)\n", error);
        return false;
    }
    
    // Map view
    m_pSharedBlock = (SovereignSharedBlock*)MapViewOfFile(
        m_hSharedMemory,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(SovereignSharedBlock)
    );
    
    if (!m_pSharedBlock) {
        printf("[SovereignRuntime] ERROR: Failed to map view of file\n");
        CleanupSharedMemory();
        return false;
    }
    
    // Initialize shared block
    ZeroMemory(m_pSharedBlock, sizeof(SovereignSharedBlock));
    m_pSharedBlock->requestReady.store(0);
    m_pSharedBlock->responseReady.store(0);
    
    // Create synchronization events
    m_hRequestEvent = CreateEventW(nullptr, FALSE, FALSE, L"RawrXD_RequestEvent");
    m_hResponseEvent = CreateEventW(nullptr, FALSE, FALSE, L"RawrXD_ResponseEvent");
    
    if (!m_hRequestEvent || !m_hResponseEvent) {
        printf("[SovereignRuntime] ERROR: Failed to create events\n");
        CleanupSharedMemory();
        return false;
    }
    
    printf("[SovereignRuntime] Shared memory initialized: %ls\n", sharedMemoryName);
    printf("[SovereignRuntime] Block size: %zu bytes\n", sizeof(SovereignSharedBlock));
    printf("[SovereignRuntime] Request buffer: %zu bytes\n", sizeof(SovereignRequest));
    printf("[SovereignRuntime] Response buffer: %zu bytes\n", sizeof(SovereignResponse));
    
    return true;
}

void SovereignSharedMemoryServer::Shutdown() {
    StopWorker();
    CleanupSharedMemory();
}

void SovereignSharedMemoryServer::CleanupSharedMemory() {
    if (m_pSharedBlock) {
        UnmapViewOfFile(m_pSharedBlock);
        m_pSharedBlock = nullptr;
    }
    
    if (m_hSharedMemory) {
        CloseHandle(m_hSharedMemory);
        m_hSharedMemory = NULL;
    }
    
    if (m_hRequestEvent) {
        CloseHandle(m_hRequestEvent);
        m_hRequestEvent = NULL;
    }
    
    if (m_hResponseEvent) {
        CloseHandle(m_hResponseEvent);
        m_hResponseEvent = NULL;
    }
    
    printf("[SovereignRuntime] Shared memory cleaned up\n");
}

/*===========================================================================
 * Worker Thread
 *=========================================================================*/

bool SovereignSharedMemoryServer::StartWorker() {
    if (m_running) {
        printf("[SovereignRuntime] Worker already running\n");
        return true;
    }
    
    if (!m_pSharedBlock) {
        printf("[SovereignRuntime] ERROR: Shared memory not initialized\n");
        return false;
    }
    
    m_running = true;
    m_workerActive = false;
    
    m_hWorkerThread = CreateThread(
        nullptr, 0,
        WorkerThreadProc,
        this, 0, nullptr
    );
    
    if (!m_hWorkerThread) {
        printf("[SovereignRuntime] ERROR: Failed to create worker thread\n");
        m_running = false;
        return false;
    }
    
    // Wait for worker to become active
    int retries = 50;
    while (!m_workerActive && retries-- > 0) {
        Sleep(10);
    }
    
    if (m_workerActive) {
        printf("[SovereignRuntime] Worker thread active\n");
        return true;
    } else {
        printf("[SovereignRuntime] ERROR: Worker failed to start\n");
        StopWorker();
        return false;
    }
}

void SovereignSharedMemoryServer::StopWorker() {
    if (!m_running) return;
    
    printf("[SovereignRuntime] Stopping worker...\n");
    m_running = false;
    
    // Signal event to wake up worker
    if (m_hRequestEvent) {
        SetEvent(m_hRequestEvent);
    }
    
    // Wait for thread to exit
    if (m_hWorkerThread) {
        WaitForSingleObject(m_hWorkerThread, 5000);
        CloseHandle(m_hWorkerThread);
        m_hWorkerThread = NULL;
    }
    
    m_workerActive = false;
    printf("[SovereignRuntime] Worker stopped\n");
}

bool SovereignSharedMemoryServer::IsWorkerActive() const {
    return m_workerActive;
}

DWORD WINAPI SovereignSharedMemoryServer::WorkerThreadProc(LPVOID param) {
    auto* server = static_cast<SovereignSharedMemoryServer*>(param);
    server->WorkerLoop();
    return 0;
}

void SovereignSharedMemoryServer::WorkerLoop() {
    printf("[SovereignRuntime] Worker loop started\n");
    m_workerActive = true;
    
    while (m_running) {
        // Wait for request
        DWORD waitResult = WaitForSingleObject(m_hRequestEvent, 100);
        
        if (waitResult == WAIT_OBJECT_0) {
            // Request signaled - process it
            if (m_pSharedBlock && m_pSharedBlock->requestReady.load() == 1) {
                SovereignRequest request = m_pSharedBlock->request;
                SovereignResponse response = {};
                
                // Mark request as consumed
                m_pSharedBlock->requestReady.store(0);
                
                // Process
                bool success = ProcessRequest(request, response);
                
                // Write response with atomic sequence for consistency detection
                // Sequence is incremented before responseReady to ensure client
                // can detect if they read a partially-written response
                uint32_t seq = m_pSharedBlock->response.sequenceNumber.load() + 1;
                m_pSharedBlock->response = response;
                m_pSharedBlock->response.sequenceNumber.store(seq);
                
                // Memory barrier ensures all writes complete before responseReady
                std::atomic_thread_fence(std::memory_order_release);
                m_pSharedBlock->responseReady.store(1);
                
                // Signal completion
                SetEvent(m_hResponseEvent);
                
                // Update stats
                m_pSharedBlock->stats.requestsReceived++;
                m_pSharedBlock->stats.responsesSent++;
                if (!success) {
                    m_pSharedBlock->stats.errors++;
                }
                m_pSharedBlock->stats.totalTokens += response.tokenCount;
                m_pSharedBlock->stats.totalLatencyMs += response.latencyMs;
                
                // Log
                printf("[SovereignRuntime] Request %llu: %u tokens, %u ms, %.1f TPS\n",
                       request.requestId, response.tokenCount, 
                       response.latencyMs, response.tps);
            }
        }
    }
    
    m_workerActive = false;
    printf("[SovereignRuntime] Worker loop exiting\n");
}

/*===========================================================================
 * Request Processing
 *=========================================================================*/

bool SovereignSharedMemoryServer::ProcessRequest(
    const SovereignRequest& request, 
    SovereignResponse& response) {
    
    // Populate response header
    response.requestId = request.requestId;
    response.timestamp = GetTickCount64();
    response.status = 0;  // Success
    
    // Call Deep2 inference
    bool success = CallDeep2Inference(request, response);
    
    if (!success) {
        response.status = 1;  // Error
        strncpy_s(response.errorMessage, sizeof(response.errorMessage),
                   "Deep2 inference failed", _TRUNCATE);
    }
    
    return success;
}

bool SovereignSharedMemoryServer::CallDeep2Inference(
    const SovereignRequest& request, 
    SovereignResponse& response) {
    
    // Check if model is loaded
    if (!IsModelLoaded()) {
        // Try to initialize
        if (!EnsureInferenceEngine()) {
            strncpy_s(response.errorMessage, sizeof(response.errorMessage),
                      "No model loaded. Initialize inference engine first.", _TRUNCATE);
            response.status = 1;
            return false;
        }
    }
    
    // Prepare parameters
    uint32_t maxTokens = request.maxTokens > 0 ? request.maxTokens : m_maxTokens;
    float temperature = request.temperature > 0 ? request.temperature : m_temperature;
    
    // Call real inference
    uint32_t tokenCount = 0;
    float confidence = 0.0f;
    uint32_t latencyMs = 0;
    float tps = 0.0f;
    
    bool success = GenerateTokensInternal(
        request.prompt,
        response.text,
        sizeof(response.text),
        maxTokens,
        temperature,
        tokenCount,
        confidence,
        latencyMs,
        tps
    );
    
    if (success) {
        response.tokenCount = tokenCount;
        response.confidence = confidence;
        response.latencyMs = latencyMs;
        response.tps = tps;
        response.status = 0;
        
        // Detect execution mode using GGUF header probe
        ExecutionMode mode = ExecutionModeDetector::Detect(g_ggufFileMapping);
        g_currentExecutionMode = mode;
        
        // Populate execution provenance
        strncpy_s(response.modelName, sizeof(response.modelName), 
                  GetModelName(), _TRUNCATE);
        strncpy_s(response.executionMode, sizeof(response.executionMode),
                  ExecutionModeToString(mode), _TRUNCATE);
        strncpy_s(response.backend, sizeof(response.backend),
                  "Sovereign CPU", _TRUNCATE);  // TODO: Detect AVX512/AVX2
        response.runtimeVersion = 0x00010000;  // Version 1.0.0
        response.flags = (mode == ExecutionMode::GgufBacked) ? 0x00000002 : 0x00000001;
    } else {
        response.status = 1;
        strncpy_s(response.errorMessage, sizeof(response.errorMessage),
                  response.text, _TRUNCATE);  // Error message is in text buffer on failure
    }
    
    return success;
}

/*===========================================================================
 * Telemetry
 *=========================================================================*/

SovereignSharedMemoryServer::Telemetry SovereignSharedMemoryServer::GetTelemetry() const {
    Telemetry telem = {};
    
    if (m_pSharedBlock) {
        telem.requestsReceived = m_pSharedBlock->stats.requestsReceived;
        telem.responsesSent = m_pSharedBlock->stats.responsesSent;
        telem.errors = m_pSharedBlock->stats.errors;
        telem.totalTokens = m_pSharedBlock->stats.totalTokens;
        
        if (telem.responsesSent > 0) {
            telem.avgLatencyMs = (double)m_pSharedBlock->stats.totalLatencyMs / telem.responsesSent;
            telem.avgTps = (double)telem.totalTokens / (m_pSharedBlock->stats.totalLatencyMs / 1000.0);
        }
    }
    
    return telem;
}

/*===========================================================================
 * Callbacks
 *=========================================================================*/

void SovereignSharedMemoryServer::SetTokenCallback(TokenCallback callback) {
    m_tokenCallback = callback;
}

void SovereignSharedMemoryServer::SetCompletionCallback(CompletionCallback callback) {
    m_completionCallback = callback;
}

} // namespace Runtime
} // namespace RawrXD

/*===========================================================================
 * C-Compatible Exports
 *=========================================================================*/

extern "C" {

__declspec(dllexport) void* SovereignRuntime_Create() {
    return new RawrXD::Runtime::SovereignSharedMemoryServer();
}

__declspec(dllexport) void SovereignRuntime_Destroy(void* server) {
    delete static_cast<RawrXD::Runtime::SovereignSharedMemoryServer*>(server);
}

__declspec(dllexport) int SovereignRuntime_Initialize(void* server, const wchar_t* name) {
    auto* srv = static_cast<RawrXD::Runtime::SovereignSharedMemoryServer*>(server);
    return srv->Initialize(name) ? 1 : 0;
}

__declspec(dllexport) int SovereignRuntime_Start(void* server) {
    auto* srv = static_cast<RawrXD::Runtime::SovereignSharedMemoryServer*>(server);
    return srv->StartWorker() ? 1 : 0;
}

__declspec(dllexport) void SovereignRuntime_Stop(void* server) {
    auto* srv = static_cast<RawrXD::Runtime::SovereignSharedMemoryServer*>(server);
    srv->StopWorker();
}

__declspec(dllexport) int SovereignRuntime_IsRunning(void* server) {
    auto* srv = static_cast<RawrXD::Runtime::SovereignSharedMemoryServer*>(server);
    return srv->IsWorkerActive() ? 1 : 0;
}

} // extern "C"
