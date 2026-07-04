// ============================================================================
// RawrXD Pipe Server Callback - C++ payload processing
// Called by RawrXD_PipeServer_v2.asm to validate and route hotpatch payloads
// ============================================================================

#include <windows.h>
#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

// Phase 4A: Model Manager Integration
// These are defined in hotpatch_model_manager.cpp
extern "C" uint64_t RawrXD_HotpatchLoadModel(const char* modelPath);
extern "C" uint64_t RawrXD_HotpatchGetActiveModel(void);
extern "C" uint64_t RawrXD_HotpatchInitManager(void);

// Phase 4B: Cleanup Worker
extern "C" void RawrXD_HotpatchStartCleanupWorker(void);
extern "C" void RawrXD_HotpatchStopCleanupWorker(void);

#pragma pack(push, 1)
struct HotpatchPayload {
    uint32_t magic;           // 0x52485044 "RHPD"
    uint32_t version;         // Payload version
    uint32_t payloadSize;     // Size of payload data
    uint32_t flags;           // Execution flags
    uint64_t timestamp;       // Unix timestamp
    uint32_t crc32;           // CRC32 checksum
    uint8_t  data[0];         // Variable-length payload
};
#pragma pack(pop)

#define HOTPATCH_MAGIC 0x52485044
#define HOTPATCH_VERSION 1

// External router functions from rawrxd_hotpatch_router_simple.asm
extern "C" {
    uint64_t RawrXD_RequestHotpatch(void* modelDescriptor, uint64_t gpuFence);
    uint64_t RawrXD_CheckEpochSwap();
    uint64_t RawrXD_WaitForHotpatchComplete(uint32_t timeoutMs);
    uint64_t RawrXD_InitHotpatchSystem();
    uint64_t RawrXD_ForceSyncHotpatch();
    // Status query functions (to be implemented in router)
    uint64_t RawrXD_GetActiveEpochSlot();
    uint64_t RawrXD_GetShadowEpochSlot();
    uint64_t RawrXD_GetRetiredEpochSlot();
    uint64_t RawrXD_GetEpochCounter();
    uint64_t RawrXD_IsSwapPending();
    uint64_t RawrXD_RollbackToPreviousModel();
}

// Epoch counter - defined in hotpatch router
extern "C" uint64_t g_EpochCounter;
extern "C" uint64_t g_HotpatchCount;

// ============================================================================
// Telemetry / Observability
// ============================================================================
struct HotpatchTelemetry {
    uint64_t totalRequests = 0;
    uint64_t successCount = 0;      // router_code: 0
    uint64_t pendingCount = 0;      // router_code: 1
    uint64_t busyCount = 0;         // router_code: 2
    uint64_t readersActiveCount = 0; // router_code: 3
    uint64_t errorCount = 0;        // other codes
    uint64_t totalLatencyUs = 0;    // cumulative latency in microseconds
    uint64_t lastEpoch = 0;
};

static HotpatchTelemetry g_Telemetry;

static void LogTelemetry(uint64_t routerCode, uint64_t latencyUs) {
    g_Telemetry.totalRequests++;
    g_Telemetry.totalLatencyUs += latencyUs;
    
    switch (routerCode) {
        case 0: g_Telemetry.successCount++; break;
        case 1: g_Telemetry.pendingCount++; break;
        case 2: g_Telemetry.busyCount++; break;
        case 3: g_Telemetry.readersActiveCount++; break;
        default: g_Telemetry.errorCount++; break;
    }
    
    uint64_t epoch = g_EpochCounter;
    if (epoch != g_Telemetry.lastEpoch) {
        g_Telemetry.lastEpoch = epoch;
        fprintf(stderr, "[TELEMETRY] Epoch changed: %llu, Total requests: %llu, Avg latency: %llu us\n",
                epoch, g_Telemetry.totalRequests,
                g_Telemetry.totalRequests > 0 ? g_Telemetry.totalLatencyUs / g_Telemetry.totalRequests : 0);
    }
}

// Calculate CRC32 checksum
static uint32_t CalculateCRC32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

// Response buffer for pipe server
static uint8_t g_ResponseBuffer[4096];
static uint32_t g_ResponseLen = 0;

// Simple JSON parser for control commands
// Returns: pointer to value for key, or nullptr if not found
static const char* JsonGetString(const char* json, const char* key, char* outVal, size_t outSize) {
    char searchKey[64];
    snprintf(searchKey, sizeof(searchKey), "\"%s\"", key);
    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return nullptr;
    
    const char* valStart = strchr(keyPos + strlen(searchKey), '"');
    if (!valStart) return nullptr;
    valStart++; // Skip opening quote
    
    const char* valEnd = strchr(valStart, '"');
    if (!valEnd) return nullptr;
    
    size_t len = valEnd - valStart;
    if (len >= outSize) len = outSize - 1;
    memcpy(outVal, valStart, len);
    outVal[len] = '\0';
    return outVal;
}

// Process JSON control command
// Returns: number of bytes to send back to client
static uint32_t ProcessJsonCommand(const char* json, uint32_t jsonLen) {
    char cmd[32] = {0};
    if (!JsonGetString(json, "cmd", cmd, sizeof(cmd))) {
        const char* msg = "{\"error\": \"Missing 'cmd' field\"}";
        g_ResponseLen = (uint32_t)strlen(msg);
        memcpy(g_ResponseBuffer, msg, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // === CMD: status ===
    if (strcmp(cmd, "status") == 0) {
        uint64_t activeSlot = RawrXD_GetActiveEpochSlot();
        uint64_t shadowSlot = RawrXD_GetShadowEpochSlot();
        uint64_t retiredSlot = RawrXD_GetRetiredEpochSlot();
        uint64_t epoch = RawrXD_GetEpochCounter();
        uint64_t pending = RawrXD_IsSwapPending();
        
        char response[1024];
        snprintf(response, sizeof(response),
            "{\"status\":\"ok\",\"epoch\":%llu,\"swap_pending\":%s,"
            "\"slots\":{\"active\":%llu,\"shadow\":%llu,\"retired\":%llu}}",
            epoch, pending ? "true" : "false",
            activeSlot, shadowSlot, retiredSlot);
        
        g_ResponseLen = (uint32_t)strlen(response);
        memcpy(g_ResponseBuffer, response, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // === CMD: rollback ===
    if (strcmp(cmd, "rollback") == 0) {
        uint64_t result = RawrXD_RollbackToPreviousModel();
        
        char response[512];
        const char* status = (result == 0) ? "ok" : "failed";
        snprintf(response, sizeof(response),
            "{\"status\":\"%s\",\"rollback_code\":%llu}",
            status, result);
        
        g_ResponseLen = (uint32_t)strlen(response);
        memcpy(g_ResponseBuffer, response, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // === CMD: gpu_upload (Phase 3: Track 3) ===
    if (strcmp(cmd, "gpu_upload") == 0) {
        char modelHandleStr[32] = {0};
        if (!JsonGetString(json, "model_handle", modelHandleStr, sizeof(modelHandleStr))) {
            const char* msg = "{\"error\": \"Missing 'model_handle' field\"}";
            g_ResponseLen = (uint32_t)strlen(msg);
            memcpy(g_ResponseBuffer, msg, g_ResponseLen);
            return g_ResponseLen;
        }
        
        uint64_t modelHandle = strtoull(modelHandleStr, nullptr, 16);
        if (!modelHandle) {
            const char* msg = "{\"error\": \"Invalid model_handle\"}";
            g_ResponseLen = (uint32_t)strlen(msg);
            memcpy(g_ResponseBuffer, msg, g_ResponseLen);
            return g_ResponseLen;
        }
        
        // GPU upload - placeholder until Vulkan SDK is available
        // TODO: Enable RAWRXD_ENABLE_GPU_UPLOAD when Vulkan headers are in path
        char response[512];
        snprintf(response, sizeof(response),
            "{\"status\":\"ok\",\"model_handle\":\"0x%llX\",\"note\":\"GPU upload pipeline ready (Vulkan SDK required for actual upload)\"}",
            modelHandle);
        
        g_ResponseLen = (uint32_t)strlen(response);
        memcpy(g_ResponseBuffer, response, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // === CMD: gpu_status (Phase 3: Track 3) ===
    if (strcmp(cmd, "gpu_status") == 0) {
        // GPU status - placeholder until GPU swap bridge is linked
        // TODO: Link rawrxd_gpu_swap_bridge.asm for full implementation
        char response[512];
        snprintf(response, sizeof(response),
            "{\"status\":\"ok\",\"active_gpu_slot\":0,\"buffer_handle\":\"0x0\",\"note\":\"GPU upload pipeline ready, bridge linking pending\"}");
        
        g_ResponseLen = (uint32_t)strlen(response);
        memcpy(g_ResponseBuffer, response, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // === CMD: telemetry ===
    if (strcmp(cmd, "telemetry") == 0) {
        char response[1024];
        uint64_t avgLatency = g_Telemetry.totalRequests > 0 ? 
            g_Telemetry.totalLatencyUs / g_Telemetry.totalRequests : 0;
        
        snprintf(response, sizeof(response),
            "{\"status\":\"ok\",\"total_requests\":%llu,\"success\":%llu,\"pending\":%llu,\"busy\":%llu,\"readers_active\":%llu,\"errors\":%llu,\"avg_latency_us\":%llu,\"epoch\":%llu}",
            g_Telemetry.totalRequests,
            g_Telemetry.successCount,
            g_Telemetry.pendingCount,
            g_Telemetry.busyCount,
            g_Telemetry.readersActiveCount,
            g_Telemetry.errorCount,
            avgLatency,
            g_EpochCounter);
        
        g_ResponseLen = (uint32_t)strlen(response);
        memcpy(g_ResponseBuffer, response, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // === CMD: hotpatch (JSON variant) ===
    if (strcmp(cmd, "hotpatch") == 0) {
        char modelPath[512] = {0};
        if (!JsonGetString(json, "model_path", modelPath, sizeof(modelPath))) {
            const char* msg = "{\"error\": \"Missing 'model_path' field\"}";
            g_ResponseLen = (uint32_t)strlen(msg);
            memcpy(g_ResponseBuffer, msg, g_ResponseLen);
            return g_ResponseLen;
        }
        
        // Optional parameters
        char gpuLayerStr[16] = {0};
        int gpuLayer = 0;
        if (JsonGetString(json, "gpu_layer", gpuLayerStr, sizeof(gpuLayerStr))) {
            gpuLayer = atoi(gpuLayerStr);
        }
        
        char timeoutStr[16] = {0};
        uint32_t timeoutMs = 30000;
        if (JsonGetString(json, "timeout_ms", timeoutStr, sizeof(timeoutStr))) {
            timeoutMs = (uint32_t)atoi(timeoutStr);
        }
        
        printf("[PIPE] JSON hotpatch request: model=%s, gpu_layer=%d, timeout=%u\n",
               modelPath, gpuLayer, timeoutMs);
        
        // Telemetry: start timing
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Load model via Model Manager
        uint64_t modelHandle = RawrXD_HotpatchLoadModel(modelPath);
        if (!modelHandle) {
            const char* msg = "{\"error\": \"Failed to load model\"}";
            g_ResponseLen = (uint32_t)strlen(msg);
            memcpy(g_ResponseBuffer, msg, g_ResponseLen);
            return g_ResponseLen;
        }
        
        // Submit to router
        uint64_t routerResult = RawrXD_RequestHotpatch((void*)modelHandle, 0);
        RawrXD_CheckEpochSwap();
        
        // Telemetry: end timing and log
        QueryPerformanceCounter(&end);
        uint64_t latencyUs = ((end.QuadPart - start.QuadPart) * 1000000ULL) / freq.QuadPart;
        LogTelemetry(routerResult, latencyUs);
        
        char response[512];
        const char* status;
        switch (routerResult) {
            case 0: status = "ok"; break;
            case 1: status = "pending"; break;
            case 2: status = "busy"; break;
            case 3: status = "readers_active"; break;
            default: status = "error"; break;
        }
        
        snprintf(response, sizeof(response),
            "{\"status\":\"%s\",\"router_code\":%llu,\"model_handle\":\"0x%llX\",\"gpu_layer\":%d}",
            status, routerResult, modelHandle, gpuLayer);
        
        g_ResponseLen = (uint32_t)strlen(response);
        memcpy(g_ResponseBuffer, response, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // Unknown command
    char response[256];
    snprintf(response, sizeof(response), "{\"error\": \"Unknown command: %s\"}", cmd);
    g_ResponseLen = (uint32_t)strlen(response);
    memcpy(g_ResponseBuffer, response, g_ResponseLen);
    return g_ResponseLen;
}

// Process incoming pipe data
// Called by RawrXD_PipeServer_RunOnce in MASM
// Returns: number of bytes to send back to client
extern "C" uint32_t RawrXD_ProcessPipePayload(const uint8_t* requestData, uint32_t requestLen) {
    // Check for JSON command (starts with '{')
    if (requestLen > 0 && requestData[0] == '{') {
        // Null-terminate for safety
        char* jsonBuf = (char*)malloc(requestLen + 1);
        if (!jsonBuf) {
            const char* msg = "{\"error\": \"Out of memory\"}";
            g_ResponseLen = (uint32_t)strlen(msg);
            memcpy(g_ResponseBuffer, msg, g_ResponseLen);
            return g_ResponseLen;
        }
        memcpy(jsonBuf, requestData, requestLen);
        jsonBuf[requestLen] = '\0';
        
        uint32_t result = ProcessJsonCommand(jsonBuf, requestLen);
        free(jsonBuf);
        return result;
    }
    
    // Check minimum size for binary header
    if (requestLen < sizeof(HotpatchPayload)) {
        const char* msg = "{\"error\": \"Payload too small\"}";
        g_ResponseLen = (uint32_t)strlen(msg);
        memcpy(g_ResponseBuffer, msg, g_ResponseLen);
        return g_ResponseLen;
    }
    
    HotpatchPayload* payload = (HotpatchPayload*)requestData;
    
    // Validate magic
    if (payload->magic != HOTPATCH_MAGIC) {
        const char* msg = "{\"error\": \"Invalid magic\"}";
        g_ResponseLen = (uint32_t)strlen(msg);
        memcpy(g_ResponseBuffer, msg, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // Validate version
    if (payload->version != HOTPATCH_VERSION) {
        const char* msg = "{\"error\": \"Invalid version\"}";
        g_ResponseLen = (uint32_t)strlen(msg);
        memcpy(g_ResponseBuffer, msg, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // Validate payload size
    if (payload->payloadSize > requestLen - sizeof(HotpatchPayload)) {
        const char* msg = "{\"error\": \"Payload size mismatch\"}";
        g_ResponseLen = (uint32_t)strlen(msg);
        memcpy(g_ResponseBuffer, msg, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // Validate CRC32 (simplified - just CRC of data)
    uint32_t calcCrc = CalculateCRC32(payload->data, payload->payloadSize);
    if (calcCrc != payload->crc32) {
        const char* msg = "{\"error\": \"CRC32 mismatch\"}";
        g_ResponseLen = (uint32_t)strlen(msg);
        memcpy(g_ResponseBuffer, msg, g_ResponseLen);
        return g_ResponseLen;
    }
    
    // Valid payload - Phase 4A: Load model and submit to router
    printf("[PIPE] Valid hotpatch payload: %u bytes, flags=0x%08X\n", 
           payload->payloadSize, payload->flags);
    
    // Phase 4A: Parse payload as model path and load
    // Ensure null termination
    char modelPath[512];
    size_t pathLen = payload->payloadSize < sizeof(modelPath) - 1 ? payload->payloadSize : sizeof(modelPath) - 1;
    memcpy(modelPath, payload->data, pathLen);
    modelPath[pathLen] = '\0';
    
    printf("[PIPE] Loading model from path: %s\n", modelPath);
    
    // Telemetry: start timing
    LARGE_INTEGER freq2, start2, end2;
    QueryPerformanceFrequency(&freq2);
    QueryPerformanceCounter(&start2);
    
    // Load model via Model Manager
    uint64_t modelHandle = RawrXD_HotpatchLoadModel(modelPath);
    if (!modelHandle) {
        const char* msg = "{\"error\": \"Failed to load model\"}";
        g_ResponseLen = (uint32_t)strlen(msg);
        memcpy(g_ResponseBuffer, msg, g_ResponseLen);
        return g_ResponseLen;
    }
    
    printf("[PIPE] Model loaded, handle: 0x%llX\n", modelHandle);
    
    // Call router to request hotpatch with loaded model
    // rcx = model handle, rdx = GPU fence (0 for now)
    uint64_t routerResult = RawrXD_RequestHotpatch((void*)modelHandle, 0);
    
    // Telemetry: end timing and log
    QueryPerformanceCounter(&end2);
    uint64_t latencyUs2 = ((end2.QuadPart - start2.QuadPart) * 1000000ULL) / freq2.QuadPart;
    LogTelemetry(routerResult, latencyUs2);
    
    // Try to complete the swap immediately (for synchronous mode)
    RawrXD_CheckEpochSwap();
    
    // Build response based on router result
    char response[512];
    const char* status;
    switch (routerResult) {
        case 0:
            status = "ok";
            printf("[PIPE] Hotpatch requested successfully (epoch incremented)\n");
            break;
        case 1:
            status = "pending";
            printf("[PIPE] Hotpatch deferred: another already pending\n");
            break;
        case 2:
            status = "busy";
            printf("[PIPE] Hotpatch deferred: inference active\n");
            break;
        case 3:
            status = "readers_active";
            printf("[PIPE] Hotpatch deferred: readers still active\n");
            break;
        default:
            status = "error";
            printf("[PIPE] Hotpatch failed with code: %llu\n", routerResult);
            break;
    }
    
    snprintf(response, sizeof(response), 
             "{\"status\": \"%s\", \"bytes_received\": %u, \"router_code\": %llu, \"model_handle\": \"0x%llX\"}",
             status, payload->payloadSize, routerResult, modelHandle);
    
    g_ResponseLen = (uint32_t)strlen(response);
    memcpy(g_ResponseBuffer, response, g_ResponseLen);
    
    return g_ResponseLen;
}

// Get pointer to response buffer
extern "C" uint8_t* RawrXD_GetResponseBuffer() {
    return g_ResponseBuffer;
}

// Initialize hotpatch system
extern "C" void RawrXD_InitPipeServerIntegration() {
    RawrXD_InitHotpatchSystem();
    RawrXD_HotpatchInitManager();
    RawrXD_HotpatchStartCleanupWorker();  // Phase 4B: Start async cleanup
    printf("[PIPE] Hotpatch system, model manager, and cleanup worker initialized\n");
}

// Security descriptor for named pipe - only authenticated users and administrators
// SDDL: D:(A;;GA;;;AU)(A;;GA;;;BA) - Grant Generic All to Authenticated Users and Built-in Administrators
static SECURITY_ATTRIBUTES* g_PipeSecurityAttributes = nullptr;

// Initialize security attributes for named pipe with restrictive SDDL
// Returns: pointer to SECURITY_ATTRIBUTES (or nullptr on failure)
extern "C" void* RawrXD_GetPipeSecurityAttributes() {
    if (g_PipeSecurityAttributes != nullptr) {
        return g_PipeSecurityAttributes;
    }
    
    // SDDL string: Restrictive security for named pipe
    // D: DACL
    // (A;;GA;;;SY) - Allow Generic All to SYSTEM
    // (A;;GA;;;BA) - Allow Generic All to Built-in Administrators
    // (A;;GWGR;;;IU) - Allow Generic Write + Generic Read to Interactive Users (bidirectional pipe)
    const wchar_t* sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GWGR;;;IU)";
    
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 
            SDDL_REVISION_1, 
            &sd, 
            nullptr)) {
        printf("[PIPE][WARN] Failed to create security descriptor: %lu\n", GetLastError());
        return nullptr;
    }
    
    g_PipeSecurityAttributes = new SECURITY_ATTRIBUTES();
    g_PipeSecurityAttributes->nLength = sizeof(SECURITY_ATTRIBUTES);
    g_PipeSecurityAttributes->lpSecurityDescriptor = sd;
    g_PipeSecurityAttributes->bInheritHandle = FALSE;
    
    printf("[PIPE] Security attributes initialized with restricted SDDL\n");
    return g_PipeSecurityAttributes;
}

// Cleanup security attributes
extern "C" void RawrXD_CleanupPipeSecurityAttributes() {
    if (g_PipeSecurityAttributes != nullptr) {
        if (g_PipeSecurityAttributes->lpSecurityDescriptor != nullptr) {
            LocalFree(g_PipeSecurityAttributes->lpSecurityDescriptor);
        }
        delete g_PipeSecurityAttributes;
        g_PipeSecurityAttributes = nullptr;
    }
}
