/*===========================================================================
 * SovereignTelemetryIntegration.cpp
 * VAL-027: Telemetry Integration Points
 * 
 * Bridges SovereignInferenceBridge and GhostTextEngine with telemetry.
 * Non-intrusive: Only records if telemetry is initialized.
 *===========================================================================*/

#include "SovereignTelemetry.h"
#include "SovereignInferenceBridge.h"
#include "RawrXD_IDE_GhostText_Engine.hpp"
#include "Deep2Bridge.h"
#include <string>
#include <chrono>

/*===========================================================================
 * INFERENCE TELEMETRY INTEGRATION
 *=========================================================================*/

// Per-request tracking state
struct InferenceTelemetryContext {
    uint64_t requestStartMicros;
    uint64_t firstTokenMicros;
    uint64_t completionMicros;
    uint32_t promptTokens;
    uint32_t generatedTokens;
    size_t startMemoryMB;
    size_t peakMemoryMB;
    WCHAR fileExtension[8];
    WCHAR modelName[STEL_MAX_STRING_LEN];
    WCHAR quantization[16];
    WCHAR backend[16];
    uint32_t debounceMs;
    uint32_t contextWindow;
    float confidence;
};

static thread_local InferenceTelemetryContext* g_currentInference = nullptr;

/* Called at start of inference request */
void STEL_BeginInference(const SIB_CompletionRequest* request) {
    if (!STEL_IsActive()) return;
    
    if (g_currentInference) {
        delete g_currentInference;
    }
    
    g_currentInference = new InferenceTelemetryContext();
    g_currentInference->requestStartMicros = 
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    g_currentInference->firstTokenMicros = 0;
    g_currentInference->completionMicros = 0;
    g_currentInference->promptTokens = 0;
    g_currentInference->generatedTokens = 0;
    
    // Extract file extension from filePath
    if (request->filePath[0]) {
        const WCHAR* ext = wcsrchr(request->filePath, L'.');
        if (ext) {
            wcsncpy_s(g_currentInference->fileExtension, 8, ext, 7);
        } else {
            wcscpy_s(g_currentInference->fileExtension, 8, L".txt");
        }
    } else {
        wcscpy_s(g_currentInference->fileExtension, 8, L".txt");
    }
    
    // Get current memory
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        g_currentInference->startMemoryMB = pmc.WorkingSetSize / (1024 * 1024);
        g_currentInference->peakMemoryMB = g_currentInference->startMemoryMB;
    }
    
    // Get model info
    SIB_ModelInfo modelInfo;
    if (SIB_GetModelInfo(&modelInfo)) {
        wcsncpy_s(g_currentInference->modelName, STEL_MAX_STRING_LEN, modelInfo.name, STEL_MAX_STRING_LEN - 1);
        swprintf_s(g_currentInference->quantization, 16, L"Q%d", modelInfo.quantizationBits);
    } else {
        wcscpy_s(g_currentInference->modelName, STEL_MAX_STRING_LEN, L"unknown");
        wcscpy_s(g_currentInference->quantization, 16, L"Q4");
    }
    
    // Detect backend
    if (Deep2Bridge_HasAVX512()) {
        wcscpy_s(g_currentInference->backend, 16, L"AVX512");
    } else if (Deep2Bridge_HasAVX2()) {
        wcscpy_s(g_currentInference->backend, 16, L"AVX2");
    } else {
        wcscpy_s(g_currentInference->backend, 16, L"SSE");
    }
    
    // Config
    g_currentInference->debounceMs = SIB_DEBOUNCE_MS;
    g_currentInference->contextWindow = request->maxTokens;
    g_currentInference->confidence = 0.0f;
}

/* Called when first token is generated */
void STEL_OnFirstToken(uint32_t tokenIndex) {
    if (!STEL_IsActive() || !g_currentInference) return;
    
    g_currentInference->firstTokenMicros = 
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    g_currentInference->generatedTokens = tokenIndex + 1;
    
    // Update peak memory
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        size_t currentMB = pmc.WorkingSetSize / (1024 * 1024);
        if (currentMB > g_currentInference->peakMemoryMB) {
            g_currentInference->peakMemoryMB = currentMB;
        }
    }
}

/* Called for each token during generation */
void STEL_OnTokenGenerated(uint32_t tokenIndex) {
    if (!STEL_IsActive() || !g_currentInference) return;
    
    g_currentInference->generatedTokens = tokenIndex + 1;
    
    // Update peak memory periodically (every 10 tokens)
    if (tokenIndex % 10 == 0) {
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            size_t currentMB = pmc.WorkingSetSize / (1024 * 1024);
            if (currentMB > g_currentInference->peakMemoryMB) {
                g_currentInference->peakMemoryMB = currentMB;
            }
        }
    }
}

/* Called when inference completes */
void STEL_EndInference(BOOL success, float confidence) {
    if (!STEL_IsActive() || !g_currentInference) return;
    
    g_currentInference->completionMicros = 
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    g_currentInference->confidence = confidence;
    
    // Calculate latencies
    double firstTokenMs = 0.0;
    if (g_currentInference->firstTokenMicros > 0) {
        firstTokenMs = (g_currentInference->firstTokenMicros - g_currentInference->requestStartMicros) / 1000.0;
    }
    
    double totalMs = (g_currentInference->completionMicros - g_currentInference->requestStartMicros) / 1000.0;
    double generationMs = totalMs - firstTokenMs;
    
    // Calculate tokens per second
    double tps = 0.0;
    if (generationMs > 0 && g_currentInference->generatedTokens > 0) {
        tps = (g_currentInference->generatedTokens - 1) / (generationMs / 1000.0);
    }
    
    // Final memory check
    PROCESS_MEMORY_COUNTERS pmc;
    size_t currentMemoryMB = 0;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        currentMemoryMB = pmc.WorkingSetSize / (1024 * 1024);
        if (currentMB > g_currentInference->peakMemoryMB) {
            g_currentInference->peakMemoryMB = currentMB;
        }
    }
    
    // Build and record event
    STEL_InferenceEvent event = {};
    event.timestamp = g_currentInference->requestStartMicros;
    event.sessionId = 0; // Will be filled by collector
    event.eventType = success ? STEL_EVENT_INFERENCE_COMPLETE : STEL_EVENT_INFERENCE_CANCELLED;
    event.promptTokens = g_currentInference->promptTokens;
    event.generatedTokens = g_currentInference->generatedTokens;
    event.firstTokenLatencyMs = firstTokenMs;
    event.generationLatencyMs = generationMs;
    event.totalLatencyMs = totalMs;
    event.tokensPerSecond = tps;
    event.memoryUsageMB = currentMemoryMB;
    event.peakMemoryMB = g_currentInference->peakMemoryMB;
    event.kvCacheMB = 0; // TODO: Get from inference engine
    
    wcsncpy_s(event.modelName, STEL_MAX_STRING_LEN, g_currentInference->modelName, STEL_MAX_STRING_LEN - 1);
    wcsncpy_s(event.quantization, 16, g_currentInference->quantization, 15);
    wcsncpy_s(event.backend, 16, g_currentInference->backend, 15);
    wcsncpy_s(event.fileExtension, 8, g_currentInference->fileExtension, 7);
    
    event.confidence = confidence;
    event.debounceMs = g_currentInference->debounceMs;
    event.contextWindow = g_currentInference->contextWindow;
    
    STEL_RecordInference(&event);
    
    // Cleanup
    delete g_currentInference;
    g_currentInference = nullptr;
}

/*===========================================================================
 * GHOSTTEXT TELEMETRY INTEGRATION
 *=========================================================================*/

// Track GhostText state for telemetry
struct GhostTextTelemetryState {
    uint64_t generationTimestamp;
    uint64_t acceptanceTimestamp;
    std::string suggestionText;
    WCHAR fileExtension[8];
    float confidence;
    bool pending;
};

static GhostTextTelemetryState g_ghostTextState = {};

/* Called when GhostText suggestion is generated */
void STEL_GhostTextGenerated(const std::string& text, const WCHAR* filePath, float confidence) {
    if (!STEL_IsActive()) return;
    
    g_ghostTextState.generationTimestamp = 
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    g_ghostTextState.suggestionText = text;
    g_ghostTextState.confidence = confidence;
    g_ghostTextState.pending = true;
    
    // Extract file extension
    if (filePath) {
        const WCHAR* ext = wcsrchr(filePath, L'.');
        if (ext) {
            wcsncpy_s(g_ghostTextState.fileExtension, 8, ext, 7);
        } else {
            wcscpy_s(g_ghostTextState.fileExtension, 8, L".txt");
        }
    } else {
        wcscpy_s(g_ghostTextState.fileExtension, 8, L".txt");
    }
    
    // Count lines in suggestion
    uint32_t lines = 1;
    for (char c : text) {
        if (c == '\n') lines++;
    }
    
    STEL_RecordGhostText(STEL_EVENT_GHOSTTEXT_GENERATED, 
                         g_ghostTextState.fileExtension,
                         lines, 0, 0.0, confidence);
}

/* Called when GhostText suggestion is accepted */
void STEL_GhostTextAccepted(uint32_t acceptedLines) {
    if (!STEL_IsActive() || !g_ghostTextState.pending) return;
    
    g_ghostTextState.acceptanceTimestamp = 
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    
    double timeToAcceptanceMs = 
        (g_ghostTextState.acceptanceTimestamp - g_ghostTextState.generationTimestamp) / 1000.0;
    
    uint32_t totalLines = 1;
    for (char c : g_ghostTextState.suggestionText) {
        if (c == '\n') totalLines++;
    }
    
    STEL_RecordGhostText(STEL_EVENT_GHOSTTEXT_ACCEPTED,
                         g_ghostTextState.fileExtension,
                         totalLines, acceptedLines, timeToAcceptanceMs,
                         g_ghostTextState.confidence);
    
    g_ghostTextState.pending = false;
}

/* Called when GhostText suggestion is rejected */
void STEL_GhostTextRejected() {
    if (!STEL_IsActive() || !g_ghostTextState.pending) return;
    
    uint32_t totalLines = 1;
    for (char c : g_ghostTextState.suggestionText) {
        if (c == '\n') totalLines++;
    }
    
    STEL_RecordGhostText(STEL_EVENT_GHOSTTEXT_REJECTED,
                         g_ghostTextState.fileExtension,
                         totalLines, 0, 0.0,
                         g_ghostTextState.confidence);
    
    g_ghostTextState.pending = false;
}

/* Called when GhostText suggestion expires (timeout) */
void STEL_GhostTextExpired() {
    if (!STEL_IsActive() || !g_ghostTextState.pending) return;
    
    uint32_t totalLines = 1;
    for (char c : g_ghostTextState.suggestionText) {
        if (c == '\n') totalLines++;
    }
    
    STEL_RecordGhostText(STEL_EVENT_GHOSTTEXT_EXPIRED,
                         g_ghostTextState.fileExtension,
                         totalLines, 0, 0.0,
                         g_ghostTextState.confidence);
    
    g_ghostTextState.pending = false;
}

/*===========================================================================
 * MEMORY TELEMETRY INTEGRATION
 *=========================================================================*/

/* Periodic memory snapshot (call from timer) */
void STEL_RecordMemorySnapshot(void) {
    if (!STEL_IsActive()) return;
    
    STEL_MemorySnapshot snapshot;
    STEL_GetCurrentMemory(&snapshot);
    STEL_RecordMemory(&snapshot);
}

/*===========================================================================
 * INITIALIZATION
 *=========================================================================*/

/* Initialize telemetry system - call during IDE startup */
BOOL STEL_InitializeForIDE(void) {
    // Initialize telemetry collector
    if (!STEL_Initialize()) {
        return FALSE;
    }
    
    // Record session start
    STEL_InferenceEvent event = {};
    event.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    event.eventType = STEL_EVENT_SESSION_START;
    STEL_RecordInference(&event);
    
    return TRUE;
}

/* Shutdown telemetry - call during IDE shutdown */
void STEL_ShutdownForIDE(void) {
    // Record session end
    STEL_InferenceEvent event = {};
    event.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    event.eventType = STEL_EVENT_SESSION_END;
    STEL_RecordInference(&event);
    
    // Export session summary
    WCHAR exportPath[MAX_PATH];
    GetTempPathW(MAX_PATH, exportPath);
    wcscat_s(exportPath, MAX_PATH, L"\\RawrXD_Telemetry_");
    
    SYSTEMTIME st;
    GetSystemTime(&st);
    WCHAR timestamp[32];
    swprintf_s(timestamp, 32, L"%04d%02d%02d_%02d%02d%02d", 
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    wcscat_s(exportPath, MAX_PATH, timestamp);
    wcscat_s(exportPath, MAX_PATH, L".json");
    
    STEL_ExportToJSON(exportPath);
    
    STEL_Shutdown();
}
