/*===========================================================================
 * SovereignTelemetry.h
 * VAL-027: Runtime Observability Layer
 * 
 * Anonymous telemetry collection for inference performance analysis.
 * Privacy-first: No code content, no user identifiers, only metrics.
 *
 * Architecture:
 *   SovereignInferenceBridge --> TelemetryCollector --> Exporters
 *                                    |
 *                                    +--> Runtime Overlay
 *                                    +--> Benchmark Export
 *                                    +--> Session Analysis
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define STEL_VERSION                    1
#define STEL_MAX_EVENT_QUEUE            1024
#define STEL_HISTOGRAM_BUCKETS          10
#define STEL_SESSION_ID_LEN             32
#define STEL_MAX_STRING_LEN             256

/*===========================================================================
 * EVENT TYPES
 *=========================================================================*/
typedef enum STEL_EventType {
    STEL_EVENT_INFERENCE_START = 0,
    STEL_EVENT_INFERENCE_COMPLETE,
    STEL_EVENT_INFERENCE_CANCELLED,
    STEL_EVENT_MODEL_LOAD,
    STEL_EVENT_MODEL_UNLOAD,
    STEL_EVENT_MEMORY_SNAPSHOT,
    STEL_EVENT_GHOSTTEXT_GENERATED,
    STEL_EVENT_GHOSTTEXT_ACCEPTED,
    STEL_EVENT_GHOSTTEXT_REJECTED,
    STEL_EVENT_GHOSTTEXT_EXPIRED,
    STEL_EVENT_CONTEXT_EXTRACTED,
    STEL_EVENT_SESSION_START,
    STEL_EVENT_SESSION_END,
    STEL_EVENT_ADAPTIVE_DEBOUNCE_CHANGED,
    STEL_EVENT_COUNT
} STEL_EventType;

/*===========================================================================
 * INFERENCE TELEMETRY EVENT
 * Core inference performance metrics
 *=========================================================================*/
typedef struct STEL_InferenceEvent {
    uint64_t    timestamp;                    // UTC timestamp (microseconds)
    uint64_t    sessionId;                  // Anonymous session identifier
    
    // Event classification
    STEL_EventType eventType;
    
    // Token metrics
    uint32_t    promptTokens;
    uint32_t    generatedTokens;
    uint32_t    contextTokens;
    
    // Latency metrics (milliseconds)
    double      firstTokenLatencyMs;
    double      generationLatencyMs;
    double      totalLatencyMs;
    double      tokensPerSecond;
    
    // Memory metrics (MB)
    size_t      memoryUsageMB;
    size_t      peakMemoryMB;
    size_t      kvCacheMB;
    
    // Model info
    WCHAR       modelName[STEL_MAX_STRING_LEN];
    WCHAR       quantization[16];             // "Q4_K_M", "Q5_K_M", etc.
    WCHAR       backend[16];                  // "AVX512", "AVX2", "CUDA"
    
    // Context info (no code content, only metadata)
    WCHAR       fileExtension[8];           // ".cpp", ".py", etc.
    uint32_t    fileSizeKB;
    uint32_t    cursorLine;
    uint32_t    cursorColumn;
    
    // GhostText specific
    double      timeToAcceptanceMs;         // 0 if not accepted
    uint32_t    acceptedLines;
    uint32_t    generatedLines;
    float       confidence;
    
    // Adaptive runtime
    uint32_t    debounceMs;                 // Current debounce setting
    uint32_t    contextWindow;              // Current context window size
} STEL_InferenceEvent;

/*===========================================================================
 * MEMORY SNAPSHOT
 * Track memory lifecycle throughout session
 *=========================================================================*/
typedef struct STEL_MemorySnapshot {
    uint64_t    timestamp;
    size_t      rssMB;                      // Resident set size
    size_t      virtualMemoryMB;
    size_t      gpuMemoryMB;                // 0 if CPU-only
    size_t      kvCacheMB;
    size_t      arenaUsageMB;
    size_t      modelWeightsMB;
    uint32_t    numActiveContexts;
    uint32_t    numLoadedModels;
} STEL_MemorySnapshot;

/*===========================================================================
 * LATENCY HISTOGRAM
 * Track distribution, not just averages
 *=========================================================================*/
typedef struct STEL_LatencyHistogram {
    // Bucket boundaries in milliseconds
    // 0-10, 10-25, 25-50, 50-100, 100-250, 250-500, 500-1000, 1000-2500, 2500-5000, 5000+
    uint64_t    buckets[STEL_HISTOGRAM_BUCKETS];
    uint64_t    totalCount;
    double      sumMs;
    double      minMs;
    double      maxMs;
    double      p50;
    double      p95;
    double      p99;
} STEL_LatencyHistogram;

/*===========================================================================
 * GHOSTTEXT METRICS
 * Product-level acceptance tracking
 *=========================================================================*/
typedef struct STEL_GhostTextMetrics {
    uint64_t    totalGenerated;
    uint64_t    totalAccepted;
    uint64_t    totalRejected;
    uint64_t    totalExpired;
    
    double      acceptanceRate;             // accepted / generated
    double      avgTimeToAcceptanceMs;
    double      suggestionUtility;          // accepted_lines / generated_lines
    
    // Per-language breakdown (top 10)
    struct {
        WCHAR       extension[8];
        uint64_t    generated;
        uint64_t    accepted;
        double      acceptanceRate;
    } byLanguage[10];
    uint32_t    languageCount;
} STEL_GhostTextMetrics;

/*===========================================================================
 * SESSION SUMMARY
 * Aggregated metrics for export
 *=========================================================================*/
typedef struct STEL_SessionSummary {
    uint64_t    sessionStart;
    uint64_t    sessionEnd;
    uint64_t    durationSeconds;
    
    // Inference stats
    uint64_t    totalInferences;
    uint64_t    totalTokensGenerated;
    double      avgTokensPerSecond;
    
    // Latency percentiles
    double      firstTokenP50;
    double      firstTokenP95;
    double      firstTokenP99;
    
    // Memory
    size_t      peakMemoryMB;
    size_t      avgMemoryMB;
    
    // GhostText
    double      ghostTextAcceptanceRate;
    uint64_t    ghostTextGenerated;
    uint64_t    ghostTextAccepted;
    
    // Model usage
    WCHAR       primaryModel[STEL_MAX_STRING_LEN];
    WCHAR       primaryQuantization[16];
    uint32_t    modelLoadCount;
    uint32_t    modelUnloadCount;
} STEL_SessionSummary;

/*===========================================================================
 * TELEMETRY COLLECTOR INTERFACE
 *=========================================================================*/

/* Initialize telemetry system
 * Returns: TRUE on success */
BOOL STEL_Initialize(void);

/* Shutdown and cleanup */
void STEL_Shutdown(void);

/* Check if telemetry is active */
BOOL STEL_IsActive(void);

/* Record an inference event (thread-safe) */
void STEL_RecordInference(const STEL_InferenceEvent* event);

/* Record a memory snapshot (thread-safe) */
void STEL_RecordMemory(const STEL_MemorySnapshot* snapshot);

/* Record GhostText event (thread-safe) */
void STEL_RecordGhostText(STEL_EventType type, 
                          const WCHAR* fileExtension,
                          uint32_t generatedLines,
                          uint32_t acceptedLines,
                          double timeToAcceptanceMs,
                          float confidence);

/* Get current GhostText metrics */
void STEL_GetGhostTextMetrics(STEL_GhostTextMetrics* outMetrics);

/* Get latency histogram for specific metric */
typedef enum STEL_LatencyMetric {
    STEL_LATENCY_FIRST_TOKEN = 0,
    STEL_LATENCY_GENERATION,
    STEL_LATENCY_TOTAL,
    STEL_LATENCY_MODEL_LOAD,
    STEL_LATENCY_CONTEXT_EXTRACT,
    STEL_LATENCY_COUNT
} STEL_LatencyMetric;

void STEL_GetLatencyHistogram(STEL_LatencyMetric metric, STEL_LatencyHistogram* outHistogram);

/* Get current memory snapshot */
void STEL_GetCurrentMemory(STEL_MemorySnapshot* outSnapshot);

/* Generate session summary */
void STEL_GenerateSessionSummary(STEL_SessionSummary* outSummary);

/* Export to JSON file */
BOOL STEL_ExportToJSON(const WCHAR* filePath);

/* Export to CSV for analysis */
BOOL STEL_ExportToCSV(const WCHAR* filePath);

/* Get runtime overlay string for status bar */
void STEL_GetRuntimeOverlayString(WCHAR* outBuffer, size_t bufferSize);

/* Reset all metrics (for testing) */
void STEL_Reset(void);

/* Enable/disable telemetry collection */
void STEL_SetEnabled(BOOL enabled);
BOOL STEL_IsEnabled(void);

#ifdef __cplusplus
}
#endif
