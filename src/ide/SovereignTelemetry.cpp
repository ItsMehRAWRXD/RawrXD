/*===========================================================================
 * SovereignTelemetry.cpp
 * VAL-027: Runtime Observability Layer - Implementation
 * 
 * Thread-safe telemetry collection with lock-free event queue.
 *===========================================================================*/

#include "SovereignTelemetry.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <algorithm>

/*===========================================================================
 * INTERNAL STATE
 *=========================================================================*/
static struct {
    std::atomic<bool>           initialized{false};
    std::atomic<bool>           enabled{true};
    std::atomic<uint64_t>       sessionId{0};
    uint64_t                    sessionStart;
    
    // Event ring buffer (lock-free)
    STEL_InferenceEvent         eventQueue[STEL_MAX_EVENT_QUEUE];
    std::atomic<uint32_t>       writeIndex{0};
    std::atomic<uint32_t>       readIndex{0};
    
    // Histograms
    STEL_LatencyHistogram       histograms[STEL_LATENCY_COUNT];
    
    // GhostText metrics
    STEL_GhostTextMetrics       ghostTextMetrics;
    
    // Memory tracking
    std::vector<STEL_MemorySnapshot> memoryHistory;
    CRITICAL_SECTION            memoryLock;
    
    // Session aggregates
    std::atomic<uint64_t>       totalInferences{0};
    std::atomic<uint64_t>       totalTokens{0};
    std::atomic<double>         tokensPerSecondSum{0.0};
    std::atomic<uint64_t>       peakMemoryMB{0};
    
    // Model tracking
    WCHAR                       currentModel[STEL_MAX_STRING_LEN];
    WCHAR                       currentQuantization[16];
    std::atomic<uint32_t>       modelLoadCount{0};
    std::atomic<uint32_t>       modelUnloadCount{0};
} g_telemetry;

/*===========================================================================
 * HELPERS
 *=========================================================================*/
static uint64_t STEL_GetTimestampMicros(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000ULL) / freq.QuadPart;
}

static uint64_t STEL_GenerateSessionId(void) {
    // Simple hash of start time + process ID
    uint64_t time = GetTickCount64();
    DWORD pid = GetCurrentProcessId();
    return (time << 32) | pid;
}

static void STEL_UpdateHistogram(STEL_LatencyHistogram* hist, double latencyMs) {
    // Buckets: 0-10, 10-25, 25-50, 50-100, 100-250, 250-500, 500-1000, 1000-2500, 2500-5000, 5000+
    static const double boundaries[STEL_HISTOGRAM_BUCKETS] = {
        10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0
    };
    
    int bucket = STEL_HISTOGRAM_BUCKETS - 1;
    for (int i = 0; i < STEL_HISTOGRAM_BUCKETS - 1; i++) {
        if (latencyMs < boundaries[i]) {
            bucket = i;
            break;
        }
    }
    
    InterlockedIncrement64((LONG64*)&hist->buckets[bucket]);
    InterlockedIncrement64((LONG64*)&hist->totalCount);
    
    // Update min/max
    double currentMin = hist->minMs;
    while (latencyMs < currentMin && 
           InterlockedCompareExchange64((LONG64*)&hist->minMs, *(LONG64*)&latencyMs, *(LONG64*)&currentMin) != *(LONG64*)&currentMin) {
        currentMin = hist->minMs;
    }
    
    double currentMax = hist->maxMs;
    while (latencyMs > currentMax && 
           InterlockedCompareExchange64((LONG64*)&hist->maxMs, *(LONG64*)&latencyMs, *(LONG64*)&currentMax) != *(LONG64*)&currentMax) {
        currentMax = hist->maxMs;
    }
    
    // Update sum for average
    double oldSum = hist->sumMs;
    double newSum;
    do {
        newSum = oldSum + latencyMs;
    } while (InterlockedCompareExchange64((LONG64*)&hist->sumMs, *(LONG64*)&newSum, *(LONG64*)&oldSum) != *(LONG64*)&oldSum);
}

static void STEL_CalculatePercentiles(STEL_LatencyHistogram* hist) {
    if (hist->totalCount == 0) {
        hist->p50 = hist->p95 = hist->p99 = 0.0;
        return;
    }
    
    // Approximate percentiles from histogram buckets
    // Bucket centers: 5, 17.5, 37.5, 75, 175, 375, 750, 1750, 3750, 7500
    static const double centers[STEL_HISTOGRAM_BUCKETS] = {
        5.0, 17.5, 37.5, 75.0, 175.0, 375.0, 750.0, 1750.0, 3750.0, 7500.0
    };
    
    uint64_t cumulative = 0;
    uint64_t p50target = hist->totalCount / 2;
    uint64_t p95target = (hist->totalCount * 95) / 100;
    uint64_t p99target = (hist->totalCount * 99) / 100;
    
    hist->p50 = hist->p95 = hist->p99 = centers[STEL_HISTOGRAM_BUCKETS - 1];
    
    for (int i = 0; i < STEL_HISTOGRAM_BUCKETS; i++) {
        cumulative += hist->buckets[i];
        if (hist->p50 == centers[STEL_HISTOGRAM_BUCKETS - 1] && cumulative >= p50target) {
            hist->p50 = centers[i];
        }
        if (hist->p95 == centers[STEL_HISTOGRAM_BUCKETS - 1] && cumulative >= p95target) {
            hist->p95 = centers[i];
        }
        if (hist->p99 == centers[STEL_HISTOGRAM_BUCKETS - 1] && cumulative >= p99target) {
            hist->p99 = centers[i];
        }
    }
}

/*===========================================================================
 * PUBLIC API
 *=========================================================================*/
BOOL STEL_Initialize(void) {
    if (g_telemetry.initialized.exchange(true)) {
        return TRUE; // Already initialized
    }
    
    InitializeCriticalSection(&g_telemetry.memoryLock);
    
    g_telemetry.sessionId = STEL_GenerateSessionId();
    g_telemetry.sessionStart = STEL_GetTimestampMicros();
    
    // Initialize histograms
    for (int i = 0; i < STEL_LATENCY_COUNT; i++) {
        ZeroMemory(&g_telemetry.histograms[i], sizeof(STEL_LatencyHistogram));
        g_telemetry.histograms[i].minMs = 999999.0;
    }
    
    // Initialize GhostText metrics
    ZeroMemory(&g_telemetry.ghostTextMetrics, sizeof(STEL_GhostTextMetrics));
    
    return TRUE;
}

void STEL_Shutdown(void) {
    if (!g_telemetry.initialized.load()) return;
    
    DeleteCriticalSection(&g_telemetry.memoryLock);
    g_telemetry.initialized = false;
}

BOOL STEL_IsActive(void) {
    return g_telemetry.initialized.load() && g_telemetry.enabled.load();
}

void STEL_RecordInference(const STEL_InferenceEvent* event) {
    if (!STEL_IsActive()) return;
    
    // Copy to ring buffer
    uint32_t idx = g_telemetry.writeIndex.fetch_add(1) % STEL_MAX_EVENT_QUEUE;
    memcpy(&g_telemetry.eventQueue[idx], event, sizeof(STEL_InferenceEvent));
    
    // Update aggregates
    InterlockedIncrement64((LONG64*)&g_telemetry.totalInferences);
    InterlockedAdd64((LONG64*)&g_telemetry.totalTokens, event->generatedTokens);
    
    double tps = event->tokensPerSecond;
    double oldSum = g_telemetry.tokensPerSecondSum.load();
    double newSum;
    do {
        newSum = oldSum + tps;
    } while (!g_telemetry.tokensPerSecondSum.compare_exchange_weak(oldSum, newSum));
    
    // Update histograms
    STEL_UpdateHistogram(&g_telemetry.histograms[STEL_LATENCY_FIRST_TOKEN], event->firstTokenLatencyMs);
    STEL_UpdateHistogram(&g_telemetry.histograms[STEL_LATENCY_GENERATION], event->generationLatencyMs);
    STEL_UpdateHistogram(&g_telemetry.histograms[STEL_LATENCY_TOTAL], event->totalLatencyMs);
    
    // Track peak memory
    size_t currentPeak = g_telemetry.peakMemoryMB.load();
    while (event->peakMemoryMB > currentPeak && 
           !g_telemetry.peakMemoryMB.compare_exchange_weak(currentPeak, event->peakMemoryMB)) {
        // Retry with updated currentPeak
    }
}

void STEL_RecordMemory(const STEL_MemorySnapshot* snapshot) {
    if (!STEL_IsActive()) return;
    
    EnterCriticalSection(&g_telemetry.memoryLock);
    g_telemetry.memoryHistory.push_back(*snapshot);
    LeaveCriticalSection(&g_telemetry.memoryLock);
    
    // Update peak
    size_t currentPeak = g_telemetry.peakMemoryMB.load();
    while (snapshot->rssMB > currentPeak && 
           !g_telemetry.peakMemoryMB.compare_exchange_weak(currentPeak, snapshot->rssMB)) {
        // Retry
    }
}

void STEL_RecordGhostText(STEL_EventType type, 
                          const WCHAR* fileExtension,
                          uint32_t generatedLines,
                          uint32_t acceptedLines,
                          double timeToAcceptanceMs,
                          float confidence) {
    if (!STEL_IsActive()) return;
    
    STEL_GhostTextMetrics* metrics = &g_telemetry.ghostTextMetrics;
    
    switch (type) {
        case STEL_EVENT_GHOSTTEXT_GENERATED:
            InterlockedIncrement64((LONG64*)&metrics->totalGenerated);
            break;
        case STEL_EVENT_GHOSTTEXT_ACCEPTED:
            InterlockedIncrement64((LONG64*)&metrics->totalAccepted);
            // Update time to acceptance
            if (timeToAcceptanceMs > 0) {
                double oldAvg = metrics->avgTimeToAcceptanceMs;
                double newAvg;
                uint64_t count = metrics->totalAccepted;
                do {
                    newAvg = (oldAvg * (count - 1) + timeToAcceptanceMs) / count;
                } while (*(LONG64*)&metrics->avgTimeToAcceptanceMs != *(LONG64*)&oldAvg &&
                         InterlockedCompareExchange64((LONG64*)&metrics->avgTimeToAcceptanceMs, 
                                                      *(LONG64*)&newAvg, *(LONG64*)&oldAvg) != *(LONG64*)&oldAvg);
            }
            break;
        case STEL_EVENT_GHOSTTEXT_REJECTED:
            InterlockedIncrement64((LONG64*)&metrics->totalRejected);
            break;
        case STEL_EVENT_GHOSTTEXT_EXPIRED:
            InterlockedIncrement64((LONG64*)&metrics->totalExpired);
            break;
        default:
            break;
    }
    
    // Recalculate acceptance rate
    uint64_t generated = metrics->totalGenerated;
    uint64_t accepted = metrics->totalAccepted;
    if (generated > 0) {
        metrics->acceptanceRate = (double)accepted / (double)generated;
    }
    
    // Update suggestion utility
    if (generatedLines > 0) {
        double currentUtility = metrics->suggestionUtility;
        double newUtility = (currentUtility * (generated - 1) + (double)acceptedLines / generatedLines) / generated;
        InterlockedExchange64((LONG64*)&metrics->suggestionUtility, *(LONG64*)&newUtility);
    }
    
    // Track per-language stats
    if (fileExtension && wcslen(fileExtension) > 0) {
        EnterCriticalSection(&g_telemetry.memoryLock);
        
        bool found = false;
        for (uint32_t i = 0; i < metrics->languageCount && i < 10; i++) {
            if (wcsncmp(metrics->byLanguage[i].extension, fileExtension, 7) == 0) {
                metrics->byLanguage[i].generated++;
                if (type == STEL_EVENT_GHOSTTEXT_ACCEPTED) {
                    metrics->byLanguage[i].accepted++;
                }
                if (metrics->byLanguage[i].generated > 0) {
                    metrics->byLanguage[i].acceptanceRate = 
                        (double)metrics->byLanguage[i].accepted / (double)metrics->byLanguage[i].generated;
                }
                found = true;
                break;
            }
        }
        
        if (!found && metrics->languageCount < 10) {
            uint32_t idx = metrics->languageCount++;
            wcsncpy_s(metrics->byLanguage[idx].extension, 8, fileExtension, 7);
            metrics->byLanguage[idx].generated = 1;
            metrics->byLanguage[idx].accepted = (type == STEL_EVENT_GHOSTTEXT_ACCEPTED) ? 1 : 0;
            metrics->byLanguage[idx].acceptanceRate = metrics->byLanguage[idx].accepted ? 1.0 : 0.0;
        }
        
        LeaveCriticalSection(&g_telemetry.memoryLock);
    }
}

void STEL_GetGhostTextMetrics(STEL_GhostTextMetrics* outMetrics) {
    if (!outMetrics) return;
    memcpy(outMetrics, &g_telemetry.ghostTextMetrics, sizeof(STEL_GhostTextMetrics));
}

void STEL_GetLatencyHistogram(STEL_LatencyMetric metric, STEL_LatencyHistogram* outHistogram) {
    if (!outHistogram || metric < 0 || metric >= STEL_LATENCY_COUNT) return;
    
    memcpy(outHistogram, &g_telemetry.histograms[metric], sizeof(STEL_LatencyHistogram));
    STEL_CalculatePercentiles(outHistogram);
}

void STEL_GetCurrentMemory(STEL_MemorySnapshot* outSnapshot) {
    if (!outSnapshot) return;
    
    // Get current memory info
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        outSnapshot->timestamp = STEL_GetTimestampMicros();
        outSnapshot->rssMB = pmc.WorkingSetSize / (1024 * 1024);
        outSnapshot->virtualMemoryMB = pmc.PagefileUsage / (1024 * 1024);
        outSnapshot->gpuMemoryMB = 0; // TODO: Query GPU memory if applicable
        outSnapshot->kvCacheMB = 0;     // TODO: Track from inference engine
        outSnapshot->arenaUsageMB = 0;  // TODO: Track from allocator
        outSnapshot->numActiveContexts = 1;
        outSnapshot->numLoadedModels = g_telemetry.currentModel[0] ? 1 : 0;
    }
}

void STEL_GenerateSessionSummary(STEL_SessionSummary* outSummary) {
    if (!outSummary) return;
    
    ZeroMemory(outSummary, sizeof(STEL_SessionSummary));
    
    outSummary->sessionStart = g_telemetry.sessionStart;
    outSummary->sessionEnd = STEL_GetTimestampMicros();
    outSummary->durationSeconds = (outSummary->sessionEnd - outSummary->sessionStart) / 1000000;
    
    outSummary->totalInferences = g_telemetry.totalInferences.load();
    outSummary->totalTokensGenerated = g_telemetry.totalTokens.load();
    
    uint64_t count = g_telemetry.totalInferences.load();
    if (count > 0) {
        outSummary->avgTokensPerSecond = g_telemetry.tokensPerSecondSum.load() / count;
    }
    
    // Get latency percentiles
    STEL_LatencyHistogram hist;
    STEL_GetLatencyHistogram(STEL_LATENCY_FIRST_TOKEN, &hist);
    outSummary->firstTokenP50 = hist.p50;
    outSummary->firstTokenP95 = hist.p95;
    outSummary->firstTokenP99 = hist.p99;
    
    outSummary->peakMemoryMB = g_telemetry.peakMemoryMB.load();
    
    // GhostText summary
    STEL_GhostTextMetrics gt;
    STEL_GetGhostTextMetrics(&gt);
    outSummary->ghostTextAcceptanceRate = gt.acceptanceRate;
    outSummary->ghostTextGenerated = gt.totalGenerated;
    outSummary->ghostTextAccepted = gt.totalAccepted;
    
    // Model info
    wcsncpy_s(outSummary->primaryModel, STEL_MAX_STRING_LEN, g_telemetry.currentModel, STEL_MAX_STRING_LEN - 1);
    wcsncpy_s(outSummary->primaryQuantization, 16, g_telemetry.currentQuantization, 15);
    outSummary->modelLoadCount = g_telemetry.modelLoadCount.load();
    outSummary->modelUnloadCount = g_telemetry.modelUnloadCount.load();
}

void STEL_GetRuntimeOverlayString(WCHAR* outBuffer, size_t bufferSize) {
    if (!outBuffer || bufferSize == 0) return;
    
    STEL_SessionSummary summary;
    STEL_GenerateSessionSummary(&summary);
    
    STEL_GhostTextMetrics gt;
    STEL_GetGhostTextMetrics(&gt);
    
    // Format: "28.4 tok/s | 87ms p50 | 68% accept | 3.2GB"
    swprintf_s(outBuffer, bufferSize, 
        L"%.1f tok/s | %.0fms p50 | %.0f%% accept | %.1fGB",
        summary.avgTokensPerSecond,
        summary.firstTokenP50,
        gt.acceptanceRate * 100.0,
        (double)summary.peakMemoryMB / 1024.0);
}

BOOL STEL_ExportToJSON(const WCHAR* filePath) {
    if (!filePath) return FALSE;
    
    FILE* fp;
    if (_wfopen_s(&fp, filePath, L"w") != 0 || !fp) {
        return FALSE;
    }
    
    STEL_SessionSummary summary;
    STEL_GenerateSessionSummary(&summary);
    
    STEL_GhostTextMetrics gt;
    STEL_GetGhostTextMetrics(&gt);
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"version\": %d,\n", STEL_VERSION);
    fprintf(fp, "  \"sessionId\": \"%llu\",\n", (unsigned long long)g_telemetry.sessionId.load());
    fprintf(fp, "  \"durationSeconds\": %llu,\n", (unsigned long long)summary.durationSeconds);
    fprintf(fp, "  \"inference\": {\n");
    fprintf(fp, "    \"totalInferences\": %llu,\n", (unsigned long long)summary.totalInferences);
    fprintf(fp, "    \"totalTokensGenerated\": %llu,\n", (unsigned long long)summary.totalTokensGenerated);
    fprintf(fp, "    \"avgTokensPerSecond\": %.2f,\n", summary.avgTokensPerSecond);
    fprintf(fp, "    \"firstTokenLatencyP50\": %.2f,\n", summary.firstTokenP50);
    fprintf(fp, "    \"firstTokenLatencyP95\": %.2f,\n", summary.firstTokenP95);
    fprintf(fp, "    \"firstTokenLatencyP99\": %.2f\n", summary.firstTokenP99);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"ghostText\": {\n");
    fprintf(fp, "    \"totalGenerated\": %llu,\n", (unsigned long long)gt.totalGenerated);
    fprintf(fp, "    \"totalAccepted\": %llu,\n", (unsigned long long)gt.totalAccepted);
    fprintf(fp, "    \"totalRejected\": %llu,\n", (unsigned long long)gt.totalRejected);
    fprintf(fp, "    \"acceptanceRate\": %.4f,\n", gt.acceptanceRate);
    fprintf(fp, "    \"avgTimeToAcceptanceMs\": %.2f,\n", gt.avgTimeToAcceptanceMs);
    fprintf(fp, "    \"suggestionUtility\": %.4f\n", gt.suggestionUtility);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"memory\": {\n");
    fprintf(fp, "    \"peakMB\": %llu,\n", (unsigned long long)summary.peakMemoryMB);
    fprintf(fp, "    \"modelLoads\": %u,\n", summary.modelLoadCount);
    fprintf(fp, "    \"modelUnloads\": %u\n", summary.modelUnloadCount);
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    return TRUE;
}

void STEL_SetEnabled(BOOL enabled) {
    g_telemetry.enabled = enabled;
}

BOOL STEL_IsEnabled(void) {
    return g_telemetry.enabled.load();
}

void STEL_Reset(void) {
    if (!g_telemetry.initialized.load()) return;
    
    g_telemetry.writeIndex = 0;
    g_telemetry.readIndex = 0;
    
    for (int i = 0; i < STEL_LATENCY_COUNT; i++) {
        ZeroMemory(&g_telemetry.histograms[i], sizeof(STEL_LatencyHistogram));
        g_telemetry.histograms[i].minMs = 999999.0;
    }
    
    ZeroMemory(&g_telemetry.ghostTextMetrics, sizeof(STEL_GhostTextMetrics));
    
    EnterCriticalSection(&g_telemetry.memoryLock);
    g_telemetry.memoryHistory.clear();
    LeaveCriticalSection(&g_telemetry.memoryLock);
    
    g_telemetry.totalInferences = 0;
    g_telemetry.totalTokens = 0;
    g_telemetry.tokensPerSecondSum = 0.0;
    g_telemetry.peakMemoryMB = 0;
    g_telemetry.modelLoadCount = 0;
    g_telemetry.modelUnloadCount = 0;
}
