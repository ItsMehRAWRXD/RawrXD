// =============================================================================
// sovereign_telemetry_amx.cpp
// Phase 18B: AMX Utilization Telemetry Implementation
// =============================================================================

#include "sovereign_telemetry_amx.h"
#include "sovereign_hybrid_scheduler.h"
#include <windows.h>
#include <cstdio>
#include <string>
#include <atomic>

// =============================================================================
// Telemetry State
// =============================================================================

static struct {
    std::atomic<int> initialized{0};
    std::atomic<int> enabled{1};
    
    // Ring buffer
    AMXTelemetryEntry buffer[AMX_TELEMETRY_BUFFER_SIZE];
    std::atomic<uint64_t> writeIndex{0};
    std::atomic<uint64_t> readIndex{0};
    
    // Statistics
    std::atomic<uint64_t> totalEvents{0};
    std::atomic<uint64_t> amxKernelsExecuted{0};
    std::atomic<uint64_t> avx512KernelsExecuted{0};
    std::atomic<uint64_t> totalLatencyUs{0};  // For average calculation
    std::atomic<uint64_t> totalSpeedupNumerator{0};  // Sum of (AVX latency / AMX latency)
    std::atomic<uint64_t> speedupSamples{0};
    
    // Performance counters
    LARGE_INTEGER qpcFrequency;
    HANDLE flushThread{nullptr};
    HANDLE flushEvent{nullptr};
    
    // File output
    FILE* outputFile{nullptr};
    char outputPath[MAX_PATH];
} g_telemetry;

// =============================================================================
// Internal Functions
// =============================================================================

static uint64_t GetTimestamp() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (uint64_t)now.QuadPart;
}

static void WriteEntryToFile(const AMXTelemetryEntry* entry) {
    if (!g_telemetry.outputFile) return;
    
    fprintf(g_telemetry.outputFile,
        "%llu,%u,%u,%u,%u,%u,%u,%u,%.3f,%.2f,%u,%u\n",
        entry->timestamp,
        entry->eventType,
        entry->workloadType,
        entry->selectedPath,
        entry->reason,
        entry->matrixRows,
        entry->matrixCols,
        entry->batchSize,
        entry->latencyMs,
        entry->throughputGFlops,
        entry->tileUtilization,
        entry->flags
    );
    
    // Flush periodically
    static int flushCounter = 0;
    if (++flushCounter >= 100) {
        fflush(g_telemetry.outputFile);
        flushCounter = 0;
    }
}

static DWORD WINAPI FlushThreadProc(LPVOID lpParam) {
    (void)lpParam;
    
    while (WaitForSingleObject(g_telemetry.flushEvent, 100) == WAIT_TIMEOUT) {
        // Periodic flush
        Sovereign_AMX_Telemetry_Flush();
    }
    
    // Final flush on exit
    Sovereign_AMX_Telemetry_Flush();
    return 0;
}

// =============================================================================
// Public API Implementation
// =============================================================================

__declspec(dllexport) int Sovereign_AMX_Telemetry_Init(void) {
    if (g_telemetry.initialized.exchange(1)) {
        return 0;  // Already initialized
    }
    
    QueryPerformanceFrequency(&g_telemetry.qpcFrequency);
    
    // Create output file
    const char* telemetryDir = getenv("SOVEREIGN_TELEMETRY_DIR");
    if (!telemetryDir) {
        telemetryDir = "./telemetry";
    }
    
    CreateDirectoryA(telemetryDir, nullptr);
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(g_telemetry.outputPath, MAX_PATH,
        "%s/amx_telemetry_%04d%02d%02d_%02d%02d%02d.csv",
        telemetryDir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    g_telemetry.outputFile = fopen(g_telemetry.outputPath, "w");
    if (g_telemetry.outputFile) {
        // Write CSV header
        fprintf(g_telemetry.outputFile,
            "timestamp,event_type,workload_type,selected_path,reason,"
            "matrix_rows,matrix_cols,batch_size,latency_ms,throughput_gflops,"
            "tile_utilization,flags\n");
        fflush(g_telemetry.outputFile);
    }
    
    // Create flush event and thread
    g_telemetry.flushEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (g_telemetry.flushEvent) {
        g_telemetry.flushThread = CreateThread(nullptr, 0, FlushThreadProc, nullptr, 0, nullptr);
    }
    
    return 0;
}

__declspec(dllexport) void Sovereign_AMX_Telemetry_Shutdown(void) {
    if (!g_telemetry.initialized.load()) return;
    
    // Signal flush thread to exit
    if (g_telemetry.flushEvent) {
        SetEvent(g_telemetry.flushEvent);
        if (g_telemetry.flushThread) {
            WaitForSingleObject(g_telemetry.flushThread, 5000);
            CloseHandle(g_telemetry.flushThread);
        }
        CloseHandle(g_telemetry.flushEvent);
    }
    
    // Final flush
    Sovereign_AMX_Telemetry_Flush();
    
    // Close file
    if (g_telemetry.outputFile) {
        fclose(g_telemetry.outputFile);
        g_telemetry.outputFile = nullptr;
    }
    
    g_telemetry.initialized = 0;
}

__declspec(dllexport) void Sovereign_AMX_Telemetry_Record(
    AMXTelemetryEventType eventType,
    uint32_t workloadType,
    uint32_t selectedPath,
    PathSelectionReason reason,
    uint32_t rows,
    uint32_t cols,
    uint32_t batchSize,
    float latencyMs,
    float throughputGFlops
) {
    if (!g_telemetry.enabled.load() || !g_telemetry.initialized.load()) return;
    
    // Get write position
    uint64_t index = g_telemetry.writeIndex.fetch_add(1);
    uint64_t slot = index % AMX_TELEMETRY_BUFFER_SIZE;
    
    // Fill entry
    AMXTelemetryEntry* entry = &g_telemetry.buffer[slot];
    entry->timestamp = GetTimestamp();
    entry->eventType = (uint32_t)eventType;
    entry->workloadType = workloadType;
    entry->selectedPath = selectedPath;
    entry->reason = (uint32_t)reason;
    entry->matrixRows = rows;
    entry->matrixCols = cols;
    entry->batchSize = batchSize;
    entry->latencyMs = latencyMs;
    entry->throughputGFlops = throughputGFlops;
    entry->tileUtilization = 0;  // Calculated separately
    entry->flags = 0;
    
    // Update statistics
    g_telemetry.totalEvents.fetch_add(1);
    
    if (selectedPath == SOVEREIGN_PATH_AMX_TILE) {
        g_telemetry.amxKernelsExecuted.fetch_add(1);
    } else if (selectedPath == SOVEREIGN_PATH_AVX512_FMA || 
               selectedPath == SOVEREIGN_PATH_AVX512_VNNI) {
        g_telemetry.avx512KernelsExecuted.fetch_add(1);
    }
    
    if (latencyMs > 0) {
        g_telemetry.totalLatencyUs.fetch_add((uint64_t)(latencyMs * 1000));
    }
    
    // Write to file immediately for critical events
    if (eventType == AMX_EVENT_ERROR || eventType == AMX_EVENT_FALLBACK) {
        WriteEntryToFile(entry);
    }
}

__declspec(dllexport) uint32_t Sovereign_AMX_GetUtilization(void) {
    uint64_t total = g_telemetry.totalEvents.load();
    uint64_t amx = g_telemetry.amxKernelsExecuted.load();
    
    if (total == 0) return 0;
    
    // Calculate AMX utilization as percentage of compute-heavy operations
    uint64_t computeOps = amx + g_telemetry.avx512KernelsExecuted.load();
    if (computeOps == 0) return 0;
    
    return (uint32_t)((amx * 100) / computeOps);
}

__declspec(dllexport) void Sovereign_AMX_Telemetry_GetStats(
    uint64_t* totalEvents,
    uint64_t* amxKernelsExecuted,
    uint64_t* avx512KernelsExecuted,
    float* avgSpeedupVsAVX512
) {
    if (totalEvents) *totalEvents = g_telemetry.totalEvents.load();
    if (amxKernelsExecuted) *amxKernelsExecuted = g_telemetry.amxKernelsExecuted.load();
    if (avx512KernelsExecuted) *avx512KernelsExecuted = g_telemetry.avx512KernelsExecuted.load();
    
    if (avgSpeedupVsAVX512) {
        uint64_t samples = g_telemetry.speedupSamples.load();
        if (samples > 0) {
            *avgSpeedupVsAVX512 = (float)(g_telemetry.totalSpeedupNumerator.load() / samples);
        } else {
            *avgSpeedupVsAVX512 = 0.0f;
        }
    }
}

__declspec(dllexport) void Sovereign_AMX_Telemetry_Flush(void) {
    if (!g_telemetry.outputFile) return;
    
    uint64_t writeIdx = g_telemetry.writeIndex.load();
    uint64_t readIdx = g_telemetry.readIndex.load();
    
    // Write all pending entries
    while (readIdx < writeIdx) {
        uint64_t slot = readIdx % AMX_TELEMETRY_BUFFER_SIZE;
        WriteEntryToFile(&g_telemetry.buffer[slot]);
        readIdx++;
    }
    
    g_telemetry.readIndex.store(readIdx);
    fflush(g_telemetry.outputFile);
}

__declspec(dllexport) void Sovereign_AMX_Telemetry_SetEnabled(int enabled) {
    g_telemetry.enabled.store(enabled ? 1 : 0);
}

__declspec(dllexport) int Sovereign_AMX_Telemetry_IsEnabled(void) {
    return g_telemetry.enabled.load();
}
