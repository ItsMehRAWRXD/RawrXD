// =============================================================================
// sovereign_telemetry_amx.h
// Phase 18B: AMX Utilization Telemetry Hooks
//
// Provides instrumentation for:
// - AMX tile utilization counters
// - Path selection telemetry
// - Performance regression detection
// =============================================================================

#ifndef SOVEREIGN_TELEMETRY_AMX_H
#define SOVEREIGN_TELEMETRY_AMX_H

#include <cstdint>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// AMX Telemetry Event Types
// =============================================================================

typedef enum {
    AMX_EVENT_PATH_SELECTED = 0,      // Hybrid scheduler selected path
    AMX_EVENT_KERNEL_START = 1,      // AMX kernel execution started
    AMX_EVENT_KERNEL_END = 2,        // AMX kernel execution completed
    AMX_EVENT_FALLBACK = 3,          // Fallback from AMX to AVX-512
    AMX_EVENT_ERROR = 4,             // AMX execution error
    AMX_EVENT_TILE_CONFIG = 5,       // Tile configuration changed
    AMX_EVENT_COUNT = 6
} AMXTelemetryEventType;

// =============================================================================
// Path Selection Reasons
// =============================================================================

typedef enum {
    PATH_REASON_FIRST_CALL = 0,      // First time, no profiling data
    PATH_REASON_PROFILING = 1,       // Based on profiling data
    PATH_REASON_MATRIX_SIZE = 2,     // Matrix size threshold
    PATH_REASON_CPU_FEATURES = 3,    // CPU feature availability
    PATH_REASON_USER_OVERRIDE = 4,   // User forced path
    PATH_REASON_ERROR_RECOVERY = 5,  // Recovered from error
    PATH_REASON_COUNT = 6
} PathSelectionReason;

// =============================================================================
// Telemetry Entry Structure
// =============================================================================

#pragma pack(push, 1)
typedef struct {
    uint64_t timestamp;              // QPC timestamp
    uint32_t eventType;              // AMXTelemetryEventType
    uint32_t workloadType;         // SovereignWorkloadType
    uint32_t selectedPath;         // SovereignComputePath
    uint32_t reason;               // PathSelectionReason
    uint32_t matrixRows;           // Matrix dimensions
    uint32_t matrixCols;
    uint32_t batchSize;
    float latencyMs;               // Measured latency
    float throughputGFlops;        // Calculated throughput
    uint32_t tileUtilization;      // Tile utilization % (0-100)
    uint32_t flags;                // Additional flags
} AMXTelemetryEntry;
#pragma pack(pop)

// =============================================================================
// Ring Buffer Configuration
// =============================================================================

#define AMX_TELEMETRY_BUFFER_SIZE 16384  // 16K entries
#define AMX_TELEMETRY_BATCH_SIZE 64      // Batch write threshold

// =============================================================================
// API Functions
// =============================================================================

// Initialize AMX telemetry subsystem
__declspec(dllexport) int Sovereign_AMX_Telemetry_Init(void);

// Shutdown and flush telemetry
__declspec(dllexport) void Sovereign_AMX_Telemetry_Shutdown(void);

// Record a telemetry event
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
);

// Get current AMX utilization percentage
__declspec(dllexport) uint32_t Sovereign_AMX_GetUtilization(void);

// Get telemetry statistics
__declspec(dllexport) void Sovereign_AMX_Telemetry_GetStats(
    uint64_t* totalEvents,
    uint64_t* amxKernelsExecuted,
    uint64_t* avx512KernelsExecuted,
    float* avgSpeedupVsAVX512
);

// Flush telemetry buffer to disk
__declspec(dllexport) void Sovereign_AMX_Telemetry_Flush(void);

// Enable/disable telemetry collection
__declspec(dllexport) void Sovereign_AMX_Telemetry_SetEnabled(int enabled);

// Check if telemetry is enabled
__declspec(dllexport) int Sovereign_AMX_Telemetry_IsEnabled(void);

// =============================================================================
// Inline Helper Macros
// =============================================================================

#ifdef SOVEREIGN_AMX_INSTRUMENTATION
    #define AMX_TELEMETRY_RECORD(event, workload, path, reason, rows, cols, batch, latency, flops) \
        Sovereign_AMX_Telemetry_Record(event, workload, path, reason, rows, cols, batch, latency, flops)
    #define AMX_TELEMETRY_PATH_SELECTED(workload, path, reason, rows, cols, batch) \
        Sovereign_AMX_Telemetry_Record(AMX_EVENT_PATH_SELECTED, workload, path, reason, rows, cols, batch, 0.0f, 0.0f)
    #define AMX_TELEMETRY_KERNEL_START(workload, rows, cols, batch) \
        Sovereign_AMX_Telemetry_Record(AMX_EVENT_KERNEL_START, workload, SOVEREIGN_PATH_AMX_TILE, PATH_REASON_PROFILING, rows, cols, batch, 0.0f, 0.0f)
    #define AMX_TELEMETRY_KERNEL_END(workload, latency, flops) \
        Sovereign_AMX_Telemetry_Record(AMX_EVENT_KERNEL_END, workload, SOVEREIGN_PATH_AMX_TILE, PATH_REASON_PROFILING, 0, 0, 0, latency, flops)
    #define AMX_TELEMETRY_FALLBACK(workload, reason) \
        Sovereign_AMX_Telemetry_Record(AMX_EVENT_FALLBACK, workload, SOVEREIGN_PATH_AVX512_FMA, reason, 0, 0, 0, 0.0f, 0.0f)
#else
    #define AMX_TELEMETRY_RECORD(event, workload, path, reason, rows, cols, batch, latency, flops) ((void)0)
    #define AMX_TELEMETRY_PATH_SELECTED(workload, path, reason, rows, cols, batch) ((void)0)
    #define AMX_TELEMETRY_KERNEL_START(workload, rows, cols, batch) ((void)0)
    #define AMX_TELEMETRY_KERNEL_END(workload, latency, flops) ((void)0)
    #define AMX_TELEMETRY_FALLBACK(workload, reason) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_TELEMETRY_AMX_H
