/*===========================================================================
 * AdaptiveContextController.h
 * VAL-028: Adaptive Runtime Optimization
 * 
 * Dynamic context window sizing based on telemetry signals.
 * Lock-free, bare-metal implementation for zero-latency overhead.
 *
 * Strategy: VirtualUnlock for soft pressure, EmergencyFlush for hard pressure
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *=========================================================================*/
#define ADAPTIVE_VERSION                 1

// Context window sizes (tokens)
#define AC_WINDOW_SURVIVAL               1024    // Emergency mode
#define AC_WINDOW_EFFICIENT                2048    // Small files, low pressure
#define AC_WINDOW_DEFAULT                  4096    // Safe default
#define AC_WINDOW_PERFORMANCE              8192    // High acceptance, low pressure
#define AC_WINDOW_EMERGENCY_FLOOR        512     // Hard minimum

// Memory pressure thresholds
#define AC_PRESSURE_SURVIVAL             0.80f   // Trigger VirtualUnlock
#define AC_PRESSURE_EMERGENCY            0.95f   // Trigger synchronous flush
#define AC_PRESSURE_RESTORE              0.50f   // Allow expansion
#define AC_PRESSURE_LOW                  0.30f   // Full performance mode

// Page fault threshold (faults per second)
#define AC_PAGEFAULT_THRESHOLD           1000

// Hysteresis cooldown (milliseconds)
#define AC_HYSTERESIS_COOLDOWN_MS        5000

/*===========================================================================
 * MEMORY METRICS
 *=========================================================================*/
typedef struct AC_MemoryMetrics {
    DWORD       pageFaultCount;         // Total process page faults
    DWORD       pageFaultDelta;         // Delta since last check
    size_t      workingSetBytes;        // Current working set
    size_t      peakWorkingSetBytes;    // Peak working set
    size_t      pagefileUsage;          // Committed memory
    float       memoryPressure;         // 0.0 - 1.0 calculated
    uint64_t    timestampMicros;        // Sample timestamp
} AC_MemoryMetrics;

/*===========================================================================
 * ADAPTIVE STATE
 *=========================================================================*/
typedef enum AC_State {
    AC_STATE_PERFORMANCE = 0,           // Full 8192 tokens
    AC_STATE_DEFAULT,                   // Standard 4096 tokens
    AC_STATE_EFFICIENT,                 // Reduced 2048 tokens
    AC_STATE_SURVIVAL,                  // Minimal 1024 tokens
    AC_STATE_EMERGENCY,                 // Floor 512 tokens + flush
    AC_STATE_COUNT
} AC_State;

/*===========================================================================
 * ADAPTIVE CONTEXT CONTROLLER
 *=========================================================================*/

typedef struct AC_Controller {
    // Telemetry signals (atomic, lock-free)
    std::atomic<float>      memoryPressure;
    std::atomic<float>      acceptanceRate;
    std::atomic<uint32_t>   currentFileSize;      // Lines of code
    std::atomic<uint32_t>   pageFaultRate;        // Faults/sec
    std::atomic<uint32_t>   currentWindow;        // Active context window
    std::atomic<AC_State>   currentState;
    
    // Hysteresis control
    std::atomic<uint64_t>   lastStateChange;      // Timestamp (micros)
    std::atomic<uint32_t>   lastWindow;           // Previous window size
    
    // Configuration
    uint32_t                bytesPerToken;
    size_t                  totalSystemMemory;
    BOOL                    hysteresisEnabled;
    uint32_t                hysteresisCooldownMs;
    
    // Internal
    DWORD                   lastPageFaultCount;
    uint64_t                lastMetricsTime;
} AC_Controller;

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

/* Initialize the adaptive controller
 * totalSysMem: Total physical memory in bytes (0 = auto-detect)
 * bytesPerTok: Bytes per token in KV cache
 * Returns: TRUE on success */
BOOL AC_Initialize(AC_Controller* ctrl, size_t totalSysMem, uint32_t bytesPerTok);

/* Shutdown and cleanup */
void AC_Shutdown(AC_Controller* ctrl);

/* Check if controller is active */
BOOL AC_IsActive(const AC_Controller* ctrl);

/*===========================================================================
 * TELEMETRY INPUTS
 *=========================================================================*/

/* Update memory metrics (call periodically, e.g., 1Hz) */
void AC_UpdateMemoryMetrics(AC_Controller* ctrl);

/* Set acceptance rate from GhostText telemetry (0.0 - 1.0) */
void AC_SetAcceptanceRate(AC_Controller* ctrl, float rate);

/* Set current file size in lines */
void AC_SetFileSize(AC_Controller* ctrl, uint32_t lines);

/* Set current context window from inference engine */
void AC_SetCurrentWindow(AC_Controller* ctrl, uint32_t tokens);

/*===========================================================================
 * DECISION OUTPUTS
 *=========================================================================*/

/* Calculate target context window based on current telemetry
 * Returns: Recommended token count for next inference */
uint32_t AC_GetTargetWindow(const AC_Controller* ctrl);

/* Get current adaptive state */
AC_State AC_GetCurrentState(const AC_Controller* ctrl);

/* Get current memory pressure (0.0 - 1.0) */
float AC_GetMemoryPressure(const AC_Controller* ctrl);

/* Get current page fault rate (faults/sec) */
uint32_t AC_GetPageFaultRate(const AC_Controller* ctrl);

/* Check if state change is allowed (hysteresis) */
BOOL AC_CanChangeState(const AC_Controller* ctrl);

/*===========================================================================
 * STATE MACHINE
 *=========================================================================*/

/* Force a state transition (bypasses hysteresis) */
void AC_ForceState(AC_Controller* ctrl, AC_State newState);

/* Get human-readable state name */
const char* AC_GetStateName(AC_State state);

/* Get recommended window size for a state */
uint32_t AC_GetWindowForState(AC_State state);

/*===========================================================================
 * MEMORY METRICS HELPERS
 *=========================================================================*/

/* Capture current process memory metrics */
BOOL AC_CaptureMemoryMetrics(AC_MemoryMetrics* outMetrics);

/* Calculate memory pressure from metrics (0.0 - 1.0) */
float AC_CalculatePressure(const AC_MemoryMetrics* metrics, size_t totalSystemMemory);

#ifdef __cplusplus
}
#endif
