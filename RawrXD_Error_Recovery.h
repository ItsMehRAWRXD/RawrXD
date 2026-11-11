/* RawrXD_Error_Recovery.h
 * C/C++ interface for error recovery and self-healing
 */

#ifndef RAWRXD_ERROR_RECOVERY_H
#define RAWRXD_ERROR_RECOVERY_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * Error Codes
 * ============================================================================= */
typedef enum {
    ERR_NONE = 0,
    ERR_OUT_OF_MEMORY = 0xE001,
    ERR_MODEL_LOAD_FAILED = 0xE002,
    ERR_INFERENCE_TIMEOUT = 0xE003,
    ERR_INVALID_INPUT = 0xE004,
    ERR_KV_CACHE_FULL = 0xE005,
    ERR_GPU_OOM = 0xE006,
    ERR_NETWORK_TIMEOUT = 0xE007,
    ERR_WORKER_DIED = 0xE008,
    ERR_NO_RESPONSE = 0xE009,           /* No response from model/service */
    ERR_AUTOPILOT_RECOVERY = 0xE00A     /* Autopilot recovered from error */
} SovereignErrorCode;

/* =============================================================================
 * Circuit Breaker States
 * ============================================================================= */
typedef enum {
    CB_STATE_CLOSED = 0,      /* Normal operation */
    CB_STATE_OPEN = 1,          /* Failing fast */
    CB_STATE_HALF_OPEN = 2      /* Testing recovery */
} CircuitBreakerState;

/* =============================================================================
 * Recovery Statistics
 * ============================================================================= */
typedef struct {
    uint64_t total_requests;
    uint64_t successful_requests;
    uint64_t failed_requests;
    uint64_t recovered_requests;
    uint64_t no_response_count;          /* Count of "no response" scenarios */
    uint64_t autopilot_recoveries;       /* Count of autopilot recoveries */
    int32_t  cb_state;
    bool     fallback_active;
    bool     autopilot_recovery_active;  /* Currently in autopilot recovery */
} RecoveryStats;

/* =============================================================================
 * Function Types
 * ============================================================================= */

/* Operation function signature for retry wrapper */
typedef int (*RecoveryOperationFunc)(void* context);

/* =============================================================================
 * API Functions
 * ============================================================================= */

/**
 * Initialize error recovery system
 * @param max_retries Maximum retry attempts (0 = use default of 5)
 * @param enable_fallback Enable fallback to degraded mode
 * @param enable_circuit_breaker Enable circuit breaker pattern
 * @return 1 on success, 0 on failure
 */
int Recovery_Init(int max_retries, bool enable_fallback, bool enable_circuit_breaker);

/**
 * Execute operation with automatic retry logic
 * @param operation Function to execute
 * @param context Context pointer passed to operation
 * @return 1 on success (possibly after retries), 0 on failure
 */
int Recovery_ExecuteWithRetry(RecoveryOperationFunc operation, void* context);

/**
 * Check current circuit breaker state
 * @return Current CB_STATE_* value
 */
int Recovery_CheckCircuitBreaker(void);

/**
 * Get error recovery statistics
 * @param stats Pointer to stats structure to fill
 */
void Recovery_GetStats(RecoveryStats* stats);

/**
 * Reset error recovery state
 * Clears counters and resets circuit breaker to closed
 */
void Recovery_Reset(void);

/**
 * Check if fallback mode is active
 * @return true if running in fallback/degraded mode
 */
bool Recovery_IsFallbackActive(void);

/**
 * Get last error code
 * @return Last error code encountered
 */
int Recovery_GetLastError(void);

/**
 * Get error message for code
 * @param error_code Error code
 * @return Human-readable error message
 */
const char* Recovery_GetErrorMessage(int error_code);

/**
 * Handle "no response" scenario with autopilot recovery
 * @param request_id Unique request identifier
 * @return 1 if recovery initiated, 0 if failed
 */
int Recovery_HandleNoResponse(uint64_t request_id);

/**
 * Check if autopilot is currently in recovery mode
 * @return true if autopilot recovery is active
 */
bool Recovery_IsAutopilotRecovery(void);

/**
 * Acknowledge autopilot recovery completion
 * Call this after handling a recovered request
 */
void Recovery_AcknowledgeAutopilot(void);

/**
 * Get current retry delay with exponential backoff
 * @return Delay in milliseconds
 */
uint32_t Recovery_GetRetryDelay(void);

/**
 * Configure autopilot behavior
 * @param max_autopilot_attempts Maximum autopilot recovery attempts
 * @param autopilot_timeout_ms Timeout for autopilot recovery
 */
void Recovery_ConfigureAutopilot(int max_autopilot_attempts, uint32_t autopilot_timeout_ms);

/* =============================================================================
 * Convenience Macros
 * ============================================================================= */

/* Execute with retry and automatic error handling */
#define SOVEREIGN_EXECUTE_WITH_RETRY(operation, context) \
    Recovery_ExecuteWithRetry((RecoveryOperationFunc)(operation), (context))

/* Check if operation should proceed (circuit breaker) */
#define SOVEREIGN_SHOULD_PROCEED() \
    (Recovery_CheckCircuitBreaker() == CB_STATE_CLOSED)

/* Get recovery success rate as percentage */
#define SOVEREIGN_RECOVERY_RATE(stats) \
    ((stats)->total_requests > 0 ? \
     (int)(((stats)->successful_requests + (stats)->recovered_requests) * 100 / (stats)->total_requests) : 0)

/* Handle "no response" scenario */
#define SOVEREIGN_NO_RESPONSE(req_id) \
    Recovery_HandleNoResponse(req_id)

/* Check if autopilot is recovering */
#define SOVEREIGN_AUTOPILOT_ACTIVE() \
    Recovery_IsAutopilotRecovery()

/* Acknowledge autopilot recovery */
#define SOVEREIGN_AUTOPILOT_ACK() \
    Recovery_AcknowledgeAutopilot()

/* Get current retry delay */
#define SOVEREIGN_RETRY_DELAY() \
    Recovery_GetRetryDelay()

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RAWRXD_ERROR_RECOVERY_H */
