/* RawrXD_Telemetry.h
 * C/C++ Header for RawrXD Telemetry Integration
 * Pure C interface for interoperability
 */

#ifndef RAWRXD_TELEMETRY_H
#define RAWRXD_TELEMETRY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * Metric Type Constants
 * ============================================================================= */
typedef enum {
    METRIC_NONE = 0,
    METRIC_INFERENCE_START = 1,
    METRIC_INFERENCE_END = 2,
    METRIC_TOKEN_GENERATED = 3,
    METRIC_CACHE_HIT = 4,
    METRIC_CACHE_MISS = 5,
    METRIC_PRECISION_SWITCH = 6,
    METRIC_SECURITY_EVENT = 7
} MetricType;

/* =============================================================================
 * Quantization Type Constants
 * ============================================================================= */
typedef enum {
    QUANT_INT8 = 0,
    QUANT_BF16 = 1,
    QUANT_FP32 = 2
} QuantizationType;

/* =============================================================================
 * Telemetry Statistics Structure
 * ============================================================================= */
typedef struct {
    uint64_t total_inferences;      /* Total inference requests */
    uint64_t total_tokens;            /* Total tokens generated */
    uint64_t total_latency_us;        /* Cumulative latency in microseconds */
    uint32_t avg_latency_us;          /* Average latency per inference */
    uint32_t current_session_tokens;  /* Tokens in current session */
    uint32_t session_cache_hits;      /* Cache hits this session */
    uint32_t session_cache_misses;    /* Cache misses this session */
    uint8_t  current_quant_type;      /* Current quantization type */
} TelemetryStats;

/* =============================================================================
 * Core Telemetry API
 * ============================================================================= */

/**
 * Initialize telemetry subsystem
 * Creates memory-mapped buffer and prepares logging
 * @return 1 on success, 0 on failure
 */
int Telemetry_Init(void);

/**
 * Log a telemetry event
 * @param metric_type Type of event (see MetricType enum)
 * @param session_id Session identifier
 * @param count Token count or cache line ID
 * @param latency_us Latency in microseconds
 */
void Telemetry_LogEvent(int metric_type, int session_id, int count, int latency_us);

/**
 * Flush telemetry buffer to consumers
 * Called periodically to ensure metrics are visible
 */
void Telemetry_Flush(void);

/**
 * Get current telemetry statistics
 * @param stats Pointer to TelemetryStats structure to fill
 */
void Telemetry_GetStats(TelemetryStats* stats);

/**
 * Shutdown telemetry subsystem
 * Closes memory-mapped file and releases resources
 */
void Telemetry_Shutdown(void);

/* =============================================================================
 * Sovereign Engine Integration API
 * ============================================================================= */

/**
 * Initialize Sovereign Engine telemetry
 * Must be called before any inference operations
 * @return 1 on success, 0 on failure
 */
int Sovereign_Telemetry_Init(void);

/**
 * Begin inference session
 * @param prompt_length Length of input prompt in tokens
 * @return Session ID for tracking
 */
int Sovereign_Inference_Begin(int prompt_length);

/**
 * End inference session
 * Logs completion metrics and returns token count
 * @return Total tokens generated in session
 */
int Sovereign_Inference_End(void);

/**
 * Log token generation event
 * @param token_id Generated token ID
 * @param latency_us Generation latency in microseconds
 */
void Sovereign_Token_Generated(int token_id, int latency_us);

/**
 * Log cache access event
 * @param cache_line_id Cache line identifier
 * @param is_hit 1 if cache hit, 0 if miss
 */
void Sovereign_Cache_Access(int cache_line_id, int is_hit);

/**
 * Log precision switch event
 * @param quant_type New quantization type (0=INT8, 1=BF16, 2=FP32)
 */
void Sovereign_Precision_Switch(int quant_type);

/**
 * Get comprehensive telemetry statistics
 * @param stats Pointer to TelemetryStats structure
 */
void Sovereign_GetTelemetryStats(TelemetryStats* stats);

/* =============================================================================
 * Convenience Macros
 * ============================================================================= */

/* Quick inference timing macro */
#define SOVEREIGN_TIMED_INFERENCE(prompt_len, code) \
    do { \
        int __session = Sovereign_Inference_Begin(prompt_len); \
        (void)__session; /* Suppress unused warning */ \
        code; \
        Sovereign_Inference_End(); \
    } while(0)

/* Token generation with automatic latency tracking */
#define SOVEREIGN_GENERATE_TOKEN(token_id, start_cycles) \
    do { \
        uint64_t __end = __rdtsc(); \
        uint64_t __latency = (__end - (start_cycles)) / 3; /* Approx us @ 3GHz */ \
        Sovereign_Token_Generated((token_id), (int)__latency); \
    } while(0)

/* Cache access macros */
#define SOVEREIGN_CACHE_HIT(line_id) Sovereign_Cache_Access((line_id), 1)
#define SOVEREIGN_CACHE_MISS(line_id) Sovereign_Cache_Access((line_id), 0)

/* Precision switch macros */
#define SOVEREIGN_USE_INT8() Sovereign_Precision_Switch(QUANT_INT8)
#define SOVEREIGN_USE_BF16() Sovereign_Precision_Switch(QUANT_BF16)
#define SOVEREIGN_USE_FP32() Sovereign_Precision_Switch(QUANT_FP32)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RAWRXD_TELEMETRY_H */
