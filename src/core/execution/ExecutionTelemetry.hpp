// ============================================================================
// Execution Telemetry
// ============================================================================
// Performance metrics for RawrXD inference execution
// ============================================================================

#pragma once

#include <cstdint>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Execution Telemetry Structure
// ============================================================================
// Captures timing, throughput, and resource usage
// ============================================================================

struct ExecutionTelemetry {
    // Timing (milliseconds)
    uint64_t latency_ms = 0;           // Total wall-clock time
    uint64_t time_to_first_token_ms = 0;  // TTFT
    
    // Token counts
    uint32_t prompt_tokens = 0;
    uint32_t generated_tokens = 0;
    
    // Throughput
    double tokens_per_second = 0.0;
    double prompt_tokens_per_second = 0.0;  // Prompt processing rate
    
    // Memory (bytes)
    uint64_t peak_memory_bytes = 0;
    uint64_t model_memory_bytes = 0;
    uint64_t kv_cache_memory_bytes = 0;
    
    // Kernel timing (microseconds) - for GPU backends
    uint64_t kernel_time_us = 0;
    uint64_t io_time_us = 0;
    uint64_t overhead_time_us = 0;
    
    // Stage breakdown (microseconds)
    uint64_t tokenize_time_us = 0;
    uint64_t inference_time_us = 0;
    uint64_t sampling_time_us = 0;
    uint64_t detokenize_time_us = 0;
    
    // Calculate derived metrics
    void CalculateDerived() {
        if (latency_ms > 0 && generated_tokens > 0) {
            tokens_per_second = (generated_tokens * 1000.0) / latency_ms;
        }
        if (prompt_tokens > 0 && time_to_first_token_ms > 0) {
            prompt_tokens_per_second = (prompt_tokens * 1000.0) / time_to_first_token_ms;
        }
    }
};

} // namespace Execution
} // namespace RawrXD
