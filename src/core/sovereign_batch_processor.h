// =============================================================================
// sovereign_batch_processor.h
// Phase 19: Scaling & Concurrency Optimization
// High-throughput batch processing for inference requests
// =============================================================================

#ifndef SOVEREIGN_BATCH_PROCESSOR_H
#define SOVEREIGN_BATCH_PROCESSOR_H

#include "sovereign_thread_pool.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Configuration
// =============================================================================

#define SOVEREIGN_MAX_BATCH_SIZE 256
#define SOVEREIGN_MAX_SEQUENCE_LENGTH 8192
#define SOVEREIGN_PREFETCH_DISTANCE 4

// =============================================================================
// Batch Types
// =============================================================================

typedef enum {
    SOVEREIGN_BATCH_ATTENTION_QK,      // Q × K^T
    SOVEREIGN_BATCH_ATTENTION_SOFTMAX_V, // Softmax(QK) × V
    SOVEREIGN_BATCH_FFN_UP,            // Gate + Up projection
    SOVEREIGN_BATCH_FFN_DOWN,          // Down projection
    SOVEREIGN_BATCH_EMBEDDING,         // Token embedding lookup
    SOVEREIGN_BATCH_RMS_NORM,          // RMS normalization
    SOVEREIGN_BATCH_ROPE,              // Rotary position embedding
    SOVEREIGN_BATCH_COUNT
} SovereignBatchType;

// =============================================================================
// Batch Request
// =============================================================================

typedef struct {
    uint32_t request_id;
    void* input_data;
    void* output_data;
    uint32_t seq_length;
    uint32_t batch_size;
    uint32_t priority;      // 0 = highest priority
    uint64_t submit_time;   // For latency tracking
    uint64_t deadline;      // Optional deadline (0 = none)
} SovereignBatchRequest;

// =============================================================================
// Batch Configuration
// =============================================================================

typedef struct {
    uint32_t max_batch_size;
    uint32_t max_sequence_length;
    uint32_t timeout_us;           // Microseconds to wait for batch fill
    uint32_t padding_token_id;   // Token ID for padding
    float padding_scale;         // Scale factor for padding
    int enable_dynamic_batching;   // Allow variable sequence lengths
    int enable_priority_queue;     // Priority-based scheduling
} SovereignBatchConfig;

// =============================================================================
// Batch Statistics
// =============================================================================

typedef struct {
    uint64_t batches_processed;
    uint64_t requests_processed;
    uint64_t tokens_processed;
    uint64_t padding_tokens;       // Wasted compute
    double avg_batch_size;
    double avg_batch_latency_ms;
    double avg_request_latency_ms;
    double throughput_tokens_per_sec;
    double utilization_percent;    // GPU/CPU utilization
    uint64_t deadline_misses;
} SovereignBatchStats;

// =============================================================================
// Batch Processor Handle
// =============================================================================

typedef struct SovereignBatchProcessor* SovereignBatchProcessorHandle;

// =============================================================================
// API Functions
// =============================================================================

// Initialize batch processor
__declspec(dllexport) SovereignBatchProcessorHandle Sovereign_BatchProcessor_Init(
    SovereignThreadPoolHandle thread_pool,
    const SovereignBatchConfig* config
);

// Shutdown batch processor
__declspec(dllexport) void Sovereign_BatchProcessor_Shutdown(
    SovereignBatchProcessorHandle processor
);

// Submit single request
__declspec(dllexport) int Sovereign_BatchProcessor_Submit(
    SovereignBatchProcessorHandle processor,
    const SovereignBatchRequest* request,
    SovereignBatchType type
);

// Submit multiple requests (batch API)
__declspec(dllexport) int Sovereign_BatchProcessor_SubmitBatch(
    SovereignBatchProcessorHandle processor,
    const SovereignBatchRequest* requests,
    uint32_t count,
    SovereignBatchType type
);

// Wait for specific request to complete
__declspec(dllexport) int Sovereign_BatchProcessor_WaitRequest(
    SovereignBatchProcessorHandle processor,
    uint32_t request_id,
    uint32_t timeout_ms
);

// Wait for all pending requests
__declspec(dllexport) void Sovereign_BatchProcessor_WaitAll(
    SovereignBatchProcessorHandle processor
);

// Get batch statistics
__declspec(dllexport) void Sovereign_BatchProcessor_GetStats(
    SovereignBatchProcessorHandle processor,
    SovereignBatchStats* stats
);

// Reset statistics
__declspec(dllexport) void Sovereign_BatchProcessor_ResetStats(
    SovereignBatchProcessorHandle processor
);

// Flush current batch (process immediately)
__declspec(dllexport) void Sovereign_BatchProcessor_Flush(
    SovereignBatchProcessorHandle processor
);

// Set batch timeout dynamically
__declspec(dllexport) void Sovereign_BatchProcessor_SetTimeout(
    SovereignBatchProcessorHandle processor,
    uint32_t timeout_us
);

// Get optimal batch size for current workload
__declspec(dllexport) uint32_t Sovereign_BatchProcessor_GetOptimalBatchSize(
    SovereignBatchProcessorHandle processor
);

// =============================================================================
// Utility Functions
// =============================================================================

// Pack variable-length sequences into padded batch
__declspec(dllexport) int Sovereign_BatchProcessor_PackSequences(
    void** input_sequences,
    uint32_t* sequence_lengths,
    uint32_t count,
    uint32_t padding_token,
    void* output_padded,
    uint32_t* max_length_out
);

// Unpack batched output to individual sequences
__declspec(dllexport) int Sovereign_BatchProcessor_UnpackSequences(
    const void* input_padded,
    uint32_t batch_size,
    uint32_t max_length,
    uint32_t* actual_lengths,
    void** output_sequences
);

// Calculate batch efficiency (1.0 = perfect, no padding)
__declspec(dllexport) float Sovereign_BatchProcessor_CalculateEfficiency(
    uint32_t* sequence_lengths,
    uint32_t count,
    uint32_t padded_length
);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_BATCH_PROCESSOR_H
