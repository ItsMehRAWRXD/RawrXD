// =============================================================================
// sovereign_interface_contract.h
// Phase 22/23 Integration Contract
// Defines the unified interface between Engine Controller and Ring Attention Swarm
// =============================================================================

#ifndef SOVEREIGN_INTERFACE_CONTRACT_H
#define SOVEREIGN_INTERFACE_CONTRACT_H

#include <cstdint>
#include <cstddef>

// =============================================================================
// Ring Attention Status Codes (from Phase 23B)
// =============================================================================

enum class RingStatus : uint32_t {
    OK = 0,                    // Operation successful
    RING_STALLED = 1,          // Token circulation timeout
    NODE_UNRESPONSIVE = 2,     // Worker node timeout
    CHECKSUM_MISMATCH = 3,     // Data integrity failure
    RECOVERY_FAILED = 4,       // Autopilot recovery exhausted
    INVALID_LAYER = 5,         // Layer index out of bounds
    BUFFER_OVERFLOW = 6,       // Ring buffer capacity exceeded
    CIRCUIT_OPEN = 7           // Circuit breaker triggered
};

// =============================================================================
// Ring Statistics (mirrors Phase 23B RingStats)
// =============================================================================

struct RingMetrics {
    uint64_t tokens_forwarded;      // Total tokens sent around ring
    uint64_t tokens_received;         // Total tokens received back
    uint64_t recovery_events;         // Number of recovery attempts
    uint64_t circuit_breaks;          // Circuit breaker triggers
    uint64_t checksum_failures;       // Data integrity failures
    uint32_t active_nodes;            // Currently responsive nodes
    uint32_t total_nodes;             // Configured node count
    float avg_latency_ms;             // Average round-trip latency
    float p99_latency_ms;             // 99th percentile latency
    float throughput_tps;             // Current throughput estimate
    uint64_t last_update_us;          // Timestamp of last update
};

// =============================================================================
// KV Cache Metadata (from Phase 11 Loader)
// =============================================================================

struct KVCacheMetadata {
    uint32_t seq_length;              // Current sequence position
    uint32_t max_seq_length;          // Maximum sequence capacity
    uint32_t n_layers;                // Number of transformer layers
    uint32_t n_heads;                 // Number of attention heads
    uint32_t head_dim;                // Dimension per head
    uint32_t batch_size;              // Current batch size
    uint8_t  quant_type;              // Quantization type (Q8_0/Q4_K/Q2_K)
    bool     sliding_window;          // Sliding window enabled
    uint32_t window_size;             // Window size if sliding
};

// =============================================================================
// Layer Processing Request
// =============================================================================

struct LayerRequest {
    uint32_t layer_idx;             // Layer to process
    uint32_t token_id;              // Input token
    uint32_t position;              // Position in sequence
    float*   input_activations;     // Input tensor (n_heads * head_dim)
    float*   output_activations;    // Output buffer (n_heads * head_dim)
    uint32_t activation_count;      // Number of float values
    uint64_t request_id;            // Unique request identifier
    uint64_t deadline_us;           // Deadline for completion
};

// =============================================================================
// Layer Processing Response
// =============================================================================

struct LayerResponse {
    RingStatus status;              // Operation status
    uint32_t   layer_idx;           // Layer that was processed
    uint64_t   request_id;          // Matching request ID
    uint64_t   processing_time_us;  // Time taken
    float*     output_activations;  // Result data
    uint32_t   output_count;        // Number of output values
    RingMetrics ring_metrics;       // Current ring state
};

// =============================================================================
// Circuit Breaker Configuration
// =============================================================================

struct CircuitBreakerConfig {
    uint32_t failure_threshold;     // Failures before opening
    uint32_t recovery_timeout_ms;     // Time before half-open
    uint32_t half_open_max_calls;     // Test calls in half-open
    float    latency_threshold_ms;    // Latency trigger threshold
};

// =============================================================================
// C Interface for ASM Ring Attention (extern "C" linkage)
// =============================================================================

extern "C" {

// Initialize the ring attention system
// Returns: 0 on success, non-zero on error
int RingAttention_Init(uint32_t node_count, 
                       uint32_t ring_buffer_size,
                       const CircuitBreakerConfig* config);

// Shutdown the ring attention system
void RingAttention_Shutdown(void);

// Process a single layer through the ring
// This is the core integration point - Controller calls this for each layer
RingStatus RingAttention_ProcessLayer(const LayerRequest* request,
                                      LayerResponse* response);

// Process multiple layers in batch (for throughput optimization)
RingStatus RingAttention_ProcessLayers(const LayerRequest* requests,
                                       uint32_t request_count,
                                       LayerResponse* responses);

// Get current ring metrics
void RingAttention_GetMetrics(RingMetrics* metrics);

// Inject KV cache metadata into the ring (Phase 11 → Phase 23 bridge)
void RingAttention_InjectKVCache(const KVCacheMetadata* metadata);

// Force circuit breaker state (for testing/emergency)
void RingAttention_ForceCircuitBreaker(bool open);

// Recovery telemetry export (links to RawrXD_Recovery_Telemetry.asm)
void RingAttention_ExportTelemetry(const char* prometheus_endpoint);

} // extern "C"

// =============================================================================
// C++ Interface (wrappers with RAII and type safety)
// =============================================================================

namespace Sovereign {

class RingAttentionInterface {
public:
    // Initialize with configuration
    static bool Initialize(uint32_t node_count, 
                          uint32_t ring_buffer_size = 1024,
                          const CircuitBreakerConfig* config = nullptr);
    
    // Shutdown and cleanup
    static void Shutdown();
    
    // Check if initialized
    static bool IsInitialized();
    
    // Process a layer (blocking call with timeout)
    static RingStatus ProcessLayer(const LayerRequest& request,
                                   LayerResponse& response,
                                   uint32_t timeout_ms = 5000);
    
    // Process multiple layers
    static RingStatus ProcessLayers(const LayerRequest* requests,
                                    uint32_t count,
                                    LayerResponse* responses,
                                    uint32_t timeout_ms = 10000);
    
    // Get current metrics
    static RingMetrics GetMetrics();
    
    // Inject KV cache from Phase 11 loader
    static void InjectKVCache(const KVCacheMetadata& metadata);
    
    // Check ring health
    static bool IsHealthy();
    
    // Get last error
    static RingStatus GetLastError();
    
    // Force recovery (for testing)
    static void ForceRecovery();
    
    // Export telemetry
    static void ExportTelemetry(const char* endpoint);
};

// Status code to string conversion
const char* RingStatusToString(RingStatus status);

} // namespace Sovereign

#endif // SOVEREIGN_INTERFACE_CONTRACT_H
