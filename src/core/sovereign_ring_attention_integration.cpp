// =============================================================================
// sovereign_ring_attention_integration.cpp
// Phase 22/23 Integration Implementation
// Binds SovereignEngineController to Ring Attention Swarm
// =============================================================================

#include "sovereign_interface_contract.h"
#include "sovereign_engine_controller_integration.h"
#include <cstdio>
#include <cstring>
#include <mutex>
#include <atomic>
#include <chrono>

namespace Sovereign {

// =============================================================================
// Internal State
// =============================================================================

static std::atomic<bool> g_ring_initialized{false};
static std::atomic<RingStatus> g_last_error{RingStatus::OK};
static std::mutex g_ring_mutex;
static RingMetrics g_cached_metrics{};
static CircuitBreakerConfig g_circuit_config{};

// Default circuit breaker config
static const CircuitBreakerConfig DEFAULT_CIRCUIT_CONFIG = {
    .failure_threshold = 5,           // 5 failures before opening
    .recovery_timeout_ms = 30000,     // 30s before half-open
    .half_open_max_calls = 3,         // 3 test calls
    .latency_threshold_ms = 150.0f    // 150ms p99 threshold
};

// =============================================================================
// C Interface Implementation (calls ASM functions)
// =============================================================================

extern "C" {

// Forward declarations to ASM functions (defined in RawrXD_Ring_Attention_Simple.asm)
extern "C" int RawrXD_RingAttention_Init(uint32_t node_count, uint32_t buffer_size);
extern "C" void RawrXD_RingAttention_Shutdown(void);
extern "C" int RawrXD_RingAttention_Process(uint32_t layer_idx, 
                                             const float* input,
                                             float* output,
                                             uint32_t count);
extern "C" void RawrXD_RingAttention_GetStats(void* stats_buffer);
extern "C" void RawrXD_RingAttention_InjectMetadata(const void* metadata);

int RingAttention_Init(uint32_t node_count, 
                       uint32_t ring_buffer_size,
                       const CircuitBreakerConfig* config) {
    std::lock_guard<std::mutex> lock(g_ring_mutex);
    
    if (g_ring_initialized.load()) {
        printf("[RingAttention] Already initialized\n");
        return 0;  // Idempotent success
    }
    
    // Store circuit breaker config
    if (config) {
        g_circuit_config = *config;
    } else {
        g_circuit_config = DEFAULT_CIRCUIT_CONFIG;
    }
    
    printf("[RingAttention] Initializing with %u nodes, buffer size %u\n", 
           node_count, ring_buffer_size);
    printf("[RingAttention] Circuit breaker: %u failures, %ums recovery\n",
           g_circuit_config.failure_threshold,
           g_circuit_config.recovery_timeout_ms);
    
    // Call ASM initialization
    int result = RawrXD_RingAttention_Init(node_count, ring_buffer_size);
    if (result != 0) {
        fprintf(stderr, "[RingAttention] ASM init failed: %d\n", result);
        g_last_error = RingStatus::RECOVERY_FAILED;
        return result;
    }
    
    g_ring_initialized.store(true);
    g_last_error = RingStatus::OK;
    
    printf("[RingAttention] Initialization complete\n");
    return 0;
}

void RingAttention_Shutdown(void) {
    std::lock_guard<std::mutex> lock(g_ring_mutex);
    
    if (!g_ring_initialized.load()) {
        return;
    }
    
    printf("[RingAttention] Shutting down...\n");
    
    RawrXD_RingAttention_Shutdown();
    
    g_ring_initialized.store(false);
    g_last_error = RingStatus::OK;
    
    printf("[RingAttention] Shutdown complete\n");
}

RingStatus RingAttention_ProcessLayer(const LayerRequest* request,
                                      LayerResponse* response) {
    if (!request || !response) {
        return RingStatus::INVALID_LAYER;
    }
    
    if (!g_ring_initialized.load()) {
        return RingStatus::RECOVERY_FAILED;
    }
    
    // Check circuit breaker
    if (g_last_error.load() == RingStatus::CIRCUIT_OPEN) {
        return RingStatus::CIRCUIT_OPEN;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Call ASM layer processing
    int result = RawrXD_RingAttention_Process(
        request->layer_idx,
        request->input_activations,
        response->output_activations,
        request->activation_count
    );
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    
    // Map ASM result to RingStatus
    RingStatus status;
    switch (result) {
        case 0:  status = RingStatus::OK; break;
        case 1:  status = RingStatus::RING_STALLED; break;
        case 2:  status = RingStatus::NODE_UNRESPONSIVE; break;
        case 3:  status = RingStatus::CHECKSUM_MISMATCH; break;
        default: status = RingStatus::RECOVERY_FAILED; break;
    }
    
    // Populate response
    response->status = status;
    response->layer_idx = request->layer_idx;
    response->request_id = request->request_id;
    response->processing_time_us = duration.count();
    response->output_count = request->activation_count;
    
    // Update cached metrics
    {
        std::lock_guard<std::mutex> lock(g_ring_mutex);
        if (status == RingStatus::OK) {
            g_cached_metrics.tokens_forwarded++;
            g_cached_metrics.tokens_received++;
        } else {
            g_cached_metrics.recovery_events++;
            g_last_error = status;
            
            // Check if we should trigger circuit breaker
            if (g_cached_metrics.recovery_events >= g_circuit_config.failure_threshold) {
                g_last_error = RingStatus::CIRCUIT_OPEN;
                g_cached_metrics.circuit_breaks++;
                fprintf(stderr, "[RingAttention] CIRCUIT BREAKER OPENED!\n");
            }
        }
        
        // Update latency tracking
        float latency_ms = duration.count() / 1000.0f;
        g_cached_metrics.avg_latency_ms = 
            (g_cached_metrics.avg_latency_ms * 0.9f) + (latency_ms * 0.1f);
    }
    
    // Get current ring metrics
    RingAttention_GetMetrics(&response->ring_metrics);
    
    return status;
}

RingStatus RingAttention_ProcessLayers(const LayerRequest* requests,
                                         uint32_t request_count,
                                         LayerResponse* responses) {
    if (!requests || !responses || request_count == 0) {
        return RingStatus::INVALID_LAYER;
    }
    
    RingStatus overall_status = RingStatus::OK;
    
    for (uint32_t i = 0; i < request_count; i++) {
        RingStatus status = RingAttention_ProcessLayer(&requests[i], &responses[i]);
        if (status != RingStatus::OK) {
            overall_status = status;
            // Continue processing remaining layers
        }
    }
    
    return overall_status;
}

void RingAttention_GetMetrics(RingMetrics* metrics) {
    if (!metrics) return;
    
    std::lock_guard<std::mutex> lock(g_ring_mutex);
    
    // Get ASM stats
    RawrXD_RingAttention_GetStats(metrics);
    
    // Merge with cached metrics
    metrics->recovery_events = g_cached_metrics.recovery_events;
    metrics->circuit_breaks = g_cached_metrics.circuit_breaks;
    metrics->avg_latency_ms = g_cached_metrics.avg_latency_ms;
    
    // Calculate throughput
    if (metrics->tokens_forwarded > 0 && metrics->avg_latency_ms > 0) {
        metrics->throughput_tps = 
            1000.0f / metrics->avg_latency_ms * metrics->active_nodes;
    }
    
    // Update timestamp
    auto now = std::chrono::high_resolution_clock::now();
    metrics->last_update_us = 
        std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
}

void RingAttention_InjectKVCache(const KVCacheMetadata* metadata) {
    if (!metadata || !g_ring_initialized.load()) {
        return;
    }
    
    printf("[RingAttention] Injecting KV cache metadata:\n");
    printf("  Sequence: %u/%u\n", metadata->seq_length, metadata->max_seq_length);
    printf("  Layers: %u, Heads: %u, Head dim: %u\n",
           metadata->n_layers, metadata->n_heads, metadata->head_dim);
    printf("  Quant type: %u, Sliding window: %s\n",
           metadata->quant_type, 
           metadata->sliding_window ? "yes" : "no");
    
    // Pass to ASM layer
    RawrXD_RingAttention_InjectMetadata(metadata);
}

void RingAttention_ForceCircuitBreaker(bool open) {
    std::lock_guard<std::mutex> lock(g_ring_mutex);
    
    if (open) {
        g_last_error = RingStatus::CIRCUIT_OPEN;
        g_cached_metrics.circuit_breaks++;
        printf("[RingAttention] Circuit breaker FORCED OPEN\n");
    } else {
        g_last_error = RingStatus::OK;
        g_cached_metrics.recovery_events = 0;
        printf("[RingAttention] Circuit breaker FORCED CLOSED\n");
    }
}

void RingAttention_ExportTelemetry(const char* prometheus_endpoint) {
    if (!prometheus_endpoint) return;
    
    printf("[RingAttention] Exporting telemetry to: %s\n", prometheus_endpoint);
    
    // This would call RawrXD_Recovery_Telemetry.asm
    // For now, just log the intent
    RingMetrics metrics;
    RingAttention_GetMetrics(&metrics);
    
    printf("  Tokens forwarded: %llu\n", metrics.tokens_forwarded);
    printf("  Recovery events: %llu\n", metrics.recovery_events);
    printf("  Circuit breaks: %llu\n", metrics.circuit_breaks);
    printf("  Avg latency: %.2f ms\n", metrics.avg_latency_ms);
    printf("  Throughput: %.2f TPS\n", metrics.throughput_tps);
}

} // extern "C"

// =============================================================================
// C++ Interface Implementation
// =============================================================================

bool RingAttentionInterface::Initialize(uint32_t node_count, 
                                       uint32_t ring_buffer_size,
                                       const CircuitBreakerConfig* config) {
    return RingAttention_Init(node_count, ring_buffer_size, config) == 0;
}

void RingAttentionInterface::Shutdown() {
    RingAttention_Shutdown();
}

bool RingAttentionInterface::IsInitialized() {
    return g_ring_initialized.load();
}

RingStatus RingAttentionInterface::ProcessLayer(const LayerRequest& request,
                                                LayerResponse& response,
                                                uint32_t timeout_ms) {
    // TODO: Implement timeout handling
    (void)timeout_ms;  // Currently unused - ASM calls are synchronous
    return RingAttention_ProcessLayer(&request, &response);
}

RingStatus RingAttentionInterface::ProcessLayers(const LayerRequest* requests,
                                               uint32_t count,
                                               LayerResponse* responses,
                                               uint32_t timeout_ms) {
    (void)timeout_ms;
    return RingAttention_ProcessLayers(requests, count, responses);
}

RingMetrics RingAttentionInterface::GetMetrics() {
    RingMetrics metrics;
    RingAttention_GetMetrics(&metrics);
    return metrics;
}

void RingAttentionInterface::InjectKVCache(const KVCacheMetadata& metadata) {
    RingAttention_InjectKVCache(&metadata);
}

bool RingAttentionInterface::IsHealthy() {
    return g_ring_initialized.load() && 
           g_last_error.load() != RingStatus::CIRCUIT_OPEN;
}

RingStatus RingAttentionInterface::GetLastError() {
    return g_last_error.load();
}

void RingAttentionInterface::ForceRecovery() {
    RingAttention_ForceCircuitBreaker(false);
}

void RingAttentionInterface::ExportTelemetry(const char* endpoint) {
    RingAttention_ExportTelemetry(endpoint);
}

// =============================================================================
// Utility Functions
// =============================================================================

const char* RingStatusToString(RingStatus status) {
    switch (status) {
        case RingStatus::OK: return "OK";
        case RingStatus::RING_STALLED: return "RING_STALLED";
        case RingStatus::NODE_UNRESPONSIVE: return "NODE_UNRESPONSIVE";
        case RingStatus::CHECKSUM_MISMATCH: return "CHECKSUM_MISMATCH";
        case RingStatus::RECOVERY_FAILED: return "RECOVERY_FAILED";
        case RingStatus::INVALID_LAYER: return "INVALID_LAYER";
        case RingStatus::BUFFER_OVERFLOW: return "BUFFER_OVERFLOW";
        case RingStatus::CIRCUIT_OPEN: return "CIRCUIT_OPEN";
        default: return "UNKNOWN";
    }
}

} // namespace Sovereign
