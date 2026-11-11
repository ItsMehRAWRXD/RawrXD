// =============================================================================
// sovereign_engine_controller_ring_extension.cpp
// Implementation of Ring Attention extension for SovereignEngineController
// =============================================================================

#include "sovereign_engine_controller_ring_extension.h"
#include "sovereign_interface_contract.h"
#include <cstdio>
#include <cstring>

namespace Sovereign {

// =============================================================================
// Constructor / Destructor
// =============================================================================

SovereignEngineControllerWithRing::SovereignEngineControllerWithRing()
    : SovereignEngineController()
    , ring_initialized_(false)
    , distributed_mode_(true)
    , auto_fallback_(true)
    , last_ring_error_(RingStatus::OK) {
    
    // Default circuit breaker config
    circuit_config_.failure_threshold = 5;
    circuit_config_.recovery_timeout_ms = 30000;
    circuit_config_.half_open_max_calls = 3;
    circuit_config_.latency_threshold_ms = 150.0f;
    
    printf("[Sovereign] Engine Controller with Ring Attention initialized\n");
}

SovereignEngineControllerWithRing::~SovereignEngineControllerWithRing() {
    if (ring_initialized_) {
        ShutdownRing();
    }
    printf("[Sovereign] Engine Controller with Ring destroyed\n");
}

// =============================================================================
// Ring Attention Lifecycle
// =============================================================================

bool SovereignEngineControllerWithRing::InitializeRing(uint32_t node_count,
                                                        uint32_t ring_buffer_size) {
    if (ring_initialized_) {
        printf("[Sovereign] Ring already initialized\n");
        return true;
    }
    
    printf("[Sovereign] Initializing Ring Attention with %u nodes...\n", node_count);
    
    if (!RingAttentionInterface::Initialize(node_count, ring_buffer_size, &circuit_config_)) {
        fprintf(stderr, "[Sovereign] Failed to initialize ring attention\n");
        return false;
    }
    
    ring_initialized_ = true;
    
    // Sync KV cache if model is loaded
    if (IsModelLoaded()) {
        SyncKVCacheToRing();
    }
    
    printf("[Sovereign] Ring Attention initialized successfully\n");
    return true;
}

void SovereignEngineControllerWithRing::ShutdownRing() {
    if (!ring_initialized_) {
        return;
    }
    
    printf("[Sovereign] Shutting down Ring Attention...\n");
    
    RingAttentionInterface::Shutdown();
    ring_initialized_ = false;
    
    printf("[Sovereign] Ring Attention shutdown complete\n");
}

bool SovereignEngineControllerWithRing::IsRingHealthy() const {
    return ring_initialized_ && RingAttentionInterface::IsHealthy();
}

// =============================================================================
// Distributed Inference
// =============================================================================

bool SovereignEngineControllerWithRing::ProcessLayerDistributed(
    uint32_t layer_idx,
    const float* input_activations,
    float* output_activations,
    uint32_t activation_count) {
    
    if (!ring_initialized_) {
        fprintf(stderr, "[Sovereign] Ring not initialized\n");
        last_ring_error_ = RingStatus::RECOVERY_FAILED;
        return false;
    }
    
    if (!distributed_mode_) {
        return ProcessLayerLocal(layer_idx, input_activations, 
                                  output_activations, activation_count);
    }
    
    // Build layer request
    LayerRequest request;
    request.layer_idx = layer_idx;
    request.token_id = 0;  // Set by caller context
    request.position = 0;  // Set by caller context
    request.input_activations = const_cast<float*>(input_activations);
    request.output_activations = output_activations;
    request.activation_count = activation_count;
    request.request_id = 0;  // TODO: Generate unique ID
    request.deadline_us = 0; // TODO: Set deadline
    
    LayerResponse response;
    memset(&response, 0, sizeof(response));
    
    // Process through ring
    RingStatus status = RingAttentionInterface::ProcessLayer(request, response);
    last_ring_error_ = status;
    
    if (status != RingStatus::OK) {
        fprintf(stderr, "[Sovereign] Ring processing failed: %s\n",
                RingStatusToString(status));
        
        // Auto-fallback to local processing
        if (auto_fallback_) {
            printf("[Sovereign] Auto-fallback to local processing...\n");
            return ProcessLayerLocal(layer_idx, input_activations,
                                     output_activations, activation_count);
        }
        
        return false;
    }
    
    return true;
}

bool SovereignEngineControllerWithRing::ProcessTransformerBlock(
    uint32_t block_idx,
    const float* input,
    float* output,
    uint32_t count) {
    
    // A transformer block typically has:
    // - Self-attention layer
    // - Feed-forward layer
    // - Layer norms
    
    // Map block index to actual layer indices
    uint32_t base_layer = block_idx * 2;  // Simplified mapping
    
    // Process attention layer
    if (!ProcessLayerDistributed(base_layer, input, output, count)) {
        return false;
    }
    
    // Process feed-forward layer (output from attention becomes input)
    if (!ProcessLayerDistributed(base_layer + 1, output, output, count)) {
        return false;
    }
    
    return true;
}

// =============================================================================
// KV Cache Bridge (Phase 11 → Phase 23)
// =============================================================================

bool SovereignEngineControllerWithRing::SyncKVCacheToRing() {
    if (!ring_initialized_) {
        return false;
    }
    
    // Get KV cache metadata from loaded model
    // This would query the Phase 11 loader
    KVCacheMetadata metadata;
    memset(&metadata, 0, sizeof(metadata));
    
    // TODO: Populate from actual model
    metadata.seq_length = 0;
    metadata.max_seq_length = 4096;
    metadata.n_layers = GetLayerCount();
    metadata.n_heads = 32;
    metadata.head_dim = 128;
    metadata.batch_size = 1;
    metadata.quant_type = 8;  // Q8_0
    metadata.sliding_window = true;
    metadata.window_size = 512;
    
    RingAttentionInterface::InjectKVCache(metadata);
    
    printf("[Sovereign] KV cache metadata synced to ring\n");
    return true;
}

// =============================================================================
// Circuit Breaker Integration
// =============================================================================

void SovereignEngineControllerWithRing::SetCircuitBreakerConfig(
    const CircuitBreakerConfig& config) {
    circuit_config_ = config;
    
    // If ring is running, update live config
    if (ring_initialized_) {
        RingAttention_ForceCircuitBreaker(false);  // Reset
    }
}

bool SovereignEngineControllerWithRing::IsCircuitOpen() const {
    return RingAttentionInterface::GetLastError() == RingStatus::CIRCUIT_OPEN;
}

void SovereignEngineControllerWithRing::ForceCircuitBreaker(bool open) {
    RingAttention_ForceCircuitBreaker(open);
}

// =============================================================================
// Telemetry & Monitoring
// =============================================================================

RingMetrics SovereignEngineControllerWithRing::GetRingMetrics() const {
    return RingAttentionInterface::GetMetrics();
}

void SovereignEngineControllerWithRing::ExportRingTelemetry(const char* endpoint) const {
    RingAttentionInterface::ExportTelemetry(endpoint);
}

void SovereignEngineControllerWithRing::PrintRingStatus() const {
    printf("\n=== Ring Attention Status ===\n");
    printf("Initialized: %s\n", ring_initialized_ ? "Yes" : "No");
    printf("Distributed mode: %s\n", distributed_mode_ ? "Enabled" : "Disabled");
    printf("Auto-fallback: %s\n", auto_fallback_ ? "Enabled" : "Disabled");
    printf("Circuit breaker: %s\n", IsCircuitOpen() ? "OPEN" : "Closed");
    
    if (ring_initialized_) {
        RingMetrics metrics = GetRingMetrics();
        printf("\nMetrics:\n");
        printf("  Active nodes: %u/%u\n", metrics.active_nodes, metrics.total_nodes);
        printf("  Tokens forwarded: %llu\n", metrics.tokens_forwarded);
        printf("  Recovery events: %llu\n", metrics.recovery_events);
        printf("  Circuit breaks: %llu\n", metrics.circuit_breaks);
        printf("  Avg latency: %.2f ms\n", metrics.avg_latency_ms);
        printf("  Throughput: %.2f TPS\n", metrics.throughput_tps);
    }
    
    printf("=============================\n\n");
}

// =============================================================================
// Error Handling
// =============================================================================

RingStatus SovereignEngineControllerWithRing::GetLastRingError() const {
    return last_ring_error_;
}

const char* SovereignEngineControllerWithRing::GetLastRingErrorString() const {
    return RingStatusToString(last_ring_error_);
}

void SovereignEngineControllerWithRing::ClearRingError() {
    last_ring_error_ = RingStatus::OK;
    RingAttentionInterface::ForceRecovery();
}

// =============================================================================
// Mode Selection
// =============================================================================

void SovereignEngineControllerWithRing::SetDistributedMode(bool enabled) {
    distributed_mode_ = enabled;
    printf("[Sovereign] Distributed mode: %s\n", enabled ? "enabled" : "disabled");
}

// =============================================================================
// Private Methods
// =============================================================================

bool SovereignEngineControllerWithRing::ProcessLayerLocal(
    uint32_t layer_idx,
    const float* input,
    float* output,
    uint32_t count) {
    
    // Fallback to thread pool processing
    // This would use the existing ThreadPool in the base controller
    printf("[Sovereign] Processing layer %u locally (fallback)\n", layer_idx);
    
    // Simple memcpy as placeholder (real implementation would compute)
    memcpy(output, input, count * sizeof(float));
    
    return true;
}

} // namespace Sovereign

// =============================================================================
// C-API Implementation
// =============================================================================

extern "C" {

int Sovereign_InitializeRing(SovereignEngineHandle handle,
                              uint32_t node_count,
                              uint32_t ring_buffer_size) {
    if (!handle) return -1;
    
    auto* engine = static_cast<Sovereign::SovereignEngineControllerWithRing*>(handle);
    return engine->InitializeRing(node_count, ring_buffer_size) ? 0 : -1;
}

void Sovereign_ShutdownRing(SovereignEngineHandle handle) {
    if (!handle) return;
    
    auto* engine = static_cast<Sovereign::SovereignEngineControllerWithRing*>(handle);
    engine->ShutdownRing();
}

int Sovereign_IsRingHealthy(SovereignEngineHandle handle) {
    if (!handle) return 0;
    
    auto* engine = static_cast<Sovereign::SovereignEngineControllerWithRing*>(handle);
    return engine->IsRingHealthy() ? 1 : 0;
}

int Sovereign_ProcessLayerDistributed(SovereignEngineHandle handle,
                                       uint32_t layer_idx,
                                       const float* input,
                                       float* output,
                                       uint32_t count) {
    if (!handle || !input || !output) return -1;
    
    auto* engine = static_cast<Sovereign::SovereignEngineControllerWithRing*>(handle);
    return engine->ProcessLayerDistributed(layer_idx, input, output, count) ? 0 : -1;
}

void Sovereign_GetRingMetrics(SovereignEngineHandle handle, RingMetrics* metrics) {
    if (!handle || !metrics) return;
    
    auto* engine = static_cast<Sovereign::SovereignEngineControllerWithRing*>(handle);
    *metrics = engine->GetRingMetrics();
}

void Sovereign_ExportRingTelemetry(SovereignEngineHandle handle, const char* endpoint) {
    if (!handle || !endpoint) return;
    
    auto* engine = static_cast<Sovereign::SovereignEngineControllerWithRing*>(handle);
    engine->ExportRingTelemetry(endpoint);
}

void Sovereign_ForceCircuitBreaker(SovereignEngineHandle handle, int open) {
    if (!handle) return;
    
    auto* engine = static_cast<Sovereign::SovereignEngineControllerWithRing*>(handle);
    engine->ForceCircuitBreaker(open != 0);
}

} // extern "C"
