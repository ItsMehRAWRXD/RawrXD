// =============================================================================
// sovereign_engine_controller_ring_extension.h
// Extension to SovereignEngineController for Ring Attention integration
// =============================================================================

#ifndef SOVEREIGN_ENGINE_CONTROLLER_RING_EXTENSION_H
#define SOVEREIGN_ENGINE_CONTROLLER_RING_EXTENSION_H

#include "sovereign_engine_controller_integration.h"
#include "sovereign_interface_contract.h"

namespace Sovereign {

// =============================================================================
// Extended Controller with Ring Attention Support
// =============================================================================

class SovereignEngineControllerWithRing : public SovereignEngineController {
public:
    SovereignEngineControllerWithRing();
    ~SovereignEngineControllerWithRing() override;
    
    // Disable copy/move
    SovereignEngineControllerWithRing(const SovereignEngineControllerWithRing&) = delete;
    SovereignEngineControllerWithRing& operator=(const SovereignEngineControllerWithRing&) = delete;
    
    // =============================================================================
    // Ring Attention Lifecycle
    // =============================================================================
    
    // Initialize the ring attention swarm
    // Must be called after LoadModel() and before first inference
    bool InitializeRing(uint32_t node_count = 8,
                        uint32_t ring_buffer_size = 1024);
    
    // Shutdown the ring attention system
    void ShutdownRing();
    
    // Check if ring is initialized and healthy
    bool IsRingHealthy() const;
    
    // =============================================================================
    // Distributed Inference
    // =============================================================================
    
    // Process a single layer through the ring (replaces local processing)
    // Returns true on success, false on failure (check GetLastRingError())
    bool ProcessLayerDistributed(uint32_t layer_idx,
                                  const float* input_activations,
                                  float* output_activations,
                                  uint32_t activation_count);
    
    // Process all layers in a transformer block through the ring
    // This is the main inference entry point for distributed mode
    bool ProcessTransformerBlock(uint32_t block_idx,
                                  const float* input,
                                  float* output,
                                  uint32_t count);
    
    // =============================================================================
    // KV Cache Bridge (Phase 11 → Phase 23)
    // =============================================================================
    
    // Inject KV cache metadata from loaded model into the ring
    // Called automatically after InitializeRing() if model is loaded
    bool SyncKVCacheToRing();
    
    // =============================================================================
    // Circuit Breaker Integration
    // =============================================================================
    
    // Configure circuit breaker thresholds
    void SetCircuitBreakerConfig(const CircuitBreakerConfig& config);
    
    // Get current circuit breaker state
    bool IsCircuitOpen() const;
    
    // Force circuit breaker (for emergency stop or testing)
    void ForceCircuitBreaker(bool open);
    
    // =============================================================================
    // Telemetry & Monitoring
    // =============================================================================
    
    // Get current ring metrics
    RingMetrics GetRingMetrics() const;
    
    // Export metrics to Prometheus endpoint
    void ExportRingTelemetry(const char* endpoint) const;
    
    // Print ring status to console
    void PrintRingStatus() const;
    
    // =============================================================================
    // Error Handling
    // =============================================================================
    
    // Get last ring error
    RingStatus GetLastRingError() const;
    
    // Get last ring error as string
    const char* GetLastRingErrorString() const;
    
    // Clear error state
    void ClearRingError();
    
    // =============================================================================
    // Mode Selection
    // =============================================================================
    
    // Enable/disable distributed mode
    // When disabled, falls back to local thread pool processing
    void SetDistributedMode(bool enabled);
    bool IsDistributedMode() const { return distributed_mode_; }
    
    // Auto-fallback: if ring fails, automatically switch to local processing
    void SetAutoFallback(bool enabled) { auto_fallback_ = enabled; }
    bool IsAutoFallbackEnabled() const { return auto_fallback_; }

private:
    bool ring_initialized_ = false;
    bool distributed_mode_ = true;
    bool auto_fallback_ = true;
    mutable RingStatus last_ring_error_ = RingStatus::OK;
    CircuitBreakerConfig circuit_config_;
    
    // Fallback to local processing
    bool ProcessLayerLocal(uint32_t layer_idx,
                           const float* input,
                           float* output,
                           uint32_t count);
};

} // namespace Sovereign

// =============================================================================
// C-API Extensions
// =============================================================================

extern "C" {

// Initialize ring attention for an existing engine
int Sovereign_InitializeRing(SovereignEngineHandle handle,
                              uint32_t node_count,
                              uint32_t ring_buffer_size);

// Shutdown ring attention
void Sovereign_ShutdownRing(SovereignEngineHandle handle);

// Check ring health
int Sovereign_IsRingHealthy(SovereignEngineHandle handle);

// Process layer through ring
int Sovereign_ProcessLayerDistributed(SovereignEngineHandle handle,
                                       uint32_t layer_idx,
                                       const float* input,
                                       float* output,
                                       uint32_t count);

// Get ring metrics
void Sovereign_GetRingMetrics(SovereignEngineHandle handle, RingMetrics* metrics);

// Export telemetry
void Sovereign_ExportRingTelemetry(SovereignEngineHandle handle, 
                                    const char* endpoint);

// Circuit breaker control
void Sovereign_ForceCircuitBreaker(SovereignEngineHandle handle, int open);

} // extern "C"

#endif // SOVEREIGN_ENGINE_CONTROLLER_RING_EXTENSION_H
