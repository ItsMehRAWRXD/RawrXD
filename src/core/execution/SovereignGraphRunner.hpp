// ============================================================================
// Sovereign Graph Runner
// ============================================================================
// Orchestrates transformer inference using execution contracts
// Single decode step: Embedding → PreNorm → SelfAttention → Residual → FFN → Residual
// ============================================================================

#pragma once

#include "IExecutionBackend.hpp"
#include "ExecutionRequest.hpp"
#include "ExecutionResult.hpp"
#include "ExecutionTelemetry.hpp"

#include <memory>
#include <vector>
#include <string>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Transformer Layer Configuration
// ============================================================================

struct TransformerLayerConfig {
    uint32_t hidden_size = 4096;
    uint32_t num_heads = 32;
    uint32_t head_dim = 128;  // hidden_size / num_heads
    uint32_t intermediate_size = 11008;  // For SwiGLU FFN
    uint32_t max_seq_len = 4096;
    float rms_norm_eps = 1e-6f;
    
    // RoPE parameters
    float rope_theta = 10000.0f;
    bool use_ntk_scaling = false;
};

// ============================================================================
// Semantic Kernel Roles
// ============================================================================
// Used by GraphRunner to resolve kernels without hardcoding names

enum class KernelRole {
    EmbeddingLookup,      // Token to embedding
    PreNorm,              // RMSNorm before attention
    QKVProjection,        // Fused or separate Q,K,V
    RoPE,                 // Position embeddings
    SelfAttention,        // Attention computation
    AttentionOutput,      // Output projection
    PostAttentionResidual,// Skip connection
    FFN,                  // Feed-forward network
    PostFFNResidual,      // Skip connection
    FinalNorm,            // RMSNorm at end
    LMHead,               // Logits projection
    Sampling              // Token selection
};

// ============================================================================
// Kernel Registry Entry
// ============================================================================

struct KernelRegistryEntry {
    KernelRole role;
    std::string kernel_name;      // e.g., "Sovereign_RMSNorm_F32_AVX2"
    std::string backend_type;     // "cpu", "vulkan", "auto"
    bool available;
};

// ============================================================================
// Graph Runner State
// ============================================================================

struct GraphRunnerState {
    // Current position in sequence
    uint32_t current_seq_len = 0;
    uint32_t max_seq_len = 4096;
    
    // KV cache pointers (managed by backend)
    void* k_cache = nullptr;
    void* v_cache = nullptr;
    size_t kv_cache_size = 0;
    
    // RoPE cache (precomputed)
    void* rope_cache_sin = nullptr;
    void* rope_cache_cos = nullptr;
    
    // Activations (ping-pong buffers)
    void* activation_a = nullptr;
    void* activation_b = nullptr;
    size_t activation_size = 0;
};

// ============================================================================
// Sovereign Graph Runner
// ============================================================================
// Backend-agnostic transformer orchestrator
// ============================================================================

class SovereignGraphRunner {
public:
    SovereignGraphRunner();
    ~SovereignGraphRunner();
    
    // Initialization
    bool Initialize(std::shared_ptr<IExecutionBackend> backend,
                    const TransformerLayerConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Core transformer operations
    ExecutionResult Forward(const std::vector<int32_t>& input_tokens,
                           uint32_t max_new_tokens = 1);
    
    ExecutionResult ForwardSingleToken(int32_t input_token,
                                        uint32_t position);
    
    // Layer-by-layer (for debugging/profiling)
    ExecutionResult RunEmbedding(int32_t token_id);
    ExecutionResult RunPreNorm();
    ExecutionResult RunSelfAttention();
    ExecutionResult RunFFN();
    ExecutionResult RunFinalNorm();
    
    // KV cache management
    void ClearKVCache();
    void ResizeKVCache(uint32_t new_max_seq_len);
    
    // Registry management
    void RegisterKernel(KernelRole role, const std::string& kernel_name);
    bool HasKernel(KernelRole role) const;
    std::string GetKernelName(KernelRole role) const;
    
    // Telemetry
    ExecutionTelemetry GetLastTelemetry() const { return last_telemetry_; }
    void ResetTelemetry();
    
    // State inspection
    const GraphRunnerState& GetState() const { return state_; }

private:
    std::shared_ptr<IExecutionBackend> backend_;
    TransformerLayerConfig config_;
    GraphRunnerState state_;
    ExecutionTelemetry last_telemetry_;
    bool initialized_ = false;
    
    // Kernel registry
    std::vector<KernelRegistryEntry> kernel_registry_;
    
    // Internal helpers
    ExecutionResult DispatchKernel(KernelRole role,
                                    const ExecutionRequest& request);
    
    bool AllocateActivations();
    void FreeActivations();
    
    bool InitializeRoPECache();
    void FreeRoPECache();
    
    // Backend capability checks
    bool BackendSupportsKernel(const std::string& kernel_name) const;
};

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<SovereignGraphRunner> CreateGraphRunner(
    std::shared_ptr<IExecutionBackend> backend,
    const TransformerLayerConfig& config);

} // namespace Execution
} // namespace RawrXD
