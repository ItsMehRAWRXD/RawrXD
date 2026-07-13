// Phase I.2/5: Kernel Fusion
// Fuses multiple GPU kernels into single operations to reduce launch overhead
// and improve memory bandwidth utilization

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Optimization {

// ============================================================================
// Fusion Types
// ============================================================================

/// Types of kernel fusion patterns
enum class FusionPattern : uint8_t {
    // Element-wise operations
    RMSNORM_SILU = 0,           // RMSNorm + SiLU activation
    RMSNORM_MUL = 1,            // RMSNorm + element-wise multiply
    
    // Attention patterns
    QKV_PROJECTION = 2,         // Fuse Q, K, V projections
    ATTENTION_SCORE = 3,        // Q@K^T + softmax
    ATTENTION_OUTPUT = 4,       // softmax(Q@K^T) @ V
    
    // FFN patterns
    GATE_UP_PROJECTION = 5,     // Gate and up projections
    GATE_UP_SILU = 6,           // Gate + Up + SiLU + Mul
    
    // Embedding patterns
    EMBEDDING_ADD = 7,          // Token embedding + position embedding
    
    // Custom patterns
    CUSTOM = 255
};

/// Fusion configuration
struct FusionConfig {
    FusionPattern pattern;
    uint32_t block_size_x = 256;
    uint32_t block_size_y = 1;
    uint32_t block_size_z = 1;
    bool use_shared_memory = true;
    uint32_t shared_memory_bytes = 0;
    bool vectorize_loads = true;
    uint32_t vector_width = 4;  // float4
};

/// Performance metrics for fused kernel
struct FusionMetrics {
    uint64_t kernel_launches_saved;
    uint64_t memory_transactions_saved;
    double bandwidth_utilization_percent;
    double occupancy_percent;
    double speedup_vs_baseline;
};

// ============================================================================
// Kernel Fusion Engine
// ============================================================================

/// Manages kernel fusion operations
class KernelFusionEngine {
public:
    KernelFusionEngine();
    ~KernelFusionEngine();

    /// Initialize fusion engine
    bool Initialize();

    /// Shutdown
    void Shutdown();

    /// Register a fusion pattern
    bool RegisterPattern(FusionPattern pattern, 
                         const std::string& kernel_source,
                         const FusionConfig& config);

    /// Execute fused RMSNorm + SiLU
    bool FusedRMSNormSiLU(const void* input,
                          const void* weight,
                          void* output,
                          size_t num_elements,
                          float epsilon = 1e-6f);

    /// Execute fused QKV projection
    bool FusedQKVProjection(const void* input,
                              const void* q_weight,
                              const void* k_weight,
                              const void* v_weight,
                              void* q_output,
                              void* k_output,
                              void* v_output,
                              size_t batch_size,
                              size_t seq_len,
                              size_t hidden_dim,
                              size_t head_dim);

    /// Execute fused attention score computation
    bool FusedAttentionScore(const void* q,
                             const void* k,
                             void* scores,
                             size_t batch_size,
                             size_t num_heads,
                             size_t seq_len,
                             size_t head_dim,
                             float scale);

    /// Execute fused gate + up + SiLU
    bool FusedGateUpSiLU(const void* input,
                         const void* gate_weight,
                         const void* up_weight,
                         void* output,
                         size_t batch_size,
                         size_t hidden_dim,
                         size_t intermediate_dim);

    /// Get metrics for last fusion operation
    bool GetLastMetrics(FusionMetrics* metrics) const;

    /// Enable/disable fusion globally
    void SetFusionEnabled(bool enabled);

    /// Check if fusion is enabled
    bool IsFusionEnabled() const;

    /// Get supported patterns
    std::vector<FusionPattern> GetSupportedPatterns() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Auto-Tuner
// ============================================================================

/// Automatically tunes fusion parameters
class FusionAutoTuner {
public:
    FusionAutoTuner();
    ~FusionAutoTuner();

    /// Initialize tuner
    bool Initialize(KernelFusionEngine* engine);

    /// Run auto-tuning for a pattern
    bool TunePattern(FusionPattern pattern,
                     const std::vector<size_t>& problem_sizes);

    /// Get optimal config for pattern
    bool GetOptimalConfig(FusionPattern pattern,
                          size_t problem_size,
                          FusionConfig* config) const;

    /// Save tuning results
    bool SaveTuningResults(const std::string& filepath) const;

    /// Load tuning results
    bool LoadTuningResults(const std::string& filepath);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert pattern to string
const char* FusionPatternToString(FusionPattern pattern);

/// Estimate speedup from fusion
double EstimateFusionSpeedup(FusionPattern pattern,
                              size_t problem_size,
                              double baseline_bandwidth_gbps,
                              double fused_bandwidth_gbps);

/// Check if pattern is supported on current hardware
bool IsPatternSupported(FusionPattern pattern);

} // namespace Optimization
} // namespace RawrXD
