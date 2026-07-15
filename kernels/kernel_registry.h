/**
 * @file kernel_registry.h
 * @brief RawrXD L4.2.2 Kernel Registry and Dispatch
 *
 * Runtime kernel selection based on CPU features.
 * Provides unified interface for reference, AVX2, AVX512, and GPU kernels.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include "compression_codec.h"

namespace rawrxd {
namespace kernels {

// ============================================================================
// CPU Feature Detection
// ============================================================================

/**
 * @brief CPU capability flags
 */
struct CPUFeatures {
    bool has_sse2;
    bool has_avx;
    bool has_avx2;
    bool has_avx512f;
    bool has_avx512dq;
    bool has_fma;
    bool has_f16c;
    bool has_vnni;
    
    CPUFeatures()
        : has_sse2(false)
        , has_avx(false)
        , has_avx2(false)
        , has_avx512f(false)
        , has_avx512dq(false)
        , has_fma(false)
        , has_f16c(false)
        , has_vnni(false)
    {}
    
    bool HasAVX2() const { return has_avx2 && has_fma; }
    bool HasAVX512() const { return has_avx512f && has_avx512dq; }
};

/**
 * @brief Detect CPU features at runtime
 */
CPUFeatures DetectCPUFeatures();

// ============================================================================
// Kernel Types
// ============================================================================

/**
 * @brief Kernel function types
 */
using GemvFn = std::function<void(
    const void* weights,      // Compressed weights
    const float* input,       // Input vector
    float* output,            // Output vector
    size_t rows,              // Output dimension
    size_t cols,              // Input dimension
    compression::CompressionType codec
)>;

using RmsNormFn = std::function<void(
    float* data,              // In-place normalization
    size_t count,             // Element count
    float epsilon,            // Numerical stability
    float scale               // Scale factor (typically 1/sqrt(dim))
)>;

using RopeFn = std::function<void(
    float* q,                 // Query embeddings
    float* k,                 // Key embeddings
    size_t head_dim,          // Dimension per head
    size_t num_heads,         // Number of heads
    size_t seq_pos,           // Sequence position
    float theta               // RoPE base frequency
)>;

using SoftmaxFn = std::function<void(
    float* data,              // In-place softmax
    size_t count              // Element count
)>;

// ============================================================================
// Kernel Registry
// ============================================================================

/**
 * @brief Registry for kernel implementations
 *
 * Maintains multiple implementations per operation and selects
 * optimal kernel at runtime based on CPU features.
 */
class KernelRegistry {
public:
    enum class Implementation {
        REFERENCE,      // Portable, correct
        AVX2,           // x86-64 AVX2
        AVX512,         // x86-64 AVX-512
        GPU,            // GPU offload
        AUTO            // Select best available
    };
    
    // Singleton access
    static KernelRegistry& Instance();
    
    // Initialize with detected CPU features
    void Initialize();
    bool IsInitialized() const { return initialized_; }
    
    // Register kernel implementations
    void RegisterGemv(Implementation impl, GemvFn kernel);
    void RegisterRmsNorm(Implementation impl, RmsNormFn kernel);
    void RegisterRope(Implementation impl, RopeFn kernel);
    void RegisterSoftmax(Implementation impl, SoftmaxFn kernel);
    
    // Get kernel (auto-selects best if AUTO)
    GemvFn GetGemv(Implementation impl = Implementation::AUTO);
    RmsNormFn GetRmsNorm(Implementation impl = Implementation::AUTO);
    RopeFn GetRope(Implementation impl = Implementation::AUTO);
    SoftmaxFn GetSoftmax(Implementation impl = Implementation::AUTO);
    
    // Force specific implementation
    void SetPreferredGemv(Implementation impl) { preferred_gemv_ = impl; }
    void SetPreferredRmsNorm(Implementation impl) { preferred_rmsnorm_ = impl; }
    void SetPreferredRope(Implementation impl) { preferred_rope_ = impl; }
    void SetPreferredSoftmax(Implementation impl) { preferred_softmax_ = impl; }
    
    // Query available implementations
    bool HasGemv(Implementation impl) const;
    bool HasRmsNorm(Implementation impl) const;
    bool HasRope(Implementation impl) const;
    bool HasSoftmax(Implementation impl) const;
    
    // Get info
    std::string GetActiveImplementationName() const;
    const CPUFeatures& GetCPUFeatures() const { return cpu_features_; }
    
    // Benchmark and auto-select
    void AutoSelectKernels();
    
private:
    KernelRegistry() : initialized_(false) {}
    
    bool initialized_;
    CPUFeatures cpu_features_;
    
    Implementation preferred_gemv_;
    Implementation preferred_rmsnorm_;
    Implementation preferred_rope_;
    Implementation preferred_softmax_;
    
    std::map<Implementation, GemvFn> gemv_kernels_;
    std::map<Implementation, RmsNormFn> rmsnorm_kernels_;
    std::map<Implementation, RopeFn> rope_kernels_;
    std::map<Implementation, SoftmaxFn> softmax_kernels_;
    
    Implementation SelectBestGemv() const;
    Implementation SelectBestRmsNorm() const;
    Implementation SelectBestRope() const;
    Implementation SelectBestSoftmax() const;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Initialize registry with all available kernels
void InitializeKernelRegistry();

// Get kernels (shorthand)
GemvFn GetGemvKernel();
RmsNormFn GetRmsNormKernel();
RopeFn GetRopeKernel();
SoftmaxFn GetSoftmaxKernel();

// ============================================================================
// Batched Operations
// ============================================================================

/**
 * @brief Batched GEMV for transformer projections
 *
 * Performs multiple GEMV operations in sequence (Q, K, V projections)
 */
class BatchedGemv {
public:
    struct Projection {
        const void* weights;              // Compressed weights
        const float* input;               // Input (shared or per-projection)
        float* output;                    // Output buffer
        size_t out_dim;                   // Output dimension
        size_t in_dim;                    // Input dimension
        compression::CompressionType codec;
    };
    
    // Execute batch of projections
    static void Execute(
        const std::vector<Projection>& projections,
        KernelRegistry::Implementation impl = KernelRegistry::Implementation::AUTO
    );
    
    // Execute Q/K/V projections (common transformer pattern)
    static void ExecuteQKV(
        const void* q_weights,
        const void* k_weights,
        const void* v_weights,
        const float* input,
        float* q_output,
        float* k_output,
        float* v_output,
        size_t head_dim,
        size_t num_heads,
        size_t seq_len,
        compression::CompressionType codec,
        KernelRegistry::Implementation impl = KernelRegistry::Implementation::AUTO
    );
};

// ============================================================================
// Transformer Primitive Pipeline
// ============================================================================

/**
 * @brief Validated transformer primitive pipeline
 *
 * Executes RMSNorm → QKV Projection → RoPE with validation gates.
 */
class TransformerPrimitivePipeline {
public:
    struct Config {
        size_t hidden_dim;
        size_t num_heads;
        size_t head_dim;
        size_t num_kv_heads;      // For GQA
        float rms_norm_eps;
        float rope_theta;
    };
    
    struct Input {
        const float* hidden_state;  // [hidden_dim]
        size_t seq_pos;           // Current sequence position
    };
    
    struct Output {
        float* q;                 // [num_heads * head_dim]
        float* k;                 // [num_kv_heads * head_dim]
        float* v;                 // [num_kv_heads * head_dim]
    };
    
    struct Weights {
        const void* q_proj;       // Compressed
        const void* k_proj;
        const void* v_proj;
        const void* o_proj;       // Optional
        compression::CompressionType codec;
    };
    
    // Execute pipeline
    static bool Execute(
        const Config& config,
        const Input& input,
        const Weights& weights,
        Output& output,
        KernelRegistry::Implementation impl = KernelRegistry::Implementation::AUTO
    );
    
    // Execute with validation
    static bool ExecuteValidated(
        const Config& config,
        const Input& input,
        const Weights& weights,
        Output& output,
        std::vector<std::string>* out_errors = nullptr
    );
};

} // namespace kernels
} // namespace rawrxd
