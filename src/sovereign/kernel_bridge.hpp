// kernel_bridge.hpp
// RawrXD Sovereign Kernel Bridge v1.0
// Direct ExecutionSpine → KernelDispatcher adapter for maximum compression
//
// Design: Zero-copy buffer mapping, AVX-512 first dispatch, GFLOPS/Watt telemetry

#ifndef KERNEL_BRIDGE_HPP
#define KERNEL_BRIDGE_HPP

#include "execution_contract.h"
#include <cstdint>
#include <memory>
#include <vector>
#include <chrono>

// Include the actual KernelDispatcher header
#include "kernel_dispatch/KernelDispatcher.hpp"

namespace sovereign {

// ============================================================================
// KERNEL BRIDGE - Spine-to-Kernel Adapter
// ============================================================================

struct KernelBuffer {
    // Aligned memory for AVX-512 (64-byte alignment)
    float* data = nullptr;
    size_t size = 0;
    size_t capacity = 0;
    
    // Metadata for tensor mapping
    struct TensorShape {
        size_t dims[4] = {0, 0, 0, 0};
        size_t rank = 0;
        size_t stride[4] = {0, 0, 0, 0};
    } shape;
    
    bool allocate(size_t num_floats);
    void release();
    bool is_aligned() const;
    
    // Map from GGUF tensor data (zero-copy where possible)
    bool map_from_gguf(const void* gguf_data, size_t num_elements, int gguf_type);
};

struct KernelTelemetry {
    // Timing (microseconds for precision)
    std::chrono::microseconds kernel_dispatch_time{0};
    std::chrono::microseconds memory_transfer_time{0};
    std::chrono::microseconds total_op_time{0};
    
    // Compute metrics
    double gflops_executed = 0.0;
    double gflops_per_watt = 0.0;  // Estimated
    double tokens_per_ms = 0.0;
    
    // Dispatch decisions
    bool used_avx512 = false;
    bool used_avx2 = false;
    bool fell_back_to_scalar = false;
    std::string kernel_path_taken;
    
    // Memory
    size_t peak_memory_mb = 0;
    size_t cache_friendly_accesses = 0;
    size_t cache_unfriendly_accesses = 0;
    
    void accumulate(const KernelTelemetry& other);
    std::string to_json() const;
};

// ============================================================================
// KERNEL OPERATION TYPES
// ============================================================================

enum class KernelOpType {
    MatMul,           // C = A @ B
    MatMulAccumulate, // C += A @ B
    RMSNorm,          // Root mean square normalization
    LayerNorm,        // Layer normalization
    SiLU,             // Swish activation
    GELU,             // GELU activation
    Softmax,          // Softmax normalization
    VecDot,           // Vector dot product
    VecScale,         // Vector scaling
    VecAdd,           // Vector addition
    AttentionQK,      // Q @ K^T for attention
    AttentionSoftmaxV, // Softmax @ V for attention
    DequantizeQ4_0,   // Dequantize Q4_0 blocks
    DequantizeQ8_0,   // Dequantize Q8_0 blocks
    LoRAApply         // LoRA weight application
};

struct KernelOperation {
    KernelOpType type;
    std::vector<KernelBuffer*> inputs;
    KernelBuffer* output = nullptr;
    
    // Operation-specific parameters
    union {
        struct { float alpha; float beta; } matmul;
        struct { float eps; } norm;
        struct { float scale; } vecscale;
        struct { size_t seq_len; size_t head_dim; float scale; } attention;
    } params;
    
    // Estimated compute cost (for scheduling)
    double estimated_gflops = 0.0;
    
    // Preferred variant (Auto = let dispatcher decide)
    int preferred_variant = 0; // 0=Auto, 1=AVX512, 2=AVX2, 3=Scalar
};

// ============================================================================
// KERNEL BRIDGE CLASS
// ============================================================================

class KernelBridge {
public:
    KernelBridge();
    ~KernelBridge();
    
    // Initialize with CPU feature detection
    bool initialize();
    void shutdown();
    bool is_initialized() const { return m_initialized; }
    
    // Core execution interface
    bool execute_operation(const KernelOperation& op, KernelTelemetry& telemetry);
    bool execute_batch(const std::vector<KernelOperation>& ops, KernelTelemetry& telemetry);
    
    // Direct tensor operations (convenience wrappers)
    bool matmul(const KernelBuffer& A, const KernelBuffer& B, KernelBuffer& C,
                size_t M, size_t N, size_t K, KernelTelemetry& telemetry);
    
    bool rmsnorm(const KernelBuffer& input, const KernelBuffer& weight, 
                 KernelBuffer& output, size_t N, float eps, KernelTelemetry& telemetry);
    
    bool silu(const KernelBuffer& input, KernelBuffer& output, 
              size_t N, KernelTelemetry& telemetry);
    
    bool softmax(const KernelBuffer& input, KernelBuffer& output,
                 size_t N, KernelTelemetry& telemetry);
    
    bool vec_dot(const KernelBuffer& A, const KernelBuffer& B, 
                 float& result, size_t N, KernelTelemetry& telemetry);
    
    // Quantized operations
    bool dequantize_q4_0(const void* src, float* dst, size_t num_blocks, KernelTelemetry& telemetry);
    bool dequantize_q8_0(const void* src, float* dst, size_t num_blocks, KernelTelemetry& telemetry);
    
    // Transformer layer (composite operation)
    bool transformer_layer(
        const KernelBuffer& input,           // [batch, seq_len, hidden_dim]
        const KernelBuffer& qkv_weight,        // [hidden_dim, 3 * hidden_dim]
        const KernelBuffer& o_proj_weight,   // [hidden_dim, hidden_dim]
        const KernelBuffer& ffn_gate_weight, // [hidden_dim, ffn_dim]
        const KernelBuffer& ffn_up_weight,   // [hidden_dim, ffn_dim]
        const KernelBuffer& ffn_down_weight, // [ffn_dim, hidden_dim]
        const KernelBuffer& norm_weight,     // [hidden_dim]
        KernelBuffer& output,
        size_t batch, size_t seq_len, size_t hidden_dim, size_t ffn_dim,
        size_t num_heads, size_t head_dim,
        KernelTelemetry& telemetry
    );
    
    // Telemetry aggregation
    const KernelTelemetry& get_accumulated_telemetry() const { return m_accumulated; }
    void reset_telemetry() { m_accumulated = KernelTelemetry(); }
    
    // CPU feature queries
    bool has_avx512() const { return m_has_avx512; }
    bool has_avx2() const { return m_has_avx2; }
    bool has_fma() const { return m_has_fma; }
    std::string get_cpu_features_string() const;
    
    // Performance profiling
    struct ProfileSnapshot {
        double avg_tokens_per_ms = 0.0;
        double peak_gflops = 0.0;
        double avg_gflops_per_watt = 0.0;
        size_t total_ops_executed = 0;
        size_t avx512_ops = 0;
        size_t avx2_ops = 0;
        size_t scalar_fallbacks = 0;
    };
    ProfileSnapshot get_profile_snapshot() const;

private:
    bool m_initialized = false;
    bool m_has_avx512 = false;
    bool m_has_avx2 = false;
    bool m_has_fma = false;
    
    std::unique_ptr<RawrXD::Kernel::KernelDispatcher> m_dispatcher;
    KernelTelemetry m_accumulated;
    
    size_t m_total_ops = 0;
    size_t m_avx512_ops = 0;
    size_t m_avx2_ops = 0;
    size_t m_scalar_ops = 0;
    
    // Internal dispatch helpers
    bool dispatch_matmul(const KernelOperation& op, KernelTelemetry& telemetry);
    bool dispatch_norm(const KernelOperation& op, KernelTelemetry& telemetry);
    bool dispatch_activation(const KernelOperation& op, KernelTelemetry& telemetry);
    bool dispatch_attention(const KernelOperation& op, KernelTelemetry& telemetry);
    bool dispatch_quantized(const KernelOperation& op, KernelTelemetry& telemetry);
    
    void update_telemetry(KernelTelemetry& telemetry, bool used_avx512, bool used_avx2, 
                          double gflops, const std::string& path);
};

// ============================================================================
// INTEGRATION HELPERS
// ============================================================================

// Bridge the ExecutionRequest/Result with kernel operations
class KernelExecutionAdapter {
public:
    // Convert ExecutionRequest to kernel operation sequence
    static std::vector<KernelOperation> build_inference_pipeline(
        const ExecutionRequest& request,
        const std::vector<uint32_t>& input_tokens,
        size_t vocab_size,
        size_t hidden_dim,
        size_t num_layers
    );
    
    // Populate ExecutionResult with kernel telemetry
    static void populate_telemetry(ExecutionResult& result, const KernelTelemetry& telemetry);
    
    // Estimate GFLOPS for an operation
    static double estimate_gflops(const KernelOperation& op);
};

} // namespace sovereign

#endif // KERNEL_BRIDGE_HPP
