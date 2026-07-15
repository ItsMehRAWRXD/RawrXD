/**
 * @file kernel_registry.cpp
 * @brief RawrXD L4.2.2 Kernel Registry Implementation
 *
 * Runtime kernel selection and transformer primitive pipeline.
 *
 * @copyright RawrXD 2026
 */

#include "kernel_registry.h"
#include "fused_quant_gemm.h"
#include <immintrin.h>
#include <intrin.h>  // For __cpuid, __cpuidex on Windows
#include <cstring>
#include <cmath>

namespace rawrxd {
namespace kernels {

// ============================================================================
// CPU Feature Detection
// ============================================================================

CPUFeatures DetectCPUFeatures() {
    CPUFeatures features;
    
    int cpu_info[4] = {0};
    
    // Get vendor string and max basic function
    __cpuid(cpu_info, 0);
    int max_basic = cpu_info[0];
    
    if (max_basic >= 1) {
        __cpuid(cpu_info, 1);
        
        // Check feature flags
        features.has_sse2 = (cpu_info[3] & (1 << 26)) != 0;
        features.has_avx = (cpu_info[2] & (1 << 28)) != 0;
        features.has_f16c = (cpu_info[2] & (1 << 29)) != 0;
        features.has_fma = (cpu_info[2] & (1 << 12)) != 0;
    }
    
    if (max_basic >= 7) {
        __cpuidex(cpu_info, 7, 0);
        
        features.has_avx2 = (cpu_info[1] & (1 << 5)) != 0;
        features.has_avx512f = (cpu_info[1] & (1 << 16)) != 0;
        features.has_avx512dq = (cpu_info[1] & (1 << 17)) != 0;
        features.has_vnni = (cpu_info[2] & (1 << 11)) != 0;
    }
    
    return features;
}

// ============================================================================
// Reference Kernel Implementations
// ============================================================================

void ReferenceGemv(
    const void* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols,
    compression::CompressionType codec
) {
    // Decompress and compute
    auto codec_impl = compression::CodecFactory::Create(codec);
    if (!codec_impl) return;
    
    std::vector<float> decompressed(rows * cols);
    codec_impl->DecodeBlock(
        static_cast<const uint8_t*>(weights),
        decompressed.data(),
        rows * cols
    );
    
    // Reference GEMV
    for (size_t r = 0; r < rows; ++r) {
        double sum = 0.0;
        for (size_t c = 0; c < cols; ++c) {
            sum += decompressed[r * cols + c] * input[c];
        }
        output[r] = static_cast<float>(sum);
    }
}

void ReferenceRmsNorm(
    float* data,
    size_t count,
    float epsilon,
    float scale
) {
    // Compute RMS
    double sum_sq = 0.0;
    for (size_t i = 0; i < count; ++i) {
        sum_sq += data[i] * data[i];
    }
    
    float rms = static_cast<float>(std::sqrt(sum_sq / count + epsilon));
    float inv_rms = 1.0f / rms;
    
    // Normalize and scale
    for (size_t i = 0; i < count; ++i) {
        data[i] = data[i] * inv_rms * scale;
    }
}

void ReferenceRope(
    float* q,
    float* k,
    size_t head_dim,
    size_t num_heads,
    size_t seq_pos,
    float theta
) {
    // RoPE: Rotary Position Embedding
    for (size_t h = 0; h < num_heads; ++h) {
        for (size_t d = 0; d < head_dim; d += 2) {
            size_t idx = h * head_dim + d;
            
            // Compute rotation angle
            float angle = seq_pos / std::pow(theta, static_cast<float>(d) / head_dim);
            float cos_val = std::cos(angle);
            float sin_val = std::sin(angle);
            
            // Rotate Q
            float q0 = q[idx];
            float q1 = q[idx + 1];
            q[idx] = q0 * cos_val - q1 * sin_val;
            q[idx + 1] = q0 * sin_val + q1 * cos_val;
            
            // Rotate K
            float k0 = k[idx];
            float k1 = k[idx + 1];
            k[idx] = k0 * cos_val - k1 * sin_val;
            k[idx + 1] = k0 * sin_val + k1 * cos_val;
        }
    }
}

void ReferenceSoftmax(
    float* data,
    size_t count
) {
    // Find max for numerical stability
    float max_val = data[0];
    for (size_t i = 1; i < count; ++i) {
        max_val = std::max(max_val, data[i]);
    }
    
    // Compute exp and sum
    double sum_exp = 0.0;
    for (size_t i = 0; i < count; ++i) {
        data[i] = std::exp(data[i] - max_val);
        sum_exp += data[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / static_cast<float>(sum_exp);
    for (size_t i = 0; i < count; ++i) {
        data[i] *= inv_sum;
    }
}

// ============================================================================
// AVX2 Kernel Implementations
// ============================================================================

void AVX2RmsNorm(
    float* data,
    size_t count,
    float epsilon,
    float scale
) {
    // Compute sum of squares using AVX2
    __m256 sum_vec = _mm256_setzero_ps();
    size_t i = 0;
    
    for (; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        sum_vec = _mm256_fmadd_ps(vec, vec, sum_vec);
    }
    
    // Horizontal sum
    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, sum_vec);
    double sum_sq = sum_arr[0] + sum_arr[1] + sum_arr[2] + sum_arr[3] +
                    sum_arr[4] + sum_arr[5] + sum_arr[6] + sum_arr[7];
    
    // Remainder
    for (; i < count; ++i) {
        sum_sq += data[i] * data[i];
    }
    
    float rms = std::sqrt(static_cast<float>(sum_sq) / count + epsilon);
    float inv_rms = scale / rms;
    
    __m256 scale_vec = _mm256_set1_ps(inv_rms);
    
    // Apply normalization
    for (i = 0; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        vec = _mm256_mul_ps(vec, scale_vec);
        _mm256_storeu_ps(&data[i], vec);
    }
    
    for (; i < count; ++i) {
        data[i] *= inv_rms;
    }
}

void AVX2Softmax(
    float* data,
    size_t count
) {
    // Find max
    __m256 max_vec = _mm256_set1_ps(-1e30f);
    size_t i = 0;
    
    for (; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        max_vec = _mm256_max_ps(max_vec, vec);
    }
    
    float max_arr[8];
    _mm256_storeu_ps(max_arr, max_vec);
    float max_val = max_arr[0];
    for (int j = 1; j < 8; ++j) {
        max_val = std::max(max_val, max_arr[j]);
    }
    
    for (; i < count; ++i) {
        max_val = std::max(max_val, data[i]);
    }
    
    // Compute exp and sum
    __m256 max_vec_broadcast = _mm256_set1_ps(max_val);
    __m256 sum_vec = _mm256_setzero_ps();
    
    for (i = 0; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        vec = _mm256_sub_ps(vec, max_vec_broadcast);
        // Manual exp approximation (fast, less accurate - replace with proper impl)
        // For now, fall back to scalar for exp
        float temp[8];
        _mm256_storeu_ps(temp, vec);
        for (int j = 0; j < 8; ++j) {
            temp[j] = std::exp(temp[j]);
        }
        vec = _mm256_loadu_ps(temp);
        sum_vec = _mm256_add_ps(sum_vec, vec);
        _mm256_storeu_ps(&data[i], vec);
    }
    
    // Sum and normalize (simplified)
    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, sum_vec);
    double sum_exp = 0.0;
    for (int j = 0; j < 8; ++j) sum_exp += sum_arr[j];
    
    for (; i < count; ++i) {
        data[i] = std::exp(data[i] - max_val);
        sum_exp += data[i];
    }
    
    float inv_sum = 1.0f / static_cast<float>(sum_exp);
    __m256 inv_sum_vec = _mm256_set1_ps(inv_sum);
    
    for (i = 0; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        vec = _mm256_mul_ps(vec, inv_sum_vec);
        _mm256_storeu_ps(&data[i], vec);
    }
    
    for (; i < count; ++i) {
        data[i] *= inv_sum;
    }
}

// ============================================================================
// Kernel Registry Implementation
// ============================================================================

KernelRegistry& KernelRegistry::Instance() {
    static KernelRegistry instance;
    return instance;
}

void KernelRegistry::Initialize() {
    cpu_features_ = DetectCPUFeatures();
    initialized_ = true;
    
    // Register reference implementations (always available)
    RegisterGemv(Implementation::REFERENCE, ReferenceGemv);
    RegisterRmsNorm(Implementation::REFERENCE, ReferenceRmsNorm);
    RegisterRope(Implementation::REFERENCE, ReferenceRope);
    RegisterSoftmax(Implementation::REFERENCE, ReferenceSoftmax);
    
    // Register AVX2 implementations if available
    if (cpu_features_.HasAVX2()) {
        // Note: FusedQuantGemm::GemvAuto has different signature, needs wrapper
        // For now, use reference
        // RegisterGemv(Implementation::AVX2, FusedQuantGemm::GemvAuto);
        RegisterRmsNorm(Implementation::AVX2, AVX2RmsNorm);
        RegisterSoftmax(Implementation::AVX2, AVX2Softmax);
        // RoPE AVX2 would be registered here
    }
    
    // Auto-select best implementations
    AutoSelectKernels();
}

void KernelRegistry::RegisterGemv(Implementation impl, GemvFn kernel) {
    gemv_kernels_[impl] = kernel;
}

void KernelRegistry::RegisterRmsNorm(Implementation impl, RmsNormFn kernel) {
    rmsnorm_kernels_[impl] = kernel;
}

void KernelRegistry::RegisterRope(Implementation impl, RopeFn kernel) {
    rope_kernels_[impl] = kernel;
}

void KernelRegistry::RegisterSoftmax(Implementation impl, SoftmaxFn kernel) {
    softmax_kernels_[impl] = kernel;
}

GemvFn KernelRegistry::GetGemv(Implementation impl) {
    if (impl == Implementation::AUTO) {
        impl = SelectBestGemv();
    }
    
    auto it = gemv_kernels_.find(impl);
    if (it != gemv_kernels_.end()) {
        return it->second;
    }
    
    // Fallback to reference
    return gemv_kernels_[Implementation::REFERENCE];
}

RmsNormFn KernelRegistry::GetRmsNorm(Implementation impl) {
    if (impl == Implementation::AUTO) {
        impl = SelectBestRmsNorm();
    }
    
    auto it = rmsnorm_kernels_.find(impl);
    if (it != rmsnorm_kernels_.end()) {
        return it->second;
    }
    
    return rmsnorm_kernels_[Implementation::REFERENCE];
}

RopeFn KernelRegistry::GetRope(Implementation impl) {
    if (impl == Implementation::AUTO) {
        impl = SelectBestRope();
    }
    
    auto it = rope_kernels_.find(impl);
    if (it != rope_kernels_.end()) {
        return it->second;
    }
    
    return rope_kernels_[Implementation::REFERENCE];
}

SoftmaxFn KernelRegistry::GetSoftmax(Implementation impl) {
    if (impl == Implementation::AUTO) {
        impl = SelectBestSoftmax();
    }
    
    auto it = softmax_kernels_.find(impl);
    if (it != softmax_kernels_.end()) {
        return it->second;
    }
    
    return softmax_kernels_[Implementation::REFERENCE];
}

bool KernelRegistry::HasGemv(Implementation impl) const {
    return gemv_kernels_.find(impl) != gemv_kernels_.end();
}

bool KernelRegistry::HasRmsNorm(Implementation impl) const {
    return rmsnorm_kernels_.find(impl) != rmsnorm_kernels_.end();
}

bool KernelRegistry::HasRope(Implementation impl) const {
    return rope_kernels_.find(impl) != rope_kernels_.end();
}

bool KernelRegistry::HasSoftmax(Implementation impl) const {
    return softmax_kernels_.find(impl) != softmax_kernels_.end();
}

std::string KernelRegistry::GetActiveImplementationName() const {
    if (cpu_features_.HasAVX512()) return "AVX-512";
    if (cpu_features_.HasAVX2()) return "AVX2";
    return "Reference";
}

void KernelRegistry::AutoSelectKernels() {
    preferred_gemv_ = SelectBestGemv();
    preferred_rmsnorm_ = SelectBestRmsNorm();
    preferred_rope_ = SelectBestRope();
    preferred_softmax_ = SelectBestSoftmax();
}

KernelRegistry::Implementation KernelRegistry::SelectBestGemv() const {
    if (HasGemv(Implementation::AVX512)) return Implementation::AVX512;
    if (HasGemv(Implementation::AVX2)) return Implementation::AVX2;
    return Implementation::REFERENCE;
}

KernelRegistry::Implementation KernelRegistry::SelectBestRmsNorm() const {
    if (HasRmsNorm(Implementation::AVX512)) return Implementation::AVX512;
    if (HasRmsNorm(Implementation::AVX2)) return Implementation::AVX2;
    return Implementation::REFERENCE;
}

KernelRegistry::Implementation KernelRegistry::SelectBestRope() const {
    if (HasRope(Implementation::AVX512)) return Implementation::AVX512;
    if (HasRope(Implementation::AVX2)) return Implementation::AVX2;
    return Implementation::REFERENCE;
}

KernelRegistry::Implementation KernelRegistry::SelectBestSoftmax() const {
    if (HasSoftmax(Implementation::AVX512)) return Implementation::AVX512;
    if (HasSoftmax(Implementation::AVX2)) return Implementation::AVX2;
    return Implementation::REFERENCE;
}

// ============================================================================
// Convenience Functions
// ============================================================================

void InitializeKernelRegistry() {
    KernelRegistry::Instance().Initialize();
}

GemvFn GetGemvKernel() {
    return KernelRegistry::Instance().GetGemv();
}

RmsNormFn GetRmsNormKernel() {
    return KernelRegistry::Instance().GetRmsNorm();
}

RopeFn GetRopeKernel() {
    return KernelRegistry::Instance().GetRope();
}

SoftmaxFn GetSoftmaxKernel() {
    return KernelRegistry::Instance().GetSoftmax();
}

// ============================================================================
// Batched GEMV
// ============================================================================

void BatchedGemv::Execute(
    const std::vector<Projection>& projections,
    KernelRegistry::Implementation impl
) {
    auto gemv = KernelRegistry::Instance().GetGemv(impl);
    
    for (const auto& proj : projections) {
        gemv(proj.weights, proj.input, proj.output,
             proj.out_dim, proj.in_dim, proj.codec);
    }
}

void BatchedGemv::ExecuteQKV(
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
    KernelRegistry::Implementation impl
) {
    auto gemv = KernelRegistry::Instance().GetGemv(impl);
    
    size_t hidden_dim = head_dim * num_heads;
    
    // Q projection
    gemv(q_weights, input, q_output, hidden_dim, hidden_dim, codec);
    
    // K projection
    gemv(k_weights, input, k_output, hidden_dim, hidden_dim, codec);
    
    // V projection
    gemv(v_weights, input, v_output, hidden_dim, hidden_dim, codec);
}

// ============================================================================
// Transformer Primitive Pipeline
// ============================================================================

bool TransformerPrimitivePipeline::Execute(
    const Config& config,
    const Input& input,
    const Weights& weights,
    Output& output,
    KernelRegistry::Implementation impl
) {
    // Get kernels
    auto rmsnorm = KernelRegistry::Instance().GetRmsNorm(impl);
    auto gemv = KernelRegistry::Instance().GetGemv(impl);
    auto rope = KernelRegistry::Instance().GetRope(impl);
    
    // Step 1: RMSNorm on input
    std::vector<float> normalized(config.hidden_dim);
    std::memcpy(normalized.data(), input.hidden_state, config.hidden_dim * sizeof(float));
    
    rmsnorm(normalized.data(), config.hidden_dim, config.rms_norm_eps, 1.0f);
    
    // Step 2: QKV projections
    gemv(weights.q_proj, normalized.data(), output.q,
         config.num_heads * config.head_dim, config.hidden_dim, weights.codec);
    
    gemv(weights.k_proj, normalized.data(), output.k,
         config.num_kv_heads * config.head_dim, config.hidden_dim, weights.codec);
    
    gemv(weights.v_proj, normalized.data(), output.v,
         config.num_kv_heads * config.head_dim, config.hidden_dim, weights.codec);
    
    // Step 3: Apply RoPE to Q and K
    rope(output.q, output.k, config.head_dim, config.num_heads,
         input.seq_pos, config.rope_theta);
    
    return true;
}

bool TransformerPrimitivePipeline::ExecuteValidated(
    const Config& config,
    const Input& input,
    const Weights& weights,
    Output& output,
    std::vector<std::string>* out_errors
) {
    // Validate inputs
    if (!input.hidden_state) {
        if (out_errors) out_errors->push_back("Input hidden_state is null");
        return false;
    }
    
    if (!output.q || !output.k || !output.v) {
        if (out_errors) out_errors->push_back("Output buffers are null");
        return false;
    }
    
    if (config.hidden_dim == 0 || config.head_dim == 0 || config.num_heads == 0) {
        if (out_errors) out_errors->push_back("Invalid config dimensions");
        return false;
    }
    
    // Execute with reference kernel for validation
    std::vector<float> ref_q(config.num_heads * config.head_dim);
    std::vector<float> ref_k(config.num_kv_heads * config.head_dim);
    std::vector<float> ref_v(config.num_kv_heads * config.head_dim);
    
    Output ref_output;
    ref_output.q = ref_q.data();
    ref_output.k = ref_k.data();
    ref_output.v = ref_v.data();
    
    // Run reference
    Execute(config, input, weights, ref_output, KernelRegistry::Implementation::REFERENCE);
    
    // Run optimized
    bool success = Execute(config, input, weights, output, KernelRegistry::Implementation::AUTO);
    
    if (!success) {
        if (out_errors) out_errors->push_back("Optimized execution failed");
        return false;
    }
    
    // Validate outputs (cosine similarity)
    // Simplified - would use proper validation
    float q_dot = 0.0f, q_norm_ref = 0.0f, q_norm_opt = 0.0f;
    for (size_t i = 0; i < config.num_heads * config.head_dim; ++i) {
        q_dot += ref_q[i] * output.q[i];
        q_norm_ref += ref_q[i] * ref_q[i];
        q_norm_opt += output.q[i] * output.q[i];
    }
    
    float cosine = q_dot / (std::sqrt(q_norm_ref) * std::sqrt(q_norm_opt) + 1e-8f);
    
    if (cosine < 0.999f) {
        if (out_errors) {
            out_errors->push_back("Q projection cosine below threshold: " + std::to_string(cosine));
        }
        return false;
    }
    
    return true;
}

} // namespace kernels
} // namespace rawrxd
