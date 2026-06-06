// SovereignLayerExecutor.h
// Phase 2 Hardened: Multi-type tensor dispatch (Q4_0 / F32 / F16 / Q6_K stub)
// Header-only implementation for easy test harness integration

#ifndef SOVEREIGN_LAYER_EXECUTOR_H
#define SOVEREIGN_LAYER_EXECUTOR_H

#include <cstdint>
#include <cstddef>
#include <immintrin.h>

// ------------------------------------------------------------------------------
// GGML type constants (match ggml.h enum)
// ------------------------------------------------------------------------------
enum GGMLType : uint32_t {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q8_1 = 9,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q6_K = 14,
};

// ------------------------------------------------------------------------------
// External MASM kernel declarations (linked from Sovereign_GEMM_Q4_F32.obj)
// ------------------------------------------------------------------------------
extern "C" {
    void Sovereign_GEMM_Q4_F32(
        const void* pWeights,
        const float* pInput,
        float* pOutput,
        int nElementCount
    );
}

// ------------------------------------------------------------------------------
// Tensor descriptor
// ------------------------------------------------------------------------------
struct SovereignTensorRef {
    const char* name;
    uint32_t    ggml_type;
    uint32_t    n_dims;
    uint64_t    dims[4];
    uint64_t    file_offset;
    uint64_t    size_bytes;
};

// ------------------------------------------------------------------------------
// Alignment validation
// ------------------------------------------------------------------------------
constexpr uint64_t SOVEREIGN_ALIGN = 512;

static inline bool IsAligned512(const void* ptr) {
    return (reinterpret_cast<uintptr_t>(ptr) & (SOVEREIGN_ALIGN - 1)) == 0;
}

static inline bool IsAligned64(const void* ptr) {
    return (reinterpret_cast<uintptr_t>(ptr) & 63) == 0;
}

static inline void SovereignAlignPanic(const char* tensor_name) {
    __debugbreak();
    (void)tensor_name;
}

// ------------------------------------------------------------------------------
// Fallback kernels
// ------------------------------------------------------------------------------
static inline void Sovereign_GEMV_F32_AVX2(
    const float* weight_row,
    const float* input,
    float* output,
    int n_cols
) {
    __m256 acc = _mm256_setzero_ps();
    int i = 0;
    for (; i + 8 <= n_cols; i += 8) {
        __m256 w = _mm256_loadu_ps(weight_row + i);
        __m256 v = _mm256_loadu_ps(input + i);
        acc = _mm256_fmadd_ps(w, v, acc);
    }
    __m128 lo = _mm256_castps256_ps128(acc);
    __m128 hi = _mm256_extractf128_ps(acc, 1);
    lo = _mm_add_ps(lo, hi);
    lo = _mm_hadd_ps(lo, lo);
    lo = _mm_hadd_ps(lo, lo);
    float sum = _mm_cvtss_f32(lo);
    for (; i < n_cols; ++i) {
        sum += weight_row[i] * input[i];
    }
    *output = sum;
}

static inline void Sovereign_GEMV_F16_AVX2(
    const void* weight_row_f16,
    const float* input,
    float* output,
    int n_cols
) {
    const uint16_t* w16 = static_cast<const uint16_t*>(weight_row_f16);
    __m256 acc = _mm256_setzero_ps();
    int i = 0;
    for (; i + 8 <= n_cols; i += 8) {
        __m128i w16v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(w16 + i));
        __m256 w = _mm256_cvtph_ps(w16v);
        __m256 v = _mm256_loadu_ps(input + i);
        acc = _mm256_fmadd_ps(w, v, acc);
    }
    __m128 lo = _mm256_castps256_ps128(acc);
    __m128 hi = _mm256_extractf128_ps(acc, 1);
    lo = _mm_add_ps(lo, hi);
    lo = _mm_hadd_ps(lo, lo);
    lo = _mm_hadd_ps(lo, lo);
    float sum = _mm_cvtss_f32(lo);
    for (; i < n_cols; ++i) {
        __m128i tmp = _mm_cvtsi32_si128(static_cast<int>(w16[i]));
        __m128 f32x = _mm_cvtph_ps(tmp);
        sum += _mm_cvtss_f32(f32x) * input[i];
    }
    *output = sum;
}

static inline void Sovereign_GEMV_Q6_K_Stub(
    const void* weight_row,
    const float* input,
    float* output,
    int n_cols
) {
    (void)weight_row; (void)input; (void)output; (void)n_cols;
    __debugbreak();
}

// ------------------------------------------------------------------------------
// Unified type dispatch
// ------------------------------------------------------------------------------
static inline void Sovereign_DispatchGEMV(
    uint32_t ggml_type,
    const void* weight_row,
    const float* input,
    float* output,
    int n_cols
) {
    switch (ggml_type) {
        case GGML_TYPE_Q4_0:
            Sovereign_GEMM_Q4_F32(weight_row, input, output, n_cols);
            break;
        case GGML_TYPE_F32:
            Sovereign_GEMV_F32_AVX2(static_cast<const float*>(weight_row), input, output, n_cols);
            break;
        case GGML_TYPE_F16:
            Sovereign_GEMV_F16_AVX2(weight_row, input, output, n_cols);
            break;
        case GGML_TYPE_Q6_K:
            Sovereign_GEMV_Q6_K_Stub(weight_row, input, output, n_cols);
            break;
        default:
            __debugbreak();
            break;
    }
}

// ------------------------------------------------------------------------------
// Row stride calculators per type
// ------------------------------------------------------------------------------
static inline int Sovereign_GetRowStrideBytes(uint32_t ggml_type, int n_cols) {
    switch (ggml_type) {
        case GGML_TYPE_Q4_0:
            return (n_cols / 32) * 18;
        case GGML_TYPE_F32:
            return n_cols * sizeof(float);
        case GGML_TYPE_F16:
            return n_cols * sizeof(uint16_t);
        case GGML_TYPE_Q6_K:
            return 0;
        default:
            return 0;
    }
}

// ------------------------------------------------------------------------------
// Layer executor
// ------------------------------------------------------------------------------
class SovereignLayerExecutor {
public:
    static void ExecuteGEMV(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        const uint8_t* weight_data = arena_base + w_desc.file_offset;
        if (!IsAligned512(weight_data)) {
            SovereignAlignPanic(w_desc.name);
        }
        if (!IsAligned64(input) || !IsAligned64(output)) {
            SovereignAlignPanic("input/output buffer");
        }

        const int n_rows = static_cast<int>(w_desc.dims[1]);
        const int n_cols = static_cast<int>(w_desc.dims[0]);
        const int row_stride = Sovereign_GetRowStrideBytes(w_desc.ggml_type, n_cols);
        if (row_stride == 0 && w_desc.ggml_type != GGML_TYPE_Q6_K) {
            SovereignAlignPanic("invalid row stride");
        }

        for (int row = 0; row < n_rows; ++row) {
            const void* row_weights = weight_data + (row * row_stride);
            Sovereign_DispatchGEMV(w_desc.ggml_type, row_weights, input, &output[row], n_cols);
        }
    }

    static void ExecuteAttentionQProj(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        ExecuteGEMV(w_desc, arena_base, input, output);
    }

    static void ExecuteAttentionKProj(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        ExecuteGEMV(w_desc, arena_base, input, output);
    }

    static void ExecuteAttentionVProj(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        ExecuteGEMV(w_desc, arena_base, input, output);
    }

    static void ExecuteAttentionOutProj(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        ExecuteGEMV(w_desc, arena_base, input, output);
    }

    static void ExecuteFFNUp(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        ExecuteGEMV(w_desc, arena_base, input, output);
    }

    static void ExecuteFFNGate(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        ExecuteGEMV(w_desc, arena_base, input, output);
    }

    static void ExecuteFFNDown(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        ExecuteGEMV(w_desc, arena_base, input, output);
    }

    static void ExecuteOutputProj(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output
    ) {
        ExecuteGEMV(w_desc, arena_base, input, output);
    }

    static void ExecuteRMSNorm(
        const SovereignTensorRef& w_desc,
        uint8_t* arena_base,
        const float* input,
        float* output,
        int n_elements
    ) {
        if (w_desc.ggml_type != GGML_TYPE_F32) {
            __debugbreak();
        }
        const float* weights = reinterpret_cast<const float*>(arena_base + w_desc.file_offset);
        int i = 0;
        for (; i + 8 <= n_elements; i += 8) {
            __m256 w = _mm256_loadu_ps(weights + i);
            __m256 v = _mm256_loadu_ps(input + i);
            __m256 r = _mm256_mul_ps(v, w);
            _mm256_storeu_ps(output + i, r);
        }
        for (; i < n_elements; ++i) {
            output[i] = input[i] * weights[i];
        }
    }
};

#endif // SOVEREIGN_LAYER_EXECUTOR_H

