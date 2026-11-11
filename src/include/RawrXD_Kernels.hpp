//=============================================================================
// RawrXD Kernel Interop Layer
// Phase 21 - C++/MASM Bridge
// Provides type-safe, zero-overhead dispatch to MASM kernels
//=============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <immintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

//=============================================================================
// MASM Kernel Exports (cdecl convention for MSVC interop)
//=============================================================================

/// ApplyLoRA baseline kernel
/// @param output   Destination buffer (rows * cols floats, 64-byte aligned)
/// @param input    Source buffer (rows * cols floats, 64-byte aligned)
/// @param weights  LoRA weight matrix (rows * cols floats, 64-byte aligned)
/// @param rows     Matrix row count
/// @param cols     Matrix column count
/// @param alpha    Scaling factor
void __cdecl ApplyLoRA(
    void* output,
    const void* input,
    const void* weights,
    int32_t rows,
    int32_t cols,
    float alpha
);

/// ApplyLoRA optimized kernel (AVX-512, prefetch, unrolled)
/// @param output   Destination buffer (rows * cols floats, 64-byte aligned)
/// @param input    Source buffer (rows * cols floats, 64-byte aligned)
/// @param weights  LoRA weight matrix (rows * cols floats, 64-byte aligned)
/// @param rows     Matrix row count
/// @param cols     Matrix column count
/// @param alpha    Scaling factor
void __cdecl ApplyLoRA_Fixed(
    void* output,
    const void* input,
    const void* weights,
    int32_t rows,
    int32_t cols,
    float alpha
);

/// Matrix multiplication AVX-512 kernel
/// @param C        Output matrix (M x N)
/// @param A        Input matrix A (M x K)
/// @param B        Input matrix B (K x N)
/// @param M        Rows of A and C
/// @param N        Columns of B and C
/// @param K        Inner dimension
void __cdecl MatMul_AVX512(
    float* C,
    const float* A,
    const float* B,
    int32_t M,
    int32_t N,
    int32_t K
);

/// Fused RMSNorm kernel
/// @param output   Normalized output (N floats, 64-byte aligned)
/// @param input    Input buffer (N floats, 64-byte aligned)
/// @param weight   Scale weights (N floats, 64-byte aligned)
/// @param N        Element count
/// @param eps      Epsilon for numerical stability
void __cdecl RMSNorm_Fused(
    float* output,
    const float* input,
    const float* weight,
    int32_t N,
    float eps
);

#ifdef __cplusplus
}
#endif

namespace RawrXD {
namespace Kernels {

//=============================================================================
// C++ RAII Wrapper Classes
//=============================================================================

/// Aligned buffer allocator for kernel inputs/outputs
/// Ensures 64-byte alignment required by AVX-512 kernels
template<typename T>
class AlignedBuffer {
public:
    explicit AlignedBuffer(size_t count)
        : m_count(count)
        , m_data(static_cast<T*>(_aligned_malloc(count * sizeof(T), 64)))
    {
        if (!m_data) {
            throw std::bad_alloc();
        }
    }

    ~AlignedBuffer() {
        if (m_data) {
            _aligned_free(m_data);
        }
    }

    // Non-copyable
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;

    // Movable
    AlignedBuffer(AlignedBuffer&& other) noexcept
        : m_count(other.m_count)
        , m_data(other.m_data)
    {
        other.m_count = 0;
        other.m_data = nullptr;
    }

    AlignedBuffer& operator=(AlignedBuffer&& other) noexcept {
        if (this != &other) {
            if (m_data) _aligned_free(m_data);
            m_count = other.m_count;
            m_data = other.m_data;
            other.m_count = 0;
            other.m_data = nullptr;
        }
        return *this;
    }

    [[nodiscard]] T* data() noexcept { return m_data; }
    [[nodiscard]] const T* data() const noexcept { return m_data; }
    [[nodiscard]] size_t size() const noexcept { return m_count; }
    [[nodiscard]] size_t byte_size() const noexcept { return m_count * sizeof(T); }

    [[nodiscard]] T& operator[](size_t idx) { return m_data[idx]; }
    [[nodiscard]] const T& operator[](size_t idx) const { return m_data[idx]; }

    void zero() noexcept {
        memset(m_data, 0, m_count * sizeof(T));
    }

    void fill(T value) noexcept {
        for (size_t i = 0; i < m_count; ++i) {
            m_data[i] = value;
        }
    }

private:
    size_t m_count;
    T* m_data;
};

using FloatBuffer = AlignedBuffer<float>;
using Int32Buffer = AlignedBuffer<int32_t>;

//=============================================================================
// Kernel Dispatch Interface
//=============================================================================

enum class KernelVariant {
    Baseline,       ///< Reference implementation
    Optimized,      ///< AVX-512 + prefetch + unroll
    Auto            ///< Select based on CPU features
};

class KernelDispatcher {
public:
    static KernelDispatcher& instance();

    /// Detect available CPU features at runtime
    void detect_cpu_features();

    /// Apply LoRA transformation
    /// @param output   Destination (must be 64-byte aligned)
    /// @param input    Source (must be 64-byte aligned)
    /// @param weights  LoRA weights (must be 64-byte aligned)
    /// @param rows     Matrix dimensions
    /// @param cols     Matrix dimensions
    /// @param alpha    Scaling factor
    /// @param variant  Kernel variant to use
    void apply_lora(
        float* output,
        const float* input,
        const float* weights,
        int32_t rows,
        int32_t cols,
        float alpha,
        KernelVariant variant = KernelVariant::Auto
    );

    /// Matrix multiplication
    void matmul(
        float* C,
        const float* A,
        const float* B,
        int32_t M,
        int32_t N,
        int32_t K,
        KernelVariant variant = KernelVariant::Auto
    );

    /// RMSNorm normalization
    void rmsnorm(
        float* output,
        const float* input,
        const float* weight,
        int32_t N,
        float eps = 1e-6f,
        KernelVariant variant = KernelVariant::Auto
    );

    [[nodiscard]] bool has_avx512() const noexcept { return m_has_avx512; }
    [[nodiscard]] bool has_avx2() const noexcept { return m_has_avx2; }
    [[nodiscard]] bool has_fma() const noexcept { return m_has_fma; }

private:
    KernelDispatcher() { detect_cpu_features(); }

    bool m_has_avx512 = false;
    bool m_has_avx2 = false;
    bool m_has_fma = false;
    bool m_initialized = false;
};

} // namespace Kernels
} // namespace RawrXD
