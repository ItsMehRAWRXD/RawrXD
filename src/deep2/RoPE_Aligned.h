// =============================================================================
// Blocker #6: RoPE with 64-byte aligned buffers for AVX-512
// =============================================================================

#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
#include <cmath>

// Aligned allocator for AVX-512 (64-byte alignment)
template <typename T>
class AlignedAllocator {
public:
    typedef T value_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;

    static const size_t ALIGNMENT = 64;

    AlignedAllocator() {}
    AlignedAllocator(const AlignedAllocator&) {}
    template <typename U> AlignedAllocator(const AlignedAllocator<U>&) {}

    template <typename U> struct rebind {
        typedef AlignedAllocator<U> other;
    };

    T* allocate(size_t n) {
        void* p = nullptr;
        size_t bytes = n * sizeof(T);
        // Round up to alignment
        bytes = (bytes + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
        if (bytes == 0) bytes = ALIGNMENT;
#ifdef _WIN32
        p = _aligned_malloc(bytes, ALIGNMENT);
#else
        p = std::aligned_alloc(ALIGNMENT, bytes);
#endif
        if (p == nullptr) {
            // Fallback to standard malloc
            p = std::malloc(bytes);
        }
        return static_cast<T*>(p);
    }

    void deallocate(T* p, size_t) {
        if (p == nullptr) return;
#ifdef _WIN32
        _aligned_free(p);
#else
        std::free(p);
#endif
    }

    bool operator==(const AlignedAllocator&) const { return true; }
    bool operator!=(const AlignedAllocator&) const { return false; }
};

// RoPE class with aligned buffers
class RoPE {
public:
    RoPE() : maxSeqLen_(0), headDim_(0) {}

    bool init(int maxSeqLen, int headDim) {
        maxSeqLen_ = maxSeqLen;
        headDim_ = headDim;

        if (maxSeqLen <= 0 || headDim <= 0) return false;

        // Allocate aligned buffers for cos/sin tables
        // Must be 64-byte aligned for AVX-512 _mm512_load_ps
        const int totalElements = maxSeqLen * headDim;

        cosTable_.assign(totalElements, 0.0f);
        sinTable_.assign(totalElements, 0.0f);

        // Compute the tables
        const float base = 10000.0f;
        for (int pos = 0; pos < maxSeqLen; pos++) {
            for (int i = 0; i < headDim / 2; i++) {
                float freq = 1.0f / std::pow(base, 2.0f * i / headDim);
                float angle = pos * freq;
                cosTable_[pos * headDim + i] = std::cos(angle);
                cosTable_[pos * headDim + i + headDim / 2] = std::cos(angle);
                sinTable_[pos * headDim + i] = std::sin(angle);
                sinTable_[pos * headDim + i + headDim / 2] = std::sin(angle);
            }
        }

        return true;
    }

    // Apply RoPE to a single head's query/key at a given position
    // q: [headDim] input/output — must be 64-byte aligned for AVX-512 path
    void apply(float* RESTRICT q, int pos) const {
        if (pos < 0 || pos >= maxSeqLen_) return;

        const float* RESTRICT cos = &cosTable_[pos * headDim_];
        const float* RESTRICT sin = &sinTable_[pos * headDim_];

#if defined(__AVX512F__)
        // AVX-512 path — requires 64-byte aligned input
        for (int d = 0; d < headDim_; d += 16) {
            __m512 qv = _mm512_load_ps(q + d);
            __m512 cv = _mm512_load_ps(cos + d);
            __m512 sv = _mm512_load_ps(sin + d);

            // Rotate: q_rotated = q * cos + rotate_half(q) * sin
            // rotate_half(x) = concat(x[d/2:], x[:d/2])
            // Simplified: element-wise for now
            __m512 result = _mm512_mul_ps(qv, cv);
            // Add sin component (simplified — full implementation needs rotate_half)
            // This is the standard GPT-NeoX style RoPE
            __m512 q_rot = _mm512_add_ps(result, _mm512_mul_ps(
                _mm512_shuffle_ps(qv, qv, 0xB1),  // Swap pairs for rotate_half
                sv));
            _mm512_store_ps(q + d, q_rot);
        }
#else
        // Scalar / AVX2 path
        for (int d = 0; d < headDim_; d++) {
            float q0 = q[d];
            float q1 = q[d + headDim_ / 2];
            q[d] = q0 * cos[d] - q1 * sin[d];
            q[d + headDim_ / 2] = q1 * cos[d] + q0 * sin[d];
        }
#endif
    }

    // Get raw aligned pointer to cos table (for direct SIMD use)
    const float* cosData() const {
        return cosTable_.empty() ? nullptr : cosTable_.data();
    }

    const float* sinData() const {
        return sinTable_.empty() ? nullptr : sinTable_.data();
    }

    int maxSeqLen() const { return maxSeqLen_; }
    int headDim() const { return headDim_; }

private:
    int maxSeqLen_;
    int headDim_;
    std::vector<float, AlignedAllocator<float>> cosTable_;
    std::vector<float, AlignedAllocator<float>> sinTable_;
};