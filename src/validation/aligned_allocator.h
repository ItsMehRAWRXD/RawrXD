#pragma once

// ============================================================================
// Aligned Allocator for AVX-512 Kernels
// Guarantees 64-byte alignment for _mm512_ intrinsics
// ============================================================================

#include <cstddef>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <type_traits>

namespace RawrXD {

// ============================================================================
// Aligned Memory Functions
// ============================================================================

inline void* aligned_alloc(size_t size, size_t alignment = 64) {
    void* ptr = nullptr;
#ifdef _WIN32
    ptr = _aligned_malloc(size, alignment);
#else
    if (posix_memalign(&ptr, alignment, size) != 0) {
        ptr = nullptr;
    }
#endif
    if (!ptr) {
        throw std::bad_alloc();
    }
    return ptr;
}

inline void aligned_free(void* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

// ============================================================================
// Aligned Allocator Template
// ============================================================================

template<typename T, size_t Alignment = 64>
class AlignedAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = size_t;
    using difference_type = ptrdiff_t;

    template<typename U>
    struct rebind {
        using other = AlignedAllocator<U, Alignment>;
    };

    AlignedAllocator() noexcept = default;
    
    template<typename U>
    AlignedAllocator(const AlignedAllocator<U, Alignment>&) noexcept {}

    T* allocate(size_t n) {
        if (n == 0) return nullptr;
        // Use parentheses around max to prevent Windows macro expansion
        if (n > (std::numeric_limits<size_t>::max)() / sizeof(T)) {
            throw std::bad_alloc();
        }
        void* ptr = aligned_alloc(n * sizeof(T), Alignment);
        if (!ptr) {
            throw std::bad_alloc();
        }
        return static_cast<T*>(ptr);
    }

    void deallocate(T* ptr, size_t) noexcept {
        aligned_free(ptr);
    }

    template<typename U>
    bool operator==(const AlignedAllocator<U, Alignment>&) const noexcept {
        return true;
    }

    template<typename U>
    bool operator!=(const AlignedAllocator<U, Alignment>&) const noexcept {
        return false;
    }
};

// ============================================================================
// Aligned Vector (std::vector with guaranteed alignment)
// ============================================================================

template<typename T, size_t Alignment = 64>
using AlignedVector = std::vector<T, AlignedAllocator<T, Alignment>>;

// ============================================================================
// Aligned Buffer Wrapper (RAII)
// ============================================================================

class AlignedBuffer {
public:
    explicit AlignedBuffer(size_t size, size_t alignment = 64)
        : size_(size)
        , alignment_(alignment)
        , data_(static_cast<uint8_t*>(aligned_alloc(size, alignment))) {
        std::memset(data_, 0, size);
    }

    ~AlignedBuffer() {
        if (data_) {
            aligned_free(data_);
        }
    }

    // Move semantics
    AlignedBuffer(AlignedBuffer&& other) noexcept
        : size_(other.size_)
        , alignment_(other.alignment_)
        , data_(other.data_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    AlignedBuffer& operator=(AlignedBuffer&& other) noexcept {
        if (this != &other) {
            if (data_) {
                aligned_free(data_);
            }
            size_ = other.size_;
            alignment_ = other.alignment_;
            data_ = other.data_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    // No copy
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;

    // Accessors
    uint8_t* data() noexcept { return data_; }
    const uint8_t* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    size_t alignment() const noexcept { return alignment_; }

    // Verify alignment
    bool is_aligned() const noexcept {
        return (reinterpret_cast<uintptr_t>(data_) % alignment_) == 0;
    }

    // Verify AVX-512 alignment (64-byte boundary)
    bool is_avx512_aligned() const noexcept {
        return (reinterpret_cast<uintptr_t>(data_) % 64) == 0;
    }

private:
    size_t size_;
    size_t alignment_;
    uint8_t* data_;
};

// ============================================================================
// Tensor Buffer (Aligned + Shape Information)
// ============================================================================

struct TensorBuffer {
    AlignedBuffer data;
    std::vector<size_t> shape;
    size_t element_size;  // sizeof(float) = 4, sizeof(int32_t) = 4, etc.

    TensorBuffer(const std::vector<size_t>& dims, size_t elem_size = 4)
        : data(compute_size(dims, elem_size), 64)
        , shape(dims)
        , element_size(elem_size) {
        if (!data.is_avx512_aligned()) {
            throw std::runtime_error("TensorBuffer: Failed to achieve AVX-512 alignment");
        }
    }

    size_t total_elements() const {
        size_t total = 1;
        for (size_t dim : shape) total *= dim;
        return total;
    }

    size_t total_bytes() const {
        return total_elements() * element_size;
    }

    float* as_float() { return reinterpret_cast<float*>(data.data()); }
    int32_t* as_int32() { return reinterpret_cast<int32_t*>(data.data()); }
    const float* as_float() const { return reinterpret_cast<const float*>(data.data()); }
    const int32_t* as_int32() const { return reinterpret_cast<const int32_t*>(data.data()); }

private:
    static size_t compute_size(const std::vector<size_t>& dims, size_t elem_size) {
        size_t total = 1;
        for (size_t dim : dims) total *= dim;
        return total * elem_size;
    }
};

} // namespace RawrXD