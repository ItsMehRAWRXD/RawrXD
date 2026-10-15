#pragma once

/**
 * @file secure_buffer.h
 * @brief Memory-safety primitives for RawrXD (dependency-free C++20).
 *
 * The inference/IDE code paths move large byte buffers (model weights, KV
 * caches, token streams). Raw `new[]`/`memcpy` in those paths is the single
 * biggest source of exploitable bugs. This header provides:
 *
 *  - @ref RawrXD::Security::SecureBuffer : owning, bounds-checked heap buffer
 *    that zeroizes on destruction (and optionally pins itself in RAM with
 *    VirtualLock so weights/keys are never swapped to the page file).
 *  - @ref RawrXD::Security::secureZero : constant-time zeroization that the
 *    optimizer is not allowed to elide.
 *  - @ref RawrXD::Security::constantTimeEqual : timing-attack-resistant compare.
 *  - @ref RawrXD::Security::secureRandomBytes : CSPRNG bytes for IVs/salts.
 *
 * Design rule enforced here: every accessor is bounds-checked and returns a
 * failure signal instead of corrupting memory. An out-of-range access is a
 * detectable, loggable event -- never silent corruption and never a crash.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <type_traits>
#include <utility>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/mman.h>
#endif

namespace RawrXD {
namespace Security {

/// Zeroize @p len bytes at @p ptr. Never elided by the optimizer.
void secureZero(void* ptr, size_t len) noexcept;

/// Constant-time comparison of two byte ranges.
bool constantTimeEqual(const void* a, const void* b, size_t len) noexcept;

/// Fill @p len bytes at @p ptr with cryptographically strong randomness.
/// @return true on success.
bool secureRandomBytes(void* ptr, size_t len) noexcept;

/**
 * @brief Owning heap buffer with bounds-checked, zeroizing semantics.
 *
 * Differences from std::vector that matter for security work:
 *  - Contents are wiped before deallocation (no secrets/weights in freed pages).
 *  - `operator[]` can be used for trusted hot paths; the checked `at()`/`get()`
 *    accessors are the safe default for externally-indexed data.
 *  - Optional memory pinning (VirtualLock/MLOCK) so key material is never
 *    written to a swap file.
 *  - Copy is forbidden: accidental copies of key material are a footgun.
 *
 * @tparam T Trivially-copyable element type (float, uint8_t, Q8_K blocks...).
 */
template <typename T>
class SecureBuffer
{
    static_assert(std::is_trivially_copyable_v<T>,
                  "SecureBuffer requires a trivially copyable element type");

public:
    SecureBuffer() noexcept = default;

    explicit SecureBuffer(size_t count) { allocate(count); }

    // Copies of secret material are deliberately not permitted.
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept { moveFrom(std::move(other)); }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept
    {
        if (this != &other) {
            release();
            moveFrom(std::move(other));
        }
        return *this;
    }

    ~SecureBuffer() { release(); }

    // ------------------------------------------------------------
    // Allocation
    // ------------------------------------------------------------

    /// Allocate @p count zero-initialized elements. Any prior content is
    /// wiped. Returns false (leaving the buffer empty) on allocation failure.
    bool allocate(size_t count) noexcept
    {
        if (count == 0) { release(); return true; }
        if (count > maxSize()) return false;           // overflow / sane cap

        T* p = static_cast<T*>(::operator new(count * sizeof(T), std::nothrow_t{}));
        if (!p) return false;
        std::memset(p, 0, count * sizeof(T));
        release();
        m_data = p;
        m_size = count;
        return true;
    }

    /// Release and wipe the current buffer.
    void release() noexcept
    {
        if (m_data) {
            secureZero(m_data, m_size * sizeof(T));
            ::operator delete(m_data);
            m_data = nullptr;
        }
        m_size = 0;
        m_pinned = false;
    }

    // ------------------------------------------------------------
    // Observers
    // ------------------------------------------------------------

    T* data() noexcept { return m_data; }
    const T* data() const noexcept { return m_data; }
    size_t size() const noexcept { return m_size; }
    bool empty() const noexcept { return m_size == 0; }
    size_t sizeBytes() const noexcept { return m_size * sizeof(T); }

    std::span<T> view() noexcept { return {m_data, m_size}; }
    std::span<const T> view() const noexcept { return {m_data, m_size}; }

    // ------------------------------------------------------------
    // Checked access (the safe default)
    // ------------------------------------------------------------

    /// Bounds-checked pointer access. Returns nullptr when out of range.
    T* at(size_t index) noexcept
    {
        return (m_data && index < m_size) ? m_data + index : nullptr;
    }

    /// Bounds-checked pointer access (const).
    const T* at(size_t index) const noexcept
    {
        return (m_data && index < m_size) ? m_data + index : nullptr;
    }

    /// Bounds-checked element access. Returns @p fallback when out of range.
    T get(size_t index, const T& fallback = T{}) const noexcept
    {
        if (!m_data || index >= m_size) return fallback;
        return m_data[index];
    }

    /**
     * @brief Bounds-checked element write.
     * @return true if the index was in range (and the write happened).
     *
     * Fail-closed: an out-of-range write is reported, not silently clamped,
     * so the caller can log a validation failure.
     */
    bool set(size_t index, const T& value) noexcept
    {
        if (!m_data || index >= m_size) return false;
        m_data[index] = value;
        return true;
    }

    /// Bounds-checked sub-view: returns empty span unless [offset, offset+count) is valid.
    std::span<T> subspan(size_t offset, size_t count) noexcept
    {
        if (!m_data || offset > m_size || count > m_size - offset) return {};
        return {m_data + offset, count};
    }

    // ------------------------------------------------------------
    // Bulk operations (bounds-checked)
    // ------------------------------------------------------------

    /// Copy @p count elements from @p src into the buffer at @p offset.
    bool copyFrom(const T* src, size_t count, size_t offset = 0) noexcept
    {
        if (!src || count == 0) return count == 0;
        if (!m_data) return false;
        if (offset > m_size || count > m_size - offset) return false;
        std::memcpy(m_data + offset, src, count * sizeof(T));
        return true;
    }

    /// Copy @p count elements from @p offset into @p dst.
    bool copyTo(T* dst, size_t count, size_t offset = 0) const noexcept
    {
        if (!dst || count == 0) return count == 0;
        if (!m_data) return false;
        if (offset > m_size || count > m_size - offset) return false;
        std::memcpy(dst, m_data + offset, count * sizeof(T));
        return true;
    }

    /// Overwrite the entire buffer with zeros (keeps allocation).
    void zeroize() noexcept
    {
        if (m_data && m_size) secureZero(m_data, m_size * sizeof(T));
    }

    // ------------------------------------------------------------
    // Optional memory pinning (prevents swapping to disk)
    // ------------------------------------------------------------

    /// Attempt to lock pages in RAM (best effort).
    bool pin() noexcept
    {
        if (!m_data || m_pinned) return m_pinned;
#ifdef _WIN32
        m_pinned = ::VirtualLock(m_data, sizeBytes()) != 0;
#else
        m_pinned = ::mlock(m_data, sizeBytes()) == 0;
#endif
        return m_pinned;
    }

    /// Release the pinned state.
    void unpin() noexcept
    {
        if (!m_data || !m_pinned) return;
#ifdef _WIN32
        ::VirtualUnlock(m_data, sizeBytes());
#else
        ::munlock(m_data, sizeBytes());
#endif
        m_pinned = false;
    }

    bool isPinned() const noexcept { return m_pinned; }

private:
    static size_t maxSize() noexcept
    {
        // Guard against size_t overflow in count * sizeof(T).
        return (static_cast<size_t>(-1) - 1024) / sizeof(T);
    }

    void moveFrom(SecureBuffer&& other) noexcept
    {
        m_data = other.m_data;
        m_size = other.m_size;
        m_pinned = other.m_pinned;
        other.m_data = nullptr;
        other.m_size = 0;
        other.m_pinned = false;
    }

    T* m_data = nullptr;
    size_t m_size = 0;
    bool m_pinned = false;
};

/// Convenience alias for byte buffers (weights, keys, tensor blobs).
using SecureBytes = SecureBuffer<uint8_t>;

/// Convenience alias for float buffers (logits, embeddings, activations).
using SecureFloats = SecureBuffer<float>;

} // namespace Security
} // namespace RawrXD

// --------------------------------------------------------------------
// Convenience macros for terse, self-documenting call sites.
// --------------------------------------------------------------------
#define RAWRXD_SECURE_ZERO(ptr, len)  ::RawrXD::Security::secureZero((ptr), (len))
#define RAWRXD_CT_EQUAL(a, b, len)   ::RawrXD::Security::constantTimeEqual((a), (b), (len))
