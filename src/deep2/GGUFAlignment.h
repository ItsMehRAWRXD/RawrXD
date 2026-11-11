// =============================================================================
// Blocker #10: GGUF Alignment — add padding to align tensors to 64 bytes
// =============================================================================

#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace GGUFAlignment {

// Default GGUF alignment is 32 bytes, but we want 64 for AVX-512
static const uint32_t GGUF_DEFAULT_ALIGNMENT = 32;
static const uint32_t TARGET_ALIGNMENT = 64;

static inline uint64_t alignOffset(uint64_t offset, uint32_t alignment) {
    return (offset + alignment - 1) & ~(static_cast<uint64_t>(alignment) - 1);
}

// Check if a tensor offset is properly aligned
static inline bool isAligned(uint64_t offset, uint32_t alignment) {
    return (offset % alignment) == 0;
}

// Calculate required padding between tensor offset and target alignment
static inline uint64_t calcPadding(uint64_t offset, uint32_t alignment) {
    uint64_t aligned = alignOffset(offset, alignment);
    return aligned - offset;
}

// Apply alignment to a list of tensor offsets
// Returns total padding added
struct TensorInfo {
    std::string name;
    uint64_t offset;
    uint64_t size;
    uint32_t type;
};

static uint64_t alignTensorOffsets(
    std::vector<TensorInfo>& tensors,
    uint32_t alignment,
    uint64_t tensorDataStart
) {
    uint64_t currentOffset = tensorDataStart;
    uint64_t totalPadding = 0;

    for (size_t i = 0; i < tensors.size(); i++) {
        // Align current offset
        uint64_t aligned = alignOffset(currentOffset, alignment);
        uint64_t pad = aligned - currentOffset;
        totalPadding += pad;

        tensors[i].offset = currentOffset - tensorDataStart;  // Relative offset
        currentOffset += pad + tensors[i].size;
    }

    return totalPadding;
}

// Log alignment warnings for tensors that are not 64-byte aligned
static void logAlignmentWarnings(
    const std::vector<TensorInfo>& tensors,
    uint64_t tensorDataStart,
    uint32_t fileAlignment
) {
    uint64_t currentOffset = tensorDataStart;

    for (size_t i = 0; i < tensors.size(); i++) {
        uint64_t absOffset = tensorDataStart + tensors[i].offset;

        if (!isAligned(absOffset, TARGET_ALIGNMENT)) {
            // Warning: tensor is not 64-byte aligned
            // This is non-fatal but will cause AVX-512 misalignment penalties
            // For read-only tensors loaded via mmap, we can work around this
            // by copying to aligned buffers on first access

            uint64_t pad = calcPadding(absOffset, TARGET_ALIGNMENT);
            // Log: "Warning: tensor '%s' offset %llu not 64-byte aligned (pad=%llu)"
            // For now, just track it
            (void)pad;
        }

        currentOffset = absOffset + tensors[i].size;
    }
}

// Copy a misaligned tensor to an aligned buffer
// This is the fallback when mmap'd data isn't aligned
static void* copyToAligned(
    const void* src,
    uint64_t size,
    uint32_t alignment
) {
#if defined(_WIN32)
    void* p = _aligned_malloc(size, alignment);
#else
    void* p = std::aligned_alloc(alignment, (size + alignment - 1) & ~(alignment - 1));
#endif
    if (p) {
        std::memcpy(p, src, static_cast<size_t>(size));
    }
    return p;
}

static void freeAligned(void* p) {
    if (!p) return;
#if defined(_WIN32)
    _aligned_free(p);
#else
    std::free(p);
#endif
}

}  // namespace GGUFAlignment