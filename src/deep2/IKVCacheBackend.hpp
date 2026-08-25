// ============================================================================
// IKVCacheBackend.hpp — Unified KV Cache Interface
// Production abstraction: one interface, multiple implementations.
//
// Implementations:
//   - LegacyKVCacheAdapter  → wraps existing KVCache.cpp
//   - ToroidalKVCacheAdapter → wraps ToroidalKVCache (ring buffer)
//
// The attention layer consumes this interface exclusively.
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>

namespace Deep2 {

// ============================================================================
// Span descriptor for zero-copy KV reads
// A logical token range may map to 1 or 2 contiguous physical spans.
// ============================================================================
struct KVSpan {
    const float* keys   = nullptr;
    const float* values = nullptr;
    size_t       count  = 0;
    size_t       physicalSlot = 0;
    size_t       stride = 0;   // Floats between consecutive tokens in this span
};

// ============================================================================
// IKVCacheBackend — Abstract KV cache interface
// ============================================================================
class IKVCacheBackend {
public:
    virtual ~IKVCacheBackend() = default;

    // Initialize with model dimensions
    virtual bool initialize(size_t numLayers, size_t maxSeqLen,
                            size_t numHeads, size_t headDim) = 0;

    // Reset for new sequence (O(1) preferred)
    virtual void reset() = 0;

    // Write K/V for a specific layer and head at the current position
    virtual bool writeKV(size_t layer, size_t head,
                         const float* keyData, const float* valueData) = 0;

    // Advance to next token position after all layers/heads written
    virtual void advance() = 0;

    // Query K/V spans for attention over [startPos, endPos) for a layer+head
    // Returns number of spans (0, 1, or 2). Populates span0 and optionally span1.
    virtual size_t querySpans(size_t layer, size_t head,
                              size_t startPos, size_t endPos,
                              KVSpan& span0, KVSpan& span1) const = 0;

    // Current sequence length (number of tokens cached)
    virtual size_t currentLength() const = 0;

    virtual size_t maxLength()     const = 0;
    virtual size_t headDimSize()   const = 0;

    // Memory usage in bytes
    virtual size_t memoryBytes() const = 0;

    // Check if cache is full
    virtual bool isFull() const = 0;
};

} // namespace Deep2
