// SovereignKVCache.hpp
// Phase 3.1 — Flat ring-buffer KV cache for transformer generation
// Deterministic, no allocator, 512-byte aligned buffers
//
// Layout: k_cache[layer][pos][dim]  v_cache[layer][pos][dim]
// For ministral3: 34 layers × 128 ctx × 1024 dim × 4B = ~17MB each

#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace RawrXD {
namespace AI {

struct SovereignKVCache {
    uint32_t n_layer = 0;      // Number of transformer layers
    uint32_t n_ctx = 0;        // Maximum context window (ring buffer size)
    uint32_t n_embd_k = 0;     // K dimension per token (e.g., 1024)
    uint32_t n_embd_v = 0;     // V dimension per token (e.g., 1024)

    float* k_cache = nullptr;  // Flat: [layer][pos][dim]
    float* v_cache = nullptr;  // Flat: [layer][pos][dim]
    uint32_t seq_len = 0;      // Current write position / sequence length

    // Initialize aligned buffers. Returns false on allocation failure.
    bool Initialize(uint32_t layers, uint32_t ctx, uint32_t embd_k, uint32_t embd_v);

    // Free aligned buffers
    void Free();

    // Reset for new sequence (does not free memory)
    void Reset() { seq_len = 0; }

    // Write K/V for a specific layer at current seq_len, then advance
    // Call AFTER computing K/V projections for the new token
    void WriteK(uint32_t layer, const float* k_data);
    void WriteV(uint32_t layer, const float* v_data);

    // Read K/V pointer for a specific layer and position
    // Valid positions: 0 .. seq_len-1
    const float* ReadK(uint32_t layer, uint32_t pos) const;
    const float* ReadV(uint32_t layer, uint32_t pos) const;

    // Total bytes allocated
    size_t TotalBytes() const;

private:
    static float* AlignedAllocF32(size_t count);
    static void   AlignedFree(void* ptr);

    size_t k_stride_layer_ = 0;  // bytes between layer starts in k_cache
    size_t v_stride_layer_ = 0;  // bytes between layer starts in v_cache
};

} // namespace AI
} // namespace RawrXD
