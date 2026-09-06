// K2MLAAttention.hpp — Gate 12 complete MLA attention (RoPE / softmax / KV)
#pragma once
#include <cstdint>
#include <string>

namespace rawrxd::deep2 { class K2KVCache; }

namespace Deep2 {

struct MlaCompleteStats {
    bool ropeApplied = false;
    bool softmaxFinite = false;
    bool kvCacheWrite = false;
    bool kvCacheRead = false;
    uint32_t kvLength = 0;
};

// Complete single-token MLA attention. Requires non-null kvCache.
// q_b: [H * qHeadDim], k_b: [H * qkNope], v_b: [H * vHead], k_pe: [qkRope]
// attnOut: [H * vHead] (caller pads to oRows if needed)
bool MlaAttentionComplete(
    const float* q_b, const float* k_b, const float* v_b, float* k_pe,
    float* attnOut,
    size_t numHeads, size_t qkNopeHeadDim, size_t qkRopeHeadDim,
    size_t vHeadDim, size_t qHeadDim,
    uint32_t position, float ropeTheta, float ropeScale,
    rawrxd::deep2::K2KVCache* kvCache, uint32_t layerIdx,
    MlaCompleteStats* stats, std::string& error);

} // namespace Deep2
