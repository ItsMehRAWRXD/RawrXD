#pragma once
//
// Expansion of DeepSeek's fused attn_kv_b matrix into the per-head keys and
// values the attention consumes.
//
// The layout is a contract, not an implementation detail: llama.cpp's
// deepseek2.cpp expands the fused matrix one row block per head, and a model
// that carries the fused attn_kv_b has to be expanded that way. Treating the
// rows as grouped by projection instead gives every head the wrong weights,
// and the attention then produces NaN hidden states. That mistake was made
// twice in this tree, once silently, so the expansion lives in one place and
// is covered by a regression test.
//
// The MLA absorption optimization, which projects the query through the key
// up-projection and keeps the cache kvLora wide, needs the *split* attn_k_b
// and attn_v_b tensors. A GGUF with the fused attn_kv_b does not have them.

#include "Deep2Types.hpp"

#include <cstdint>
#include <vector>

namespace Deep2Rom {

// Expand the fused matrix into per-head keys and values.
//
// `fused` is the row-major matrix of shape [numHeads * (qkNope + vHead)][kvLora].
// `keys` receives numHeads * qkNope values, `values` numHeads * vHead, both
// laid out head-major.
//
// The buffers are resized as needed.
inline void expandFusedAttnKvB(const float* fused, const MlaKvBLayout& layout,
                                std::vector<float>& keys, std::vector<float>& values) {
    keys.resize((size_t)layout.numHeads * layout.qkNope);
    values.resize((size_t)layout.numHeads * layout.vHead);

    for (uint32_t h = 0; h < layout.numHeads; ++h) {
        const float* keySrc = fused + layout.keyOffset(h);
        float* keyDst = keys.data() + (size_t)h * layout.qkNope;
        for (uint32_t d = 0; d < layout.qkNope; ++d) {
            keyDst[d] = keySrc[d];
        }

        const float* valSrc = fused + layout.valueOffset(h);
        float* valDst = values.data() + (size_t)h * layout.vHead;
        for (uint32_t d = 0; d < layout.vHead; ++d) {
            valDst[d] = valSrc[d];
        }
    }
}

}  // namespace Deep2Rom
