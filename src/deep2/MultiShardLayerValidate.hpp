#pragma once
/* B03: fail-closed MiniMax layer attn validity before forward. <=99. */
#include "Deep2Engine.h"
#include <cstdio>

namespace Deep2 {
namespace multishard_bind {

/* valid = descriptor && shape && backingResolvable && consumerSupported */
inline int LayerAttnValid(const LayerWeights& lw, size_t layer, FILE* f) {
    auto bad = [&](const char* slot, const WeightTensor& wt, const char* why) {
        std::fprintf(f,
                     "B03_LAYER_INVALID layer=%zu slot=%s name=%s shard=%u "
                     "data=%d fileBack=%d rows=%zu cols=%zu bytes=%zu why=%s\n",
                     layer, slot, wt.name.empty() ? "(empty)" : wt.name.c_str(),
                     wt.shardId, wt.data ? 1 : 0, wt.hasFileBacking ? 1 : 0,
                     wt.rows, wt.cols, wt.sizeBytes, why);
        return 0;
    };
    auto ok = [&](const char* slot, const WeightTensor& wt) -> int {
        if (wt.name.empty()) return bad(slot, wt, "UNBOUND_DESCRIPTOR");
        if (wt.rows == 0 || wt.cols == 0 || wt.sizeBytes == 0)
            return bad(slot, wt, "SHAPE");
        if (!wt.hasFileBacking && !wt.data)
            return bad(slot, wt, "BACKING_UNRESOLVABLE");
        /* data may be null until MaterializeLayerAttn before consumer. */
        if (wt.rows * wt.cols == 0) return bad(slot, wt, "CONSUMER_UNSUPPORTED");
        return 1;
    };
    if (!ok("attn_norm", lw.attnNorm)) return 0;
    if (!ok("wq", lw.wq)) return 0;
    if (!ok("wk", lw.wk)) return 0;
    if (!ok("wv", lw.wv)) return 0;
    if (!ok("wo", lw.wo)) return 0;
    if (!ok("ffn_norm", lw.ffnNorm)) return 0;
    if (!ok("moe_router", lw.moeRouter)) return 0;
    if (!lw.attnQNorm.name.empty() && !ok("attn_q_norm", lw.attnQNorm)) return 0;
    if (!lw.attnKNorm.name.empty() && !ok("attn_k_norm", lw.attnKNorm)) return 0;
    if (lw.wq.rows % 128u != 0) return bad("wq", lw.wq, "HEAD_DIM_Q_NOT_128_ALIGNED");
    if (lw.wk.rows % 128u != 0) return bad("wk", lw.wk, "HEAD_DIM_K_NOT_128_ALIGNED");
    if (lw.wv.rows % 128u != 0) return bad("wv", lw.wv, "HEAD_DIM_V_NOT_128_ALIGNED");
    return 1;
}

inline void DumpLayer0BindTable(const LayerWeights& lw, FILE* f) {
    if (!f) return;
    auto row = [&](const char* slot, const WeightTensor& wt) {
        std::fprintf(f,
                     "B03_L0_BIND slot=%s name=%s shard=%u rows=%zu cols=%zu "
                     "type=%d bytes=%zu data=%d fileBack=%d\n",
                     slot, wt.name.empty() ? "(empty)" : wt.name.c_str(),
                     wt.shardId, wt.rows, wt.cols, wt.type, wt.sizeBytes,
                     wt.data ? 1 : 0, wt.hasFileBacking ? 1 : 0);
    };
    row("attn_norm", lw.attnNorm);
    row("wq", lw.wq); row("wk", lw.wk); row("wv", lw.wv); row("wo", lw.wo);
    row("attn_q_norm", lw.attnQNorm); row("attn_k_norm", lw.attnKNorm);
    row("ffn_norm", lw.ffnNorm); row("moe_router", lw.moeRouter);
}

inline int ValidateAllLayers(const ModelWeights& mw, FILE* f = stderr) {
    if (!f) f = stderr;
    if (!mw.layers.empty()) DumpLayer0BindTable(mw.layers[0], f);
    size_t ok = 0;
    for (size_t i = 0; i < mw.layers.size(); ++i)
        ok += static_cast<size_t>(LayerAttnValid(mw.layers[i], i, f));
    const int pass = (ok == mw.layers.size() && !mw.layers.empty()) ? 1 : 0;
    std::fprintf(f,
                 "B03_LAYER_TENSORS_VALID=%zu/%zu\n"
                 "B03_ATTENTION_BIND_VALID=%d\n",
                 ok, mw.layers.size(), pass);
    return pass;
}

} // namespace multishard_bind
} // namespace Deep2
