#pragma once
/* B03: materialize non-expert layer slots for HOST_DECODE MiniMax. <=99. */
#include "MultiShardRootMaterialize.hpp"

namespace Deep2 {
namespace multishard_bind {

inline int MaterializeOne(WeightTensor& wt, const GlobalTensorIndex& idx,
                          size_t layer, const char* slot, int& fail) {
    if (wt.name.empty() && !wt.hasFileBacking) return 0;
    if (!wt.hasFileBacking || wt.sizeBytes == 0) {
        std::fprintf(stderr,
                     "B03_MAT_SKIP layer=%zu slot=%s name=%s why=NO_DESC\n",
                     layer, slot, wt.name.empty() ? "(empty)" : wt.name.c_str());
        return 0;
    }
    if (wt.data) return 1;
    const int ok = Materialize(wt, idx, /*quiet=*/1);
    if (!ok) {
        fail = 1;
        std::fprintf(stderr,
                     "B03_MAT_FAIL layer=%zu slot=%s name=%s shard=%u "
                     "rows=%zu cols=%zu bytes=%zu why=BACKING_UNRESOLVED\n",
                     layer, slot, wt.name.c_str(), wt.shardId, wt.rows, wt.cols,
                     wt.sizeBytes);
        return 0;
    }
    return 1;
}

inline void DematerializeOne(WeightTensor& wt) {
    if (!wt.data || !wt.mapped) return;
#ifdef _WIN32
    VirtualFree(wt.data, 0, MEM_RELEASE);
#endif
    wt.data = nullptr;
    wt.mapped = false;
}

inline void DematerializeLayerAttn(LayerWeights& lw) {
    /* Keep moeRouter resident — reinject is cheap; free attn/FFN norms only. */
    DematerializeOne(lw.attnNorm);
    DematerializeOne(lw.wq); DematerializeOne(lw.wk);
    DematerializeOne(lw.wv); DematerializeOne(lw.wo);
    DematerializeOne(lw.attnQNorm); DematerializeOne(lw.attnKNorm);
    DematerializeOne(lw.ffnNorm);
}

inline int MaterializeLayerAttn(LayerWeights& lw, const GlobalTensorIndex& idx,
                                size_t layer) {
    int n = 0, fail = 0;
    n += MaterializeOne(lw.attnNorm, idx, layer, "attn_norm", fail);
    n += MaterializeOne(lw.wq, idx, layer, "wq", fail);
    n += MaterializeOne(lw.wk, idx, layer, "wk", fail);
    n += MaterializeOne(lw.wv, idx, layer, "wv", fail);
    n += MaterializeOne(lw.wo, idx, layer, "wo", fail);
    n += MaterializeOne(lw.wqkv, idx, layer, "wqkv", fail);
    n += MaterializeOne(lw.attnQNorm, idx, layer, "attn_q_norm", fail);
    n += MaterializeOne(lw.attnKNorm, idx, layer, "attn_k_norm", fail);
    n += MaterializeOne(lw.ffnNorm, idx, layer, "ffn_norm", fail);
    n += MaterializeOne(lw.moeRouter, idx, layer, "moe_router", fail);
    n += MaterializeOne(lw.wGate, idx, layer, "wGate", fail);
    n += MaterializeOne(lw.moeSharedGate, idx, layer, "shared_gate", fail);
    n += MaterializeOne(lw.moeSharedUp, idx, layer, "shared_up", fail);
    n += MaterializeOne(lw.moeSharedDown, idx, layer, "shared_down", fail);
    if (fail) return -n;
    return n;
}

inline int MaterializeLayerAttn(LayerWeights& lw, const GlobalTensorIndex& idx) {
    return MaterializeLayerAttn(lw, idx, 0);
}
inline int MaterializeAllLayers(ModelWeights& mw, const GlobalTensorIndex& idx) {
    int total = 0, bad = 0;
    for (size_t i = 0; i < mw.layers.size(); ++i) {
        const int n = MaterializeLayerAttn(mw.layers[i], idx, i);
        if (n < 0) { bad = 1; total += -n; }
        else total += n;
    }
    std::fprintf(stderr, "B03_LAYER_MATERIALIZE slots=%d layers=%zu fail=%d\n",
                 total, mw.layers.size(), bad);
    return bad ? -total : total;
}

} // namespace multishard_bind
} // namespace Deep2
