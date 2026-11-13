#pragma once
/* B02/B03: multi-shard root/layer bind + materialize + validate. ≤99. */
#include "MultiShardLayerMaterialize.hpp"
#include "MultiShardLayerValidate.hpp"
#include <cstdio>

namespace Deep2 {
namespace multishard_bind {

inline WeightTensor FromRef(const GlobalTensorRef& ref) {
    WeightTensor wt;
    wt.type = static_cast<int>(ref.ggmlType);
    if (ref.shape.size() >= 2) {
        wt.rows = static_cast<size_t>(ref.shape[1]);
        wt.cols = static_cast<size_t>(ref.shape[0]);
    } else if (ref.shape.size() == 1) {
        wt.rows = static_cast<size_t>(ref.shape[0]);
        wt.cols = 1;
    }
    wt.sizeBytes = static_cast<size_t>(ref.byteSize);
    wt.name = ref.name;
    wt.shardId = ref.shardId;
    wt.fileOffset = ref.fileOffset;
    wt.hasFileBacking = true;
    return wt;
}

inline void BindLayerTensor(LayerWeights& lw, const GlobalTensorRef& ref) {
    const std::string& n = ref.name;
    WeightTensor wt = FromRef(ref);
    if (n.find("attn_qkv") != std::string::npos) lw.wqkv = wt;
    else if (n.find("attn_output.weight") != std::string::npos) lw.wo = wt;
    else if (n.find("attn_q.weight") != std::string::npos) lw.wq = wt;
    else if (n.find("attn_k.weight") != std::string::npos) lw.wk = wt;
    else if (n.find("attn_v.weight") != std::string::npos) lw.wv = wt;
    else if (n.find("attn_q_norm") != std::string::npos) lw.attnQNorm = wt;
    else if (n.find("attn_k_norm") != std::string::npos) lw.attnKNorm = wt;
    else if (n.find("attn_norm") != std::string::npos) lw.attnNorm = wt;
    else if (n.find("ffn_gate_inp") != std::string::npos) lw.moeRouter = wt;
    else if (n.find("ffn_up_exps") != std::string::npos) lw.wUp = wt;
    else if (n.find("ffn_down_exps") != std::string::npos) lw.wDown = wt;
    else if (n.find("ffn_gate_shexp") != std::string::npos) lw.moeSharedGate = wt;
    else if (n.find("ffn_up_shexp") != std::string::npos) lw.moeSharedUp = wt;
    else if (n.find("ffn_down_shexp") != std::string::npos) lw.moeSharedDown = wt;
    else if (n.find("ffn_gate.weight") != std::string::npos) lw.wGate = wt;
    else if (n.find("ffn_up.weight") != std::string::npos) lw.wUp = wt;
    else if (n.find("ffn_down.weight") != std::string::npos) lw.wDown = wt;
    else if (n.find("ffn_norm") != std::string::npos ||
             n.find("post_attention_norm") != std::string::npos)
        lw.ffnNorm = wt;
}

inline int BindAll(ModelWeights& mw, const GlobalTensorIndex& idx) {
    if (mw.layers.empty()) return 0;
    const GlobalTensorRef* emb = idx.FindPtr("token_embd.weight");
    const GlobalTensorRef* out = idx.FindPtr("output.weight");
    if (!out) out = idx.FindPtr("lm_head.weight");
    const GlobalTensorRef* nrm = idx.FindPtr("output_norm.weight");
    if (!nrm) nrm = idx.FindPtr("norm.weight");
    std::fprintf(stderr,
                 "B02_INDEX_LOOKUP emb=%d shard=%d out=%d shard=%d nrm=%d "
                 "global_tensors=%zu\n",
                 emb ? 1 : 0, emb ? (int)emb->shardId : -1, out ? 1 : 0,
                 out ? (int)out->shardId : -1, nrm ? 1 : 0, idx.TotalTensors());
    if (emb) {
        mw.tokenEmbed = FromRef(*emb);
        if (emb->shape.size() >= 2 && mw.hiddenDim) {
            const size_t d0 = (size_t)emb->shape[0], d1 = (size_t)emb->shape[1];
            const size_t voc = (d0 == mw.hiddenDim) ? d1
                : ((d1 == mw.hiddenDim) ? d0 : (d0 > d1 ? d0 : d1));
            if (voc && voc != mw.hiddenDim) mw.vocabSize = voc;
        }
    }
    if (out) mw.lmHead = FromRef(*out);
    if (nrm) mw.finalNorm = FromRef(*nrm);
    if (!out && mw.tokenEmbed.hasFileBacking) {
        mw.lmHead = mw.tokenEmbed;
        mw.tieEmbeddings = true;
        std::fprintf(stderr, "B02_TIED_EMBED=1 reason=NO_OUTPUT_IN_INDEX\n");
    }
    const int eOk = Materialize(mw.tokenEmbed, idx);
    const int oOk = mw.tieEmbeddings ? eOk : Materialize(mw.lmHead, idx);
    const int nOk = nrm ? Materialize(mw.finalNorm, idx) : 1;
    idx.ForEach([&](const GlobalTensorRef& ref) {
        if (ref.layerIndex < 0) return;
        const size_t li = (size_t)ref.layerIndex;
        if (li >= mw.layers.size()) return;
        BindLayerTensor(mw.layers[li], ref);
    });
    /* metadata ≠ materialization — materialize on-demand in forward (OOM if all). */
    const int layersOk = ValidateAllLayers(mw, stderr);
    std::fprintf(stderr,
                 "B02_BIND_RESULT emb=%d lm=%d nrm=%d layers=%zu "
                 "layers_meta_ok=%d L0_wq_bound=%d\n",
                 eOk, oOk, nOk, mw.layers.size(), layersOk,
                 mw.layers[0].wq.hasFileBacking ? 1 : 0);
    return (eOk && oOk && nOk && layersOk) ? 1 : 0;
}

} // namespace multishard_bind
} // namespace Deep2
