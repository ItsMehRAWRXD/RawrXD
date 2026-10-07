#pragma once
/*
    PHI3_FUSED_QKV_AUTHORITY_DROP_001

    Header-only Deep2 compatibility shim for Phi-3 / fused-QKV GGUFs.

    Scope:
      - open/generation readiness only
      - recognizes blk.N.attn_qkv.weight as the owner for q/k/v authority
      - does not promote performance
      - does not fabricate split q/k/v tensors
      - does not alter Ollama HTTP state

    Integration:
      Include from src/deep2/Deep2Engine.cpp after Deep2Engine.h:
          #include "lavapath/Phi3FusedQkvAuthority.hpp"

      Use LayerAttentionAuthority(...) anywhere the existing authority ladder
      currently blocks at attn_q / attn_k / attn_v.

      Use ProjectFusedQKV(...) inside computeAttention before the split-Q/K/V
      projection path when auth.fused == true.
*/

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace Deep2 {
namespace rawr_phi3_fused_qkv {

inline bool TensorReady(const WeightTensor& t) noexcept {
    /*
       Single-file GGUF tensors have data != nullptr.
       Indexed/mapped future paths may have hasFileBacking, so keep this
       predicate slightly broader without inventing data ownership.
    */
    return (t.rows != 0 && t.cols != 0 && t.sizeBytes != 0 &&
            (t.data != nullptr || t.hasFileBacking || t.mapped));
}

inline const WeightTensor* OutProjection(const LayerWeights& lw) noexcept {
    if (TensorReady(lw.wo))    return &lw.wo;    // blk.N.attn_output.weight
    if (TensorReady(lw.attnO)) return &lw.attnO; // qwen/deepseek-style attn_o
    return nullptr;
}

inline bool SplitQKVReady(const LayerWeights& lw) noexcept {
    return TensorReady(lw.wq) && TensorReady(lw.wk) && TensorReady(lw.wv);
}

struct FusedQKVShape {
    bool valid = false;
    bool exact = false;
    const char* schema = "NONE";
    std::size_t hidden = 0;
    std::size_t qRows = 0;
    std::size_t kRows = 0;
    std::size_t vRows = 0;
    std::size_t totalRows = 0;
    std::size_t cols = 0;
};

inline std::size_t FirstNonZero(std::size_t a, std::size_t b,
                                std::size_t c = 0) noexcept {
    return a ? a : (b ? b : c);
}

inline FusedQKVShape InferFusedQKVShape(const WeightTensor& wqkv,
                                        const ModelWeights& mw,
                                        const EngineConfig& cfg) noexcept {
    FusedQKVShape s{};
    if (!TensorReady(wqkv)) return s;

    s.hidden = FirstNonZero(mw.hiddenDim, cfg.hiddenDim, wqkv.cols);
    s.cols = wqkv.cols;
    s.totalRows = wqkv.rows;

    if (s.hidden == 0 || s.cols == 0 || s.totalRows == 0) return s;

    /*
       Most Phi-3 GGUFs expose:
           blk.N.attn_qkv.weight dims=[hidden, 3*hidden]
       The project loader converts GGUF dims to rows=output, cols=input.
    */
    if (s.cols == s.hidden && s.totalRows == 3 * s.hidden) {
        s.qRows = s.hidden;
        s.kRows = s.hidden;
        s.vRows = s.hidden;
        s.valid = true;
        s.exact = true;
        s.schema = "PHI3_FUSED_QKV_3H";
        return s;
    }

    /*
       GQA fused form:
           total = qHeads*headDim + 2*(kvHeads*headDim)
       This keeps KV-head authority instead of blindly assuming 3H.
    */
    const std::size_t heads = FirstNonZero(mw.numHeads, cfg.numHeads);
    const std::size_t kvHeads = FirstNonZero(mw.numKVHeads, cfg.numKVHeads, heads);
    const std::size_t headDim =
        FirstNonZero(mw.headDim, cfg.headDim,
                     (heads ? (s.hidden / heads) : 0));

    if (s.cols == s.hidden && heads && kvHeads && headDim) {
        const std::size_t q = heads * headDim;
        const std::size_t kv = kvHeads * headDim;
        const std::size_t total = q + 2 * kv;
        if (total == s.totalRows) {
            s.qRows = q;
            s.kRows = kv;
            s.vRows = kv;
            s.valid = true;
            s.exact = true;
            s.schema = "FUSED_QKV_GQA";
            return s;
        }
    }

    /*
       Last-resort open compatibility:
       If the source file only has one fused projection and rows divide by 3,
       let the model reach runtime evidence instead of failing at attn_q.
       Mark exact=false so cert logic can refuse production promotion later.
    */
    if (s.cols == s.hidden && (s.totalRows % 3) == 0) {
        const std::size_t part = s.totalRows / 3;
        s.qRows = part;
        s.kRows = part;
        s.vRows = part;
        s.valid = true;
        s.exact = false;
        s.schema = "FUSED_QKV_3WAY_COMPAT";
        return s;
    }

    return s;
}

struct AttentionAuthority {
    bool ok = false;
    bool split = false;
    bool fused = false;
    const char* blockedAt = "attn_q";
    FusedQKVShape fusedShape{};
};

inline AttentionAuthority LayerAttentionAuthority(const LayerWeights& lw,
                                                   const ModelWeights& mw,
                                                   const EngineConfig& cfg) noexcept {
    AttentionAuthority a{};

    const bool outOk = (OutProjection(lw) != nullptr);

    if (SplitQKVReady(lw) && outOk) {
        a.ok = true;
        a.split = true;
        a.blockedAt = "NONE";
        return a;
    }

    a.fusedShape = InferFusedQKVShape(lw.wqkv, mw, cfg);
    if (a.fusedShape.valid && outOk) {
        a.ok = true;
        a.fused = true;
        a.blockedAt = "NONE";
        return a;
    }

    if (!TensorReady(lw.wqkv) && !TensorReady(lw.wq)) a.blockedAt = "attn_q";
    else if (!TensorReady(lw.wqkv) && !TensorReady(lw.wk)) a.blockedAt = "attn_k";
    else if (!TensorReady(lw.wqkv) && !TensorReady(lw.wv)) a.blockedAt = "attn_v";
    else if (!outOk) a.blockedAt = "attn_output";
    else a.blockedAt = "attn_schema";

    return a;
}

inline void EmitAttentionAuthorityReceipt(FILE* f,
                                          std::size_t layer,
                                          const AttentionAuthority& a) noexcept {
    if (!f) return;
    std::fprintf(f,
        "PHI3_FUSED_QKV_AUTHORITY=1 layer=%zu ok=%d split=%d fused=%d "
        "schema=%s exact=%d q=%zu k=%zu v=%zu total=%zu cols=%zu blocked=%s\n",
        layer,
        a.ok ? 1 : 0,
        a.split ? 1 : 0,
        a.fused ? 1 : 0,
        a.fusedShape.schema ? a.fusedShape.schema : "NONE",
        a.fusedShape.exact ? 1 : 0,
        a.fusedShape.qRows,
        a.fusedShape.kRows,
        a.fusedShape.vRows,
        a.fusedShape.totalRows,
        a.fusedShape.cols,
        a.blockedAt ? a.blockedAt : "UNKNOWN");
}

/*
   Call from computeAttention after layerTemp/input is ready and before
   the split-Q/K/V LinearW calls.

   linearW must be a callable with this shape:
       linearW(const WeightTensor&, const float* in, float* out, size_t outDim)

   qOut/kOut/vOut must point to buffers at least qRows/kRows/vRows long.
   qkvTmp must point to a buffer at least totalRows long.
*/
template <class LinearWCall>
inline bool ProjectFusedQKV(const LayerWeights& lw,
                            const ModelWeights& mw,
                            const EngineConfig& cfg,
                            const float* input,
                            float* qOut,
                            float* kOut,
                            float* vOut,
                            float* qkvTmp,
                            std::size_t qkvTmpCount,
                            LinearWCall&& linearW,
                            FILE* f = nullptr) {
    const FusedQKVShape s = InferFusedQKVShape(lw.wqkv, mw, cfg);
    if (!s.valid) return false;
    if (!input || !qOut || !kOut || !vOut || !qkvTmp) return false;
    if (qkvTmpCount < s.totalRows) {
        if (f) {
            std::fprintf(f,
                "PHI3_FUSED_QKV_PROJECT=0 reason=tmp_too_small need=%zu have=%zu\n",
                s.totalRows, qkvTmpCount);
        }
        return false;
    }

    linearW(lw.wqkv, input, qkvTmp, s.totalRows);

    std::memcpy(qOut, qkvTmp, s.qRows * sizeof(float));
    std::memcpy(kOut, qkvTmp + s.qRows, s.kRows * sizeof(float));
    std::memcpy(vOut, qkvTmp + s.qRows + s.kRows, s.vRows * sizeof(float));

    if (f) {
        std::fprintf(f,
            "PHI3_FUSED_QKV_PROJECT=1 schema=%s q=%zu k=%zu v=%zu total=%zu\n",
            s.schema, s.qRows, s.kRows, s.vRows, s.totalRows);
    }
    return true;
}

} // namespace rawr_phi3_fused_qkv
} // namespace Deep2
