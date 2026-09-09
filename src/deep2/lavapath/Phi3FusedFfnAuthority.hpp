#pragma once
/* PHI3_FUSED_FFN_AUTHORITY — logical FFN vs physical fused ffn_up. ≤99.
 * Phi-3: no ffn_gate; ffn_up rows = 2 * feed_forward_length (gate||up).
 * OPEN_COMPAT != PERF. GENERATES_1 != TEARDOWN_SAFE until extent matches. */
#include <cstddef>
#include <cstdio>

namespace Deep2 {
namespace rawr_phi3_fused_ffn {

struct FusedFfnAuth {
    bool fused = false;
    size_t logicalInter = 0;  /* consumer / down input (= meta FFN) */
    size_t physicalUpRows = 0; /* wUp.rows producer (= 2*logical) */
    const char* schema = "SPLIT_OR_GATED";
};

inline bool TensorReady(const WeightTensor& t) noexcept {
    return t.rows != 0 && t.cols != 0 && t.sizeBytes != 0 &&
           (t.data != nullptr || t.hasFileBacking || t.mapped);
}

/* Detect fused gate||up in a single ffn_up tensor. Does not mutate weights. */
inline FusedFfnAuth Inspect(const LayerWeights& lw, size_t metaInter,
                            size_t hiddenDim) noexcept {
    FusedFfnAuth a{};
    const bool hasGate = TensorReady(lw.wGate);
    if (!TensorReady(lw.wUp)) return a;
    a.physicalUpRows = lw.wUp.rows;
    size_t inter = metaInter;
    if (inter == 0) inter = hiddenDim * 4;
    a.logicalInter = inter;
    if (hasGate) {
        a.schema = "SEPARATE_GATE";
        return a;
    }
    if (a.physicalUpRows == 2 * inter && inter > 0) {
        a.fused = true;
        a.schema = "PHI3_FUSED_GATE_UP";
        return a;
    }
    if (a.physicalUpRows > inter && (a.physicalUpRows % 2) == 0 &&
        a.physicalUpRows / 2 == inter) {
        a.fused = true;
        a.schema = "PHI3_FUSED_GATE_UP";
        return a;
    }
    /* Self-gate fallback: physical == logical (Nemotron-H style). */
    a.schema = "SELF_GATE_UP";
    return a;
}

inline size_t MaxPhysicalUpRows(const ModelWeights& mw) noexcept {
    size_t m = 0;
    for (const auto& lw : mw.layers) {
        if (TensorReady(lw.wUp) && lw.wUp.rows > m) m = lw.wUp.rows;
    }
    return m;
}

inline void Emit(FILE* f, const FusedFfnAuth& a, size_t layer) noexcept {
    if (!f) return;
    std::fprintf(f,
                 "[PHI3_FUSED_FFN] layer=%zu fused=%d logical=%zu physical=%zu "
                 "schema=%s\n",
                 layer, a.fused ? 1 : 0, a.logicalInter, a.physicalUpRows,
                 a.schema);
}

} // namespace rawr_phi3_fused_ffn
} // namespace Deep2
