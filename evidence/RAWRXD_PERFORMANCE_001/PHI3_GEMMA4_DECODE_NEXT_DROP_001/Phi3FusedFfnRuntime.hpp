#pragma once
// ============================================================================
// Phi3FusedFfnRuntime.hpp
// Source-only Deep2 drop: Phi-3 fused gate|up FFN execution authority.
//
// Scope:
//   - Fixes Phi-3 runtime shape ownership after MODEL_OPEN=PASS.
//   - Does not promote TPS, benchmark cert, or product parity by itself.
//   - No new object files, no CMake edit, no external dependencies.
// ============================================================================

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cmath>

namespace Deep2::phi3_fused_ffn {

struct FusedFfnFacts {
    bool ok = false;
    bool fused = false;
    bool exact = false;
    std::size_t hidden = 0;
    std::size_t upRows = 0;
    std::size_t upCols = 0;
    std::size_t downRows = 0;
    std::size_t downCols = 0;
    std::size_t half = 0;
    const char* reason = "UNSET";
};

template <typename WeightTensorT>
inline bool WtLive(const WeightTensorT& wt) noexcept {
    return wt.data != nullptr && wt.rows > 0 && wt.cols > 0 && wt.sizeBytes > 0;
}

template <typename LayerWeightsT>
inline FusedFfnFacts InspectLayer(const LayerWeightsT& lw, std::size_t hidden,
                                  std::size_t configuredInter) noexcept {
    FusedFfnFacts f{};
    f.hidden = hidden;
    f.upRows = lw.wUp.rows;
    f.upCols = lw.wUp.cols;
    f.downRows = lw.wDown.rows;
    f.downCols = lw.wDown.cols;

    if (!WtLive(lw.wUp)) {
        f.reason = "NO_FFN_UP";
        return f;
    }
    if (!WtLive(lw.wDown)) {
        f.reason = "NO_FFN_DOWN";
        return f;
    }
    if (WtLive(lw.wGate)) {
        f.reason = "SPLIT_GATE_PRESENT";
        return f;
    }

    // Phi-3 fused FFN shape:
    //   ffn_up.weight   : [hidden, 2*intermediate] after Deep2 mapping => rows=2*inter, cols=hidden
    //   ffn_down.weight : [intermediate, hidden]   after Deep2 mapping => rows=hidden, cols=inter
    const std::size_t halfFromDown = lw.wDown.cols;
    const std::size_t half = halfFromDown ? halfFromDown : configuredInter;
    f.half = half;

    if (hidden == 0 || half == 0) {
        f.reason = "ZERO_GEOM";
        return f;
    }
    if (lw.wUp.cols != hidden) {
        f.reason = "UP_COLS_NOT_HIDDEN";
        return f;
    }
    if (lw.wDown.rows != hidden) {
        f.reason = "DOWN_ROWS_NOT_HIDDEN";
        return f;
    }
    if (lw.wDown.cols != half) {
        f.reason = "DOWN_COLS_NOT_HALF";
        return f;
    }
    if (lw.wUp.rows == 2 * half) {
        f.ok = true;
        f.fused = true;
        f.exact = true;
        f.reason = "PHI3_GATE_UP_EXACT";
        return f;
    }
    if (configuredInter > 0 && lw.wUp.rows == 2 * configuredInter && half == configuredInter) {
        f.ok = true;
        f.fused = true;
        f.exact = true;
        f.reason = "PHI3_GATE_UP_CONFIGURED";
        return f;
    }

    f.reason = "UP_ROWS_NOT_2X_HALF";
    return f;
}

template <typename ModelWeightsT>
inline std::size_t RepairModel(ModelWeightsT& mw, FILE* f = stderr) noexcept {
    std::size_t repaired = 0;
    if (mw.hiddenDim == 0 || mw.layers.empty()) return 0;

    for (std::size_t i = 0; i < mw.layers.size(); ++i) {
        auto facts = InspectLayer(mw.layers[i], mw.hiddenDim, mw.intermediateDim);
        if (!facts.ok) continue;

        // The important invariant: do not clamp fused up rows down to half.
        // The half width is owned by ffn_down.cols; wUp.rows must stay 2*half.
        if (mw.intermediateDim != facts.half) {
            if (f) {
                std::fprintf(f,
                    "PHI3_FUSED_FFN_REPAIR layer=%zu old_inter=%zu new_inter=%zu up_rows=%zu down_cols=%zu\n",
                    i, mw.intermediateDim, facts.half, facts.upRows, facts.downCols);
            }
            mw.intermediateDim = facts.half;
        }
        ++repaired;
        if (f) {
            std::fprintf(f,
                "PHI3_FUSED_FFN_LAYER layer=%zu fused=1 exact=%d up_rows=%zu up_cols=%zu half=%zu down_rows=%zu down_cols=%zu\n",
                i, facts.exact ? 1 : 0, facts.upRows, facts.upCols, facts.half,
                facts.downRows, facts.downCols);
        }
    }
    if (f) {
        std::fprintf(f,
            "PHI3_FUSED_FFN_RUNTIME layers=%zu repaired=%zu authority=%s\n",
            mw.layers.size(), repaired, repaired ? "PASS" : "UNOBSERVED");
        std::fflush(f);
    }
    return repaired;
}

inline float Silu(float x) noexcept {
    if (x > 20.0f) return x;
    if (x < -20.0f) return 0.0f;
    return x / (1.0f + std::exp(-x));
}

inline bool UpFirstEnv() noexcept {
    const char* e = std::getenv("RAWRXD_PHI3_FUSED_FFN_UP_FIRST");
    return e && e[0] == '1';
}

// Use from inside Deep2Engine::computeFFN before the split wGate/wUp/wDown branch:
//
//   if (Deep2::phi3_fused_ffn::TryExecuteLayer(
//           lw, input, output, hiddenDim, modelWeights.intermediateDim,
//           [&](const WeightTensor& wt, const float* x, float* y, size_t outDim) {
//               LinearW(wt, x, nullptr, y, outDim);
//           }, stderr)) return;
//
// LinearWFn ABI: void(const WeightTensor&, const float* in, float* out, size_t outDim)
template <typename LayerWeightsT, typename LinearWFn>
inline bool TryExecuteLayer(const LayerWeightsT& lw,
                            const float* input,
                            float* output,
                            std::size_t hidden,
                            std::size_t configuredInter,
                            LinearWFn&& linearW,
                            FILE* f = stderr) {
    const FusedFfnFacts facts = InspectLayer(lw, hidden, configuredInter);
    if (!facts.ok || !input || !output) return false;

    const std::size_t inter = facts.half;
    const std::size_t fusedRows = inter * 2;
    std::vector<float> gateUp(fusedRows, 0.0f);
    std::vector<float> act(inter, 0.0f);

    linearW(lw.wUp, input, gateUp.data(), fusedRows);

    // Default order is gate|up. Set RAWRXD_PHI3_FUSED_FFN_UP_FIRST=1 to test up|gate.
    const bool upFirst = UpFirstEnv();
    const float* gate = upFirst ? gateUp.data() + inter : gateUp.data();
    const float* up   = upFirst ? gateUp.data()         : gateUp.data() + inter;

    for (std::size_t i = 0; i < inter; ++i) {
        act[i] = Silu(gate[i]) * up[i];
    }

    linearW(lw.wDown, act.data(), output, hidden);

    if (f) {
        std::fprintf(f,
            "PHI3_FUSED_FFN_EXEC=1 order=%s hidden=%zu inter=%zu fused_rows=%zu\n",
            upFirst ? "up_gate" : "gate_up", hidden, inter, fusedRows);
        std::fflush(f);
    }
    return true;
}

} // namespace Deep2::phi3_fused_ffn
