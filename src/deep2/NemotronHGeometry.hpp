#pragma once
/* Nemotron-H SSM/attn geometry. 96=heads/dt ≠ state(128). ≤99. */
#include "NemotronHSsmMap.hpp"
#include <cstdio>

namespace Deep2 {
namespace nemotron_h {

struct Geo {
    size_t hidden = 0;
    size_t ssmHeads = 0;      /* 96 */
    size_t ssmHeadDim = 0;    /* 80 */
    size_t ssmInner = 0;      /* 7680 */
    size_t ssmGroups = 0;     /* 8 */
    size_t ssmState = 0;      /* 128 */
    size_t ssmGroupState = 0; /* 1024 */
    size_t ssmDtRank = 0;     /* 96 */
    size_t ssmConvK = 0;      /* 4 */
    size_t ssmConvDim = 0;    /* 9728 */
    size_t ssmInRows = 0;     /* 17504 */
    size_t attnQHeads = 0;
    size_t attnKvHeads = 0;
    size_t attnHeadDim = 0; /* 128; never hidden/heads */
    int ok = 0;
};

inline size_t MaxRC(const WeightTensor& w) {
    return w.rows > w.cols ? w.rows : w.cols;
}

inline Geo ResolveFromLayer(const LayerWeights& lw, size_t hidden) {
    Geo g{};
    g.hidden = hidden;
    if (!WtOk(lw.ssmIn) || !WtOk(lw.ssmOut) || !WtOk(lw.ssmA) ||
        !WtOk(lw.ssmConv1d))
        return g;
    g.ssmInRows = lw.ssmIn.rows ? lw.ssmIn.rows : lw.ssmIn.cols;
    g.ssmDtRank = MaxRC(lw.ssmA);
    g.ssmHeads = g.ssmDtRank;
    g.ssmConvK = (lw.ssmConv1d.cols > 1 && lw.ssmConv1d.cols <= 16)
                     ? lw.ssmConv1d.cols
                     : ((lw.ssmConv1d.rows > 1 && lw.ssmConv1d.rows <= 16)
                            ? lw.ssmConv1d.rows
                            : 4);
    g.ssmConvDim = (lw.ssmConv1d.rows >= lw.ssmConv1d.cols) ? lw.ssmConv1d.rows
                                                           : lw.ssmConv1d.cols;
    /* in = gate(inner)+xBC(convDim)+dt(heads); out.cols|rows = inner */
    g.ssmInner = (g.ssmInRows > g.ssmConvDim + g.ssmHeads)
                     ? (g.ssmInRows - g.ssmConvDim - g.ssmHeads)
                     : (lw.ssmOut.cols ? lw.ssmOut.cols : lw.ssmOut.rows);
    g.ssmGroupState =
        (g.ssmConvDim > g.ssmInner) ? (g.ssmConvDim - g.ssmInner) / 2 : 0;
    g.ssmGroups = 8;
    g.ssmState = g.ssmGroups ? g.ssmGroupState / g.ssmGroups : 0;
    if (g.ssmHeads && g.ssmInner % g.ssmHeads == 0)
        g.ssmHeadDim = g.ssmInner / g.ssmHeads;
    g.ok = (g.ssmState == 128 && g.ssmHeads == 96 && g.ssmInner == 7680 &&
            g.ssmGroups == 8 && g.ssmConvDim == 9728 && g.ssmInRows == 17504 &&
            g.ssmHeadDim == 80)
               ? 1
               : 0;
    return g;
}

inline void Emit(FILE* f, const Geo& g) noexcept {
    if (!f) f = stderr;
    std::fprintf(
        f,
        "GATE=NEMOTRON_H_REAL_SSM_001\nNEMOTRON_H_SSM_GEOMETRY=%s\n"
        "MAMBA_NUM_HEADS=%zu MAMBA_HEAD_DIM=%zu MAMBA_INNER_DIM=%zu\n"
        "SSM_STATE_SIZE=%zu SSM_GROUPS=%zu SSM_CONV_DIM=%zu SSM_CONV_KERNEL=%zu\n"
        "SSM_IN_ROWS=%zu SSM_DT_RANK=%zu\n"
        "NOTE=OLD_SSM_STATE_DIM_96_WAS_HEADS_NOT_STATE\n"
        "ATTN_HEAD_DIM_NE_ROPE_DIM=1 NEXT_GATE=NUMERIC_PARITY\n",
        g.ok ? "PASS" : "FAIL", g.ssmHeads, g.ssmHeadDim, g.ssmInner, g.ssmState,
        g.ssmGroups, g.ssmConvDim, g.ssmConvK, g.ssmInRows, g.ssmDtRank);
    std::fflush(f);
}

} /* namespace nemotron_h */
} /* namespace Deep2 */
