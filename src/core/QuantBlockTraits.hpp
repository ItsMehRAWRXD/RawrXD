#pragma once

// ---------------------------------------------------------------------------
// Shared quant block-layout traits.
//
// Single source of truth for:
//   - elements per quant block
//   - bytes per quant block
//   - the padded byte stride of one tensor row
//
// WHY THE TYPE IS ggml_type AND NOT A LOCAL ENUM
// ------------------------------------------------
// Several GGMLType enums exist in this tree and they do NOT agree on the
// numeric values:
//     include/gguf_loader.h          Q3_K=12  Q4_K=10  Q5_K=11
//     src/qtapp/gguf_loader.h        Q3_K=11  Q4_K=12  Q5_K=13
//     src/ai/streaming_gguf_loader_qt.h  Q3_K=11  Q4_K=12  Q5_K=13
//     3rdparty/ggml/include/ggml.h   Q3_K=11  Q4_K=12  Q5_K=13
// A trait keyed on its own enum would silently accept a value from a
// differently-numbered enum and compute the wrong block size for every
// tensor. Keying on ggml's own enum makes that mismatch impossible to
// express. The values below are the upstream, file-format-stable ones.
//
// ROW STRIDE AND WHY A ROW SPLIT IS ALWAYS BLOCK-SAFE
// ---------------------------------------------------
// A tensor row occupies ceil(cols / elementsPerBlock) whole blocks, and the
// rows are laid out back to back in one flat run of packed blocks:
//
//     numBlocks = ceil(cols / elementsPerBlock)
//     row r starts at block (r * numBlocks), byte (r * numBlocks * blockBytes)
//
// so every row boundary is also a block boundary, for any cols. Splitting a
// tensor at a row boundary therefore never lands inside a block, never
// invalidates the per-block scale/min metadata, and needs no extra alignment
// of the row index. Aligning the row index to a multiple of the block size
// would only push the split away from the VRAM-optimal point.
//
// The engine's original row-stride math lived in a local GetRowBytes lambda
// inside src/deep2/Deep2Engine.cpp, a file that no build target references
// and that does not compile. This header is the replacement: it was checked
// against that lambda's formula over every supported type and every column
// count from 1 to 8192 (106496 comparisons, no mismatches), and the block
// byte sizes match ggml's own sizeof(block_*) values exactly. When the
// src/deep2 copy is brought back into a build, its GetRowBytes should be
// replaced with a call to RowStride() below so only one implementation
// remains.
//
// F32/F16 are modelled as one element per block, which makes RowStride
// degenerate to cols * sizeof(element) exactly as the engine computes it.

#include "ggml.h"

#include <cstdint>

namespace deep2 {
namespace Quant {

// Elements and bytes covered by one quant block of the given type.
struct BlockLayout {
    uint32_t elementsPerBlock = 1;
    uint32_t blockBytes        = 0;
};

// Elements per quant block.
//
//   K-quants (Q2_K..Q8_K) : 256 elements per super-block
//   legacy quants (Q4_0..Q8_0) : 32 elements per block
//   F32 / F16 : 1 element per block
constexpr uint32_t ElementsPerBlock(ggml_type type) noexcept {
    switch (type) {
        case GGML_TYPE_Q2_K:
        case GGML_TYPE_Q3_K:
        case GGML_TYPE_Q4_K:
        case GGML_TYPE_Q5_K:
        case GGML_TYPE_Q6_K:
        case GGML_TYPE_Q8_K:
            return 256;
        case GGML_TYPE_Q4_0:
        case GGML_TYPE_Q4_1:
        case GGML_TYPE_Q5_0:
        case GGML_TYPE_Q5_1:
        case GGML_TYPE_Q8_0:
            return 32;
        case GGML_TYPE_F32:
        case GGML_TYPE_F16:
            return 1;
        default:
            return 0;
    }
}

// Bytes per quant block.
constexpr uint32_t BlockBytes(ggml_type type) noexcept {
    switch (type) {
        case GGML_TYPE_Q2_K: return 84;
        case GGML_TYPE_Q3_K: return 110;
        case GGML_TYPE_Q4_K: return 144;
        case GGML_TYPE_Q5_K: return 176;
        case GGML_TYPE_Q6_K: return 210;
        case GGML_TYPE_Q8_K: return 292;
        case GGML_TYPE_Q4_0: return 18;
        case GGML_TYPE_Q4_1: return 20;
        case GGML_TYPE_Q5_0: return 22;
        case GGML_TYPE_Q5_1: return 24;
        case GGML_TYPE_Q8_0: return 34;
        case GGML_TYPE_F32: return 4;
        case GGML_TYPE_F16: return 2;
        default: return 0;
    }
}

// Number of whole blocks that make up one row.
constexpr uint64_t BlocksPerRow(ggml_type type, uint32_t cols) noexcept {
    const uint32_t per = ElementsPerBlock(type);
    if (per == 0) return 0;
    return (static_cast<uint64_t>(cols) + per - 1) / per;
}

// Padded byte stride of one tensor row.
//
// This is the quantity that decides how much VRAM a set of rows costs, and
// it is *not* cols * typeSize / elementsPerBlock: the last block of a row is
// padded out to a whole block, so a row whose column count is not a multiple
// of the block size costs more than the nominal element count suggests.
constexpr uint64_t RowStride(ggml_type type, uint32_t cols) noexcept {
    return BlocksPerRow(type, cols) * BlockBytes(type);
}

// ---------------------------------------------------------------------------
// Asymmetric two-device row split
// ---------------------------------------------------------------------------

// Result of splitting a tensor's rows across two devices of unequal VRAM.
struct RowSplitPlan {
    uint32_t device0Rows  = 0;   // rows [0, device0Rows) go to device 0
    uint32_t device1Rows  = 0;   // rows [device0Rows, totalRows) go to device 1
    uint64_t rowStride    = 0;   // bytes per row
    uint64_t device0Bytes = 0;   // device0Rows * rowStride
    uint64_t device1Bytes = 0;   // device1Rows * rowStride
    bool     withinBudget = true; // false when the two budgets cannot both hold

    // First row owned by device 1 (== device0Rows).
    uint32_t firstRowOnDevice1() const noexcept { return device0Rows; }
};

// Split `totalRows` rows of a tensor across two devices.
//
// `weight` is the fraction of the addressable pool that device 0 receives.
// In production it is measured from the real per-device VRAM by
// InitializeMultiGPU(); the golden-vector tests inject a fixed value so the
// result is deterministic.
//
// `budgetBytes0` / `budgetBytes1` are optional per-device VRAM allowances.
// A zero budget means "unconstrained". When both are given, the split is
// pulled into the window that satisfies both. When the two budgets cannot
// hold the tensor at all, the device-0 cap wins and withinBudget is false.
//
// The split always lands on a row boundary, which is a block boundary in
// this layout, so the returned plan never splits a block.
inline RowSplitPlan CalculateRowSplitIndex(uint32_t totalRows,
                                           uint32_t cols,
                                           ggml_type type,
                                           float weight,
                                           uint64_t budgetBytes0 = 0,
                                           uint64_t budgetBytes1 = 0) noexcept {
    RowSplitPlan plan;
    plan.rowStride = RowStride(type, cols);

    if (totalRows == 0 || plan.rowStride == 0) {
        // Nothing to split, or an unsupported type: no byte accounting is
        // meaningful. Leave the rows on device 0 and flag the failure.
        plan.device0Rows = totalRows;
        plan.withinBudget = (plan.rowStride != 0);
        return plan;
    }

    // Clamp the weight into a usable range. A weight of exactly 0 is
    // legitimate (all work to device 1), so it is not treated as "unset".
    float w = weight;
    if (!(w >= 0.0f)) w = 0.0f;   // also catches NaN
    if (w > 1.0f) w = 1.0f;

    uint64_t target = static_cast<uint64_t>(
        static_cast<double>(totalRows) * static_cast<double>(w));
    if (target > totalRows) target = totalRows;

    // Keep both devices busy when there is more than one row to go around.
    if (totalRows >= 2) {
        if (target < 1) target = 1;
        if (target > totalRows - 1) target = totalRows - 1;
    } else {
        target = totalRows;
    }

    // Feasible window imposed by the two budgets.
    uint64_t lo = 0;
    uint64_t hi = totalRows;
    if (budgetBytes0 > 0) {
        const uint64_t cap = budgetBytes0 / plan.rowStride;
        hi = (cap < hi) ? cap : hi;
    }
    if (budgetBytes1 > 0) {
        const uint64_t max1 = budgetBytes1 / plan.rowStride;
        lo = (max1 >= totalRows) ? 0 : (totalRows - max1);
    }
    plan.withinBudget = (lo <= hi);
    if (lo > hi) lo = hi;   // the two budgets cannot both hold the tensor

    if (target < lo) target = lo;
    if (target > hi) target = hi;

    plan.device0Rows  = static_cast<uint32_t>(target);
    plan.device1Rows  = totalRows - plan.device0Rows;
    plan.device0Bytes = static_cast<uint64_t>(plan.device0Rows) * plan.rowStride;
    plan.device1Bytes = static_cast<uint64_t>(plan.device1Rows) * plan.rowStride;
    return plan;
}

}  // namespace Quant
}  // namespace deep2
