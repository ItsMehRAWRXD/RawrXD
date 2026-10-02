// ============================================================================
// deep2_mla_weight_skimmer.cpp
// RAWRXD_MLA_ABSOLUTE_SKIMMER_001
//
// SCALAR REFERENCE. Correctness first, deliberately unoptimised. This is the
// numerical oracle that an AVX2 or fused-register version must be measured
// against before anyone is allowed to replace it.
//
// The loop shape is the whole point. For Q4_K it walks row by row, block by
// block, and for each block it decodes 256 floats into the caller's fixed
// scratch, immediately accumulates them, and moves on. At no instant does a
// whole tensor exist as F32. For Kimi's 578 GB that is the difference between
// working and impossible.
//
// Every refusal below is deliberate. The function never falls back to treating
// bytes as F32 "just to see", because that is the exact failure this whole
// exercise exists to prevent.
// ============================================================================

#include "deep2_mla_weight_skimmer.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace rawrxd::mla {

namespace {

bool finiteVector(const float* p, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) {
        if (!std::isfinite(p[i])) return false;
    }
    return true;
}

float dotScalar(const float* a, const float* b, uint32_t n) {
    float sum = 0.0f;
    for (uint32_t i = 0; i < n; ++i) sum += a[i] * b[i];
    return sum;
}

} // namespace

const char* skimmerResultName(SkimmerResult r) {
    switch (r) {
        case SkimmerResult::Ok:               return "OK";
        case SkimmerResult::NullWeight:        return "NULL_WEIGHT";
        case SkimmerResult::NullInput:         return "NULL_INPUT";
        case SkimmerResult::NullOutput:        return "NULL_OUTPUT";
        case SkimmerResult::UnsupportedType:   return "UNSUPPORTED_FORMAT";
        case SkimmerResult::InvalidShape:      return "INVALID_SHAPE";
        case SkimmerResult::InvalidByteExtent: return "INVALID_BYTE_EXTENT";
        case SkimmerResult::ScratchTooSmall:   return "SCRATCH_TOO_SMALL";
        case SkimmerResult::DecoderFailure:    return "DECODER_FAILURE";
        case SkimmerResult::NonFiniteOutput:   return "NON_FINITE_OUTPUT";
    }
    return "UNKNOWN";
}

SkimmerResult gemvSkimmed(const WeightView& weight,
                           const float* x, uint32_t xCount,
                           float* y, uint32_t yCount,
                           SkimmerScratch& scratch,
                           DecodeQ4KBlockFn decodeQ4K,
                           SkimmerStats* stats) {
    if (!weight.data)           return SkimmerResult::NullWeight;
    if (!x)                    return SkimmerResult::NullInput;
    if (!y)                    return SkimmerResult::NullOutput;
    if (stats) *stats = SkimmerStats{};

    // Geometry is checked before format, because a shape mismatch invalidates
    // every later comparison regardless of how the bytes are laid out.
    if (!weight.rows || !weight.cols ||
        weight.cols != xCount || weight.rows != yCount)
        return SkimmerResult::InvalidShape;

    if (!scratch.values) return SkimmerResult::ScratchTooSmall;

    switch (weight.format) {
    case WeightFormat::F32: {
        const uint64_t need = uint64_t(weight.rows) * uint64_t(weight.cols) * sizeof(float);
        if (need > weight.bytes) return SkimmerResult::InvalidByteExtent;

        const auto* m = static_cast<const float*>(weight.data);
        for (uint32_t row = 0; row < weight.rows; ++row) {
            y[row] = dotScalar(m + uint64_t(row) * weight.cols, x, weight.cols);
            if (stats) { ++stats->rowsProcessed; stats->logicalValues += weight.cols; }
        }
        break;
    }

    case WeightFormat::Q4_K: {
        if (!decodeQ4K) return SkimmerResult::DecoderFailure;
        if (scratch.capacityFloats < kQ4KValuesPerBlock)
            return SkimmerResult::ScratchTooSmall;
        // A row that is not a whole number of blocks would require reading a
        // partial block, which is a different and unverified code path.
        if ((weight.cols % kQ4KValuesPerBlock) != 0)
            return SkimmerResult::InvalidShape;

        const uint32_t blocksPerRow = weight.cols / kQ4KValuesPerBlock;
        const uint64_t need =
            uint64_t(weight.rows) * uint64_t(blocksPerRow) * kQ4KBytesPerBlock;
        if (need > weight.bytes) return SkimmerResult::InvalidByteExtent;

        const auto* bytes = static_cast<const uint8_t*>(weight.data);
        for (uint32_t row = 0; row < weight.rows; ++row) {
            float acc = 0.0f;
            const uint64_t rowBase = uint64_t(row) * uint64_t(blocksPerRow) * kQ4KBytesPerBlock;
            for (uint32_t b = 0; b < blocksPerRow; ++b) {
                const uint8_t* src = bytes + rowBase + uint64_t(b) * kQ4KBytesPerBlock;
                if (!decodeQ4K(src, scratch.values)) return SkimmerResult::DecoderFailure;

                acc += dotScalar(scratch.values, x + uint64_t(b) * kQ4KValuesPerBlock,
                                 kQ4KValuesPerBlock);

                if (stats) {
                    ++stats->quantBlocksRead;
                    stats->quantBytesRead  += kQ4KBytesPerBlock;
                    stats->floatsDecoded   += kQ4KValuesPerBlock;
                    stats->logicalValues   += kQ4KValuesPerBlock;
                    stats->scratchPeakFloats = kQ4KValuesPerBlock;
                }
            }
            y[row] = acc;
            if (stats) ++stats->rowsProcessed;
        }
        break;
    }

    // Q4_0, Q6_K, Q8_0, F16 are DECLARED but not implemented. They refuse here
    // rather than being silently routed to the F32 path. F16 in particular is
    // the trap this ladder's rung-1 cert fell into.
    case WeightFormat::F16:
    case WeightFormat::Q4_0:
    case WeightFormat::Q8_0:
    case WeightFormat::Q6_K:
    default:
        return SkimmerResult::UnsupportedType;
    }

    if (!finiteVector(y, yCount)) return SkimmerResult::NonFiniteOutput;
    if (stats) stats->fullTensorExpansions = 0;   // structural: never incremented
    return SkimmerResult::Ok;
}

} // namespace rawrxd::mla