// ============================================================================
// deep2_mla_weight_skimmer.h
// RAWRXD_MLA_ABSOLUTE_SKIMMER_001
//
// A format-explicit, range-exact, bounded-memory, fail-closed weight reader.
//
// It exists to answer one question honestly: how do you compute y = Wx when W is
// 578 GB of Q4_K and you may never expand it? The answer here is: demand only
// the 144 bytes of each block you are about to decode, decode into a fixed
// scratch, accumulate, and never let a full F32 tensor exist.
//
// The invariant this file is written to preserve:
//
//     FULL_TENSOR_F32_MATERIALIZED == 0
//
// The MLA kernel does not know what a Q4_K block is. The skimmer does not know
// what MLA is. The decoder does not own tensors. Three separable concerns, and a
// mistake in any one of them cannot silently become a mistake in the others.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>

namespace rawrxd::mla {

// GGUF/GGML type ids, so the mapping from a tensor's `type` field is explicit
// rather than assumed. Q4_K is 12 in the GGML enum; stated here so the
// dependency is visible instead of buried in a magic number at the call site.
enum class WeightFormat : uint32_t {
    F32 = 0,
    F16 = 1,
    Q8_0 = 8,
    Q4_0 = 2,
    Q6_K = 14,
    Q4_K = 12,
};

static constexpr uint32_t kQ4KValuesPerBlock = 256;
static constexpr uint32_t kQ4KBytesPerBlock  = 144;
static_assert(kQ4KValuesPerBlock == 256, "Q4_K geometry is fixed by the format");
static_assert(kQ4KBytesPerBlock == 144, "Q4_K geometry is fixed by the format");

struct WeightView {
    const void* data = nullptr;
    uint64_t    bytes = 0;      // ACTUAL bytes available at `data`
    uint32_t    rows = 0;
    uint32_t    cols = 0;
    WeightFormat format = WeightFormat::F32;
};

struct SkimmerScratch {
    float*  values = nullptr;
    size_t  capacityFloats = 0;
};

struct SkimmerStats {
    uint64_t rowsProcessed       = 0;
    uint64_t logicalValues       = 0;   // weights actually consumed
    uint64_t quantBlocksRead     = 0;
    uint64_t quantBytesRead      = 0;
    uint64_t floatsDecoded       = 0;
    uint64_t scratchPeakFloats   = 0;
    uint64_t fullTensorExpansions = 0;  // must remain 0, always
};

enum class SkimmerResult : uint8_t {
    Ok = 0,
    NullWeight,
    NullInput,
    NullOutput,
    UnsupportedType,
    InvalidShape,
    InvalidByteExtent,
    ScratchTooSmall,
    DecoderFailure,
    NonFiniteOutput,
};

const char* skimmerResultName(SkimmerResult r);

// Decodes exactly one 144-byte Q4_K block into 256 floats. Supplied by the
// caller so this file never contains quantisation bit arithmetic and therefore
// cannot disagree with the certified decoder.
using DecodeQ4KBlockFn = bool (*)(const void* block, float* out256);

// Returns Ok, or a specific refusal. There is no path that guesses.
SkimmerResult gemvSkimmed(const WeightView& weight,
                           const float* x, uint32_t xCount,
                           float* y, uint32_t yCount,
                           SkimmerScratch& scratch,
                           DecodeQ4KBlockFn decodeQ4K,
                           SkimmerStats* stats = nullptr);

} // namespace rawrxd::mla