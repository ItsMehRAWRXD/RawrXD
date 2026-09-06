// RegenerativeTypes.hpp — sealed core vs disposable generated runtime
#pragma once
#include "../time_reversal/TimeReversalTypes.hpp"
#include <cstdint>
#include <cstring>

namespace Deep2 {
namespace Regenerative {

enum class Lifetime : uint8_t {
    Sealed = 0,     // permanent law
    Session = 1,    // survives runtime generations
    Generation = 2, // recreated each G
    Token = 3,      // recreated each token
    Ephemeral = 4   // discard after use
};

// Sealed nucleus — only durable authority
struct SealedCore {
    TimeReversal::Hash256 authoritySha{};
    TimeReversal::Hash256 correctnessVerifierSha{};
    TimeReversal::Hash256 hardwareInventorySha{};
    TimeReversal::Hash256 modelMetadataSha{};
    TimeReversal::Hash256 proofHistorySha{};
    TimeReversal::Hash256 performanceObsSha{};
    TimeReversal::Hash256 generatorSha{};
    uint64_t generationCounter = 0;
};

// GenerationAuthorityRecord — matches MASM layout (ALIGN 8)
#pragma pack(push, 8)
struct GenerationAuthorityRecord {
    uint64_t sealedAuthorityHash[4]; // SHA-256 as 4×DQ
    uint64_t hardwareFactsPtr;
    uint64_t workloadFactsPtr;
    uint64_t currentBudgetLimitMsFixed; // e.g. 20.00 ms → 2000 (0.01 ms units)
    uint64_t retainedProofsTablePtr;
    uint64_t generationCounter;
};
#pragma pack(pop)
static_assert(sizeof(GenerationAuthorityRecord) == 72, "authority record size");

// Generated runtime image — immutable after Freeze
struct RuntimeImage {
    uint64_t generation = 0;
    TimeReversal::Hash256 imageSha{};
    TimeReversal::Hash256 factsSha{};   // inputs that produced this image
    TimeReversal::Hash256 proofsSha{};  // retained proofs used
    bool frozen = false;
    bool derivedFromPatchHistory = false; // MUST remain false

    // Generation-scoped policy (not mutable after freeze)
    uint32_t prefetchHorizon = 0;
    uint32_t gpu0LayerBegin = 0;
    uint32_t gpu0LayerEnd = 0;
    uint32_t gpu1LayerBegin = 0;
    uint32_t gpu1LayerEnd = 0;
    uint32_t justifiedRuleCount = 0;
    double targetMsPerToken = 0.0;
    double predictedMsPerToken = 0.0;
};

inline void Hash256ToQwords(const TimeReversal::Hash256& h, uint64_t out[4]) {
    std::memcpy(out, h.b, 32);
}

inline Lifetime ShortestValidLifetime(Lifetime required) {
    return required; // caller chooses minimum; bias toward Ephemeral upstream
}

} // namespace Regenerative
} // namespace Deep2
