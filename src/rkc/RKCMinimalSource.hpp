// RKCMinimalSource.hpp — retrieve source only for identified gaps
#pragma once
#include "RKCWorld.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace RKC {

struct SourceHit {
    std::string symbol;
    std::string relPath;
    uint64_t bytes = 0;
};

struct MinimalSourceResult {
    std::vector<SourceHit> required; // RKC-selected
    std::vector<SourceHit> naive;    // broad dump baseline
    uint64_t bytesRkc = 0;
    uint64_t bytesNaive = 0;
    uint32_t filesRkc = 0;
    uint32_t filesNaive = 0;
    uint32_t irrelevantFiles = 0; // naive − required
    std::string emit;             // [SOURCE_REQUIRED] block
    std::string goalKey;
};

// Observe GPU-fallback ownership symbols into world (REAL / NOT_PRESENT).
void ObserveGpuFallbackPack(World& world, const std::string& repoRoot);

// After CodeWorld (+ optional packs), select minimal sources for query.
MinimalSourceResult SelectMinimalSource(World& world, const std::string& query,
                                        const std::string& repoRoot);

} // namespace RKC
} // namespace RawrXD
