// RKCGapEngine.hpp — resolve MISSING via derive/observe/synthesize candidates
#pragma once
#include "RKCCompiler.hpp"
#include "RKCTypes.hpp"
#include "RKCWorld.hpp"

namespace RawrXD {
namespace RKC {

struct GapResult {
    ProofState proof;
};

GapResult ResolveGaps(World& world, const CompiledGoal& goal);

} // namespace RKC
} // namespace RawrXD
