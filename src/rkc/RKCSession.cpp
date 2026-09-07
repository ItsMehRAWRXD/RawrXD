// RKCSession.cpp
#include "RKCSession.hpp"
#include "RKCCompiler.hpp"
#include "RKCEmit.hpp"
#include "RKCGapEngine.hpp"

namespace RawrXD {
namespace RKC {

SessionResult CompileQueryToProof(const std::string& query,
                                  const WorldObserveConfig& cfg) {
    World world;
    world.seedAll(cfg);
    CompiledGoal goal = CompileGoal(query);
    GapResult gap = ResolveGaps(world, goal);
    SessionResult r;
    r.proof = std::move(gap.proof);
    r.emitted = EmitState(r.proof);
    return r;
}

} // namespace RKC
} // namespace RawrXD
