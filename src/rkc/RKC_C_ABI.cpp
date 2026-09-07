// RKC_C_ABI.cpp — session + C entrypoints
#include "RKC.h"
#include "RKCCompiler.hpp"
#include "RKCEmit.hpp"
#include "RKCGapEngine.hpp"
#include "RKCValidator.hpp"
#include "RKCWorld.hpp"
#include <cstring>
#include <string>

namespace {

RawrXD::RKC::World g_world;
RawrXD::RKC::WorldObserveConfig g_cfg;
RawrXD::RKC::CompiledGoal g_goal;
RawrXD::RKC::ProofState g_proof;
std::string g_emitted;
bool g_ready = false;

} // namespace

extern "C" int RKC_BeginGoal(const char* queryUtf8, const char* modelPathUtf8) {
    g_ready = false;
    g_emitted.clear();
    g_proof = {};
    g_cfg = {};
    if (modelPathUtf8 && modelPathUtf8[0])
        g_cfg.modelPath = modelPathUtf8;
    const char* q = queryUtf8 ? queryUtf8 : "";
    g_goal = RawrXD::RKC::CompileGoal(q);
    g_world.seedAll(g_cfg);
    g_ready = true;
    return 1;
}

extern "C" void RKC_SetHardware(unsigned long long vram, unsigned long long weights,
                               unsigned long long kv, unsigned long long arena,
                               unsigned long long margin) {
    g_cfg.availableVram = vram;
    g_cfg.weightsBytes = weights;
    g_cfg.kvBudget = kv;
    g_cfg.forwardArena = arena;
    g_cfg.safetyMargin = margin ? margin : g_cfg.safetyMargin;
    if (g_ready) g_world.seedAll(g_cfg);
}

extern "C" int RKC_Resolve(void) {
    if (!g_ready) return 0;
    g_world.seedAll(g_cfg);
    auto gap = RawrXD::RKC::ResolveGaps(g_world, g_goal);
    g_proof = std::move(gap.proof);
    g_emitted = RawrXD::RKC::EmitState(g_proof);
    return 1;
}

extern "C" int RKC_EmitState(char* out, size_t cap) {
    if (!out || cap == 0) return -1;
    if (g_emitted.empty() && g_ready) {
        if (!RKC_Resolve()) return -1;
    }
    if (g_emitted.size() + 1 > cap) {
        std::memcpy(out, g_emitted.data(), cap - 1);
        out[cap - 1] = '\0';
        return -1;
    }
    std::memcpy(out, g_emitted.data(), g_emitted.size());
    out[g_emitted.size()] = '\0';
    return static_cast<int>(g_emitted.size());
}

extern "C" int RKC_VerifyNoSyntheticToReal(void) {
    auto r = RawrXD::RKC::TryPromote(RawrXD::RKC::EpistemicState::Synthetic,
                                     RawrXD::RKC::EpistemicState::Real, true);
    return r.ok ? 0 : 1;
}

extern "C" void RKC_Require(const char* keyUtf8) {
    if (!keyUtf8 || !keyUtf8[0]) return;
    for (const auto& k : g_goal.requiredKeys)
        if (k == keyUtf8) return;
    g_goal.requiredKeys.push_back(keyUtf8);
}

extern "C" int RKC_Reconstruct(void) {
    return RKC_Resolve();
}

extern "C" int RKC_Verify(void) {
    return RKC_VerifyNoSyntheticToReal();
}
