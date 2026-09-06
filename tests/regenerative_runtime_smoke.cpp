// regenerative_runtime_smoke.cpp — P1_REGENERATIVE_RUNTIME_001 (uses trust boundary)
#include "regenerative/RegenerativeRuntime.hpp"
#include "regenerative/RegenerativeVerify.hpp"
#include <cstdio>

using namespace Deep2::Regenerative;
using Deep2::TimeReversal::Hash256;

static int fail(const char* m) {
    std::printf("FAIL %s\n", m);
    return 1;
}

int main() {
    RegenerativeRuntime rt;
    SealedCore sealed{};
    sealed.authoritySha.b[0] = 0xA1;
    sealed.generationCounter = 91;
    rt.SetSealed(sealed);
    rt.SetHardware({97.0, 32.0, 0.8, 9.0, 2});
    rt.SetWorkload({28, 384, 1, true});
    rt.SetBudgets({20.0, 50.0, false});
    rt.SetKernelAbi("rawrxd.deep2.abi.v1");

    rt.StageEphemeralSlot(0xDEAD);
    Hash256 ev{};
    rt.RetainNormalizedProof("reuse_safe_skip", 1.35, 0.90, 91, ev);
    rt.RetainNormalizedProof("gpu1_hot_residency", 2.15, 0.94, 91, ev);
    rt.RetainNormalizedProof("prefetch_horizon", 0.92, 0.91, 91, ev);
    rt.RetainNormalizedProof("kv_layout", 0.61, 0.88, 91, ev);
    rt.RetainNormalizedProof("weight_residency", 2.20, 0.95, 91, ev);
    rt.RetainNormalizedProof("ffn_skip", 1.12, 0.90, 91, ev);

    auto decision = rt.EvaluateRegen(28.20, 4.50, 3.20, 1.10, 0.40, 19.85);
    if (!decision.regenerate) return fail("SHOULD_REGENERATE");
    if (!rt.CommitCrashSafeTransition(decision, true, true, true))
        return fail("COMMIT");
    if (!rt.TrustBoundaryPass()) return fail("TRUST_BOUNDARY");
    if (!rt.RegenerativePass()) return fail("GATES");
    auto rec = rt.MakeAuthorityRecord();
    if (!VerifyAndRegenerateRuntimeImage(&rec))
        return fail("AUTHORITY");

    std::printf("%s", FormatRegenDecision(decision).c_str());
    std::printf("%s", FormatRuntimeImage(*rt.Active()).c_str());
    std::printf("P1_REGENERATIVE_RUNTIME_001 PASS\n");
    return 0;
}
