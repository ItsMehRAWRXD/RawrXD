// Logic test for RAWRXD_ADAPTIVE_BLACKBOARD_INTELLIGENCE_V5 (deterministic double).
// Unit-tests the CORRECTED intelligence (real Pareto, measured-vs-measured,
// repeated validation, failure accounting). NOT a hardware measurement.
#include "AdaptiveBlackboardIntelligenceV5.hpp"
#include <cstdio>
#include <cmath>

using namespace rawrxd::blackboard_v5;
static int g_calls = 0;
static bool TestExec(const Controls& c, Measured& m) {
    ++g_calls;
    m.decodeTps  = 200.0 + 0.05 * c.batch - 0.02 * c.threads;
    m.prefillTps = 600.0 + 0.5 * c.batch;
    m.tokens = 256; m.consistent = true; m.valid = true; return true;
}
static bool FailExec(const Controls&, Measured&) { ++g_calls; return false; } // failure path

int main() {
    V5Blackboard bb; bb.rng.seed(12345);
    double firstErr = 0, lastErr = 0;
    for (int i = 0; i < 400; ++i) {
        ExploreCycleV5(bb, TestExec);
        if (i==0 && !bb.obs.empty()) firstErr = 0;
        lastErr = bb.residualVar;
    }
    // Failure accounting.
    V5Blackboard fb; fb.rng.seed(7);
    for (int i=0;i<10;++i) ExploreCycleV5(fb, FailExec);

    std::printf("ITERS=%llu OBS=%zu FRONT_OBS=%zu FRONT_VAL=%zu FAIL=%llu\n",
        (unsigned long long)bb.iterations, bb.obs.size(),
        bb.frontObserved.size(), bb.frontValidated.size(), (unsigned long long)fb.failures);
    std::printf("BEST decode=%.2f repeats=%d residVar=%.3f\n", bb.bestDecode, bb.bestRepeats, bb.residualVar);

    int fails = 0;
    auto ck=[&](bool ok,const char*n){ std::printf("%s %s\n",ok?"OK":"FAIL",n); if(!ok)++fails; };
    ck(bb.obs.size() <= bb.cap, "bounded_obs");
    ck(bb.iterations == 400, "iters_400");
    ck(fb.failures == 10, "failure_accounted");          // failures counted
    ck(bb.haveBest && bb.bestRepeats >= 2, "repeated_validation");
    ck(!bb.frontValidated.empty(), "validated_nonempty");
    ck(bb.bestDecode > 0, "best_measured_positive");
    // Pareto non-dominated check.
    bool ok=true;
    for (size_t i=0;i<bb.frontObserved.size()&&ok;++i)
        for (size_t j=0;j<bb.frontObserved.size();++j)
            if (i!=j && Dominates(bb.frontObserved[i], bb.frontObserved[j])) { ok=false; break; }
    ck(ok, "pareto_nondominated");
    std::printf("FAILS=%d\n", fails);
    return fails?1:0;
}