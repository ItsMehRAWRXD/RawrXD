// Logic test for the integrated RNG-free polymorphic blackboard.
// Deterministic test double (unit logic), NOT hardware. Verifies zero-RNG
// construction, deterministic replay, ratio allocation, best retention.
#include "PolymorphicBlackboard.hpp"
#include <cstdio>
#include <vector>

using namespace rawrxd::polybb;
using namespace rawrxd::poly;
static bool TestExec(const rawrxd::poly::Cand& c, Measured& m) {
    m.decodeTps  = 200.0 + 0.05 * c.batch - 0.02 * c.threads;
    m.prefillTps = 600.0 + 0.5 * c.batch;
    m.tokens = 256; m.consistent = true; m.valid = true; return true;
}
static std::vector<rawrxd::poly::Cand> Run(const rawrxd::poly::Ratio& r) {
    Blackboard bb; bb.ratio = r;
    std::vector<rawrxd::poly::Cand> seq;
    for (int i = 0; i < 60; ++i) { Step(bb, TestExec); seq.push_back(bb.current); }
    return seq;
}
int main() {
    rawrxd::poly::Ratio r; // 50 50
    auto a = Run(r), b = Run(r);
    bool replay = (a == b);
    rawrxd::poly::Ratio r2; r2.set(20, 80);
    auto c = Run(r2);
    bool ratioEff = false;
    for (size_t i = 0; i < a.size(); ++i) if (!(a[i] == c[i])) { ratioEff = true; break; }

    // Ratio allocation accounting.
    Blackboard bb; bb.ratio = r;
    for (int i = 0; i < 100; ++i) Step(bb, TestExec);
    double share0 = (double)bb.alloc0 / (double)(bb.alloc0 + bb.alloc1 + 1);

    std::printf("REPLAY=%d RATIO_EFFECT=%d ALLOC0=%llu ALLOC1=%llu share0=%.2f\n",
        replay, ratioEff, (unsigned long long)bb.alloc0, (unsigned long long)bb.alloc1, share0);
    std::printf("BEST decode=%.2f repeats=%d obs=%zu fails=%llu\n",
        bb.bestDecode, bb.bestRepeats, bb.obs.size(), (unsigned long long)bb.failures);

    int fails = 0;
    auto ck=[&](bool ok,const char*n){ std::printf("%s %s\n",ok?"OK":"FAIL",n); if(!ok)++fails; };
    ck(replay, "deterministic_replay");
    ck(ratioEff, "ratio_changes_behavior");
    ck(bb.obs.size() <= bb.cap, "bounded_obs");
    ck(bb.haveBest && bb.bestRepeats >= 2, "best_repeated_validation");
    ck(share0 > 0.35 && share0 < 0.65, "ratio_allocation_50_50"); // ~50/50
    std::printf("FAILS=%d\n", fails);
    return fails?1:0;
}