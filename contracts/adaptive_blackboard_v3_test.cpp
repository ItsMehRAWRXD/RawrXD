// Logic test for RAWRXD_ADAPTIVE_BLACKBOARD_INTELLIGENCE_V3 (modeled).
#include "AdaptiveBlackboardIntelligenceV3.hpp"
#include <cstdio>
#include <vector>
#include <cmath>

using namespace rawrxd;
static int g_fails = 0;
static void check(bool ok, const char* n) { std::printf("%s %s\n", ok?"OK":"FAIL", n); if(!ok) ++g_fails; }

int main() {
    std::vector<adaptive::GpuBw> gpus = {
        {"AMD Radeon AI PRO R9700", 640.0, 32.0},
        {"AMD Radeon RX 7800 XT",   624.0, 16.0},
    };
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "");

    blackboard_v3::V3Blackboard bb;
    blackboard_v3::InitV3(bb, gpus);
    const double initialDecode = bb.best.decodeTps;

    for (int i = 0; i < 300; ++i) blackboard_v3::ExploreCycleV3(bb, gpus);

    std::printf("INITIAL_DECODE=%.2f BEST_DECODE=%.2f\n", initialDecode, bb.best.decodeTps);
    std::printf("OBS=%llu PARETO=%zu ITERS=%llu ACC=%llu REJ=%llu TEMP=%.3f\n",
        (unsigned long long)bb.obs.size(), bb.pareto.size(),
        (unsigned long long)bb.iterations, (unsigned long long)bb.accepts,
        (unsigned long long)bb.rejects, bb.temperature);

    check(bb.obs.size() == 300, "obs_300");
    check(bb.iterations == 300, "iters_300");
    check(!bb.pareto.empty(), "pareto_nonempty");
    check(bb.best.decodeTps >= initialDecode, "best_ge_initial");
    check(std::isfinite(bb.best.decodeTps), "best_finite");
    check(bb.accepts + bb.rejects == 300, "acc_rej_sum");
    check(bb.temperature >= 0.05 && bb.temperature <= 1.0, "temp_bounds");
    // Pareto frontier is mutually non-dominating.
    bool ok = true;
    for (size_t i=0;i<bb.pareto.size() && ok;++i)
        for (size_t j=0;j<bb.pareto.size();++j)
            if (i!=j && blackboard_v3::Dominates(bb.pareto[i], bb.pareto[j])) { ok=false; break; }
    check(ok, "pareto_nondominated");

    std::printf("FAILS=%d\n", g_fails);
    return g_fails ? 1 : 0;
}