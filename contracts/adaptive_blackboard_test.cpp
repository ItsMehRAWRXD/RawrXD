// Logic test for RAWRXD_ADAPTIVE_BLACKBOARD_INTELLIGENCE_001 (modeled search).
#include "AdaptiveBlackboardIntelligence.hpp"
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

    blackboard::Blackboard bb;
    blackboard::InitBlackboard(bb, gpus);
    const double initial = bb.best.modeledTps;

    for (int i = 0; i < 500; ++i) blackboard::ExploreCycle(bb, gpus);

    std::printf("INITIAL_MODELED_TPS=%.2f\n", initial);
    std::printf("BEST_MODELED_TPS=%.2f\n", bb.best.modeledTps);
    std::printf("CURRENT_MODELED_TPS=%.2f\n", bb.current.modeledTps);
    std::printf("ITERATIONS=%llu ACCEPTS=%llu REJECTS=%llu TEMP=%.3f\n",
        (unsigned long long)bb.iterations, (unsigned long long)bb.accepts,
        (unsigned long long)bb.rejects, bb.temperature);

    check(bb.iterations == 500, "iterations_500");
    check(bb.best.modeledTps >= initial, "best_ge_initial");
    check(std::isfinite(bb.best.modeledTps), "best_finite");
    check(bb.accepts + bb.rejects == 500, "accept_reject_sum");
    check(bb.temperature >= 0.05, "temperature_floored");
    // best is monotonic non-decreasing across the search.
    check(bb.best.modeledTps >= bb.current.modeledTps - 1e-9, "best_ge_current");

    std::printf("FAILS=%d\n", g_fails);
    return g_fails ? 1 : 0;
}