// Reproduces the Deep2 Studio calculator numbers (modeled, not measured).
#include "AdaptiveThroughputLock.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cmath>

using namespace rawrxd::adaptive;
static int g_fails = 0;
static void check(bool ok, const char* n) { std::printf("%s %s\n", ok?"OK":"FAIL", n); if(!ok) ++g_fails; }

int main() {
    std::vector<GpuBw> gpus = {
        {"AMD Radeon AI PRO R9700", 640.0, 32.0},
        {"AMD Radeon RX 7800 XT",   624.0, 16.0},
    };
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "");

    double combined = CombinedPeakGbps(gpus);
    std::printf("COMBINED_PEAK_GBPS=%.1f\n", combined);
    check(combined > 1263.0 && combined < 1265.0, "combined_1264");

    // 80% utilization, 100% overlap -> 1011.2 effective.
    double eff = EffectiveAggregateGbps(gpus, 0.80, 1.0);
    std::printf("EFFECTIVE_AGGREGATE_GBPS=%.1f\n", eff);
    check(eff > 1010.0 && eff < 1012.0, "effective_1011");

    const double W = 18.96e9;      // active weight bytes
    const double V = eff * 1e9;    // effective aggregate B/s
    const double batch = 64.0;     // effective token batch
    double tps = ModeledTps(W, V, batch, /*R=*/1.0, /*D=*/0.0, /*S=*/1.0);
    std::printf("MODELED_TPS=%.2f\n", tps);
    check(tps > 3400.0 && tps < 3430.0, "modeled_3413");

    double minBatch = MinBatchForTarget(2450.0, W, V, 1.0, 0.0, 1.0);
    std::printf("MIN_BATCH_FOR_2450=%.0f\n", minBatch);
    check(minBatch == 46.0, "min_batch_46");

    // Override lets you reverse-engineer any aggregate.
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "2000");
    double eff2 = EffectiveAggregateGbps(gpus, 1.0, 1.0);
    std::printf("OVERRIDE_2000_EFFECTIVE=%.1f\n", eff2);
    check(eff2 > 1999.0 && eff2 < 2001.0, "override_2000");
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "");

    std::printf("FAILS=%d\n", g_fails);
    return g_fails ? 1 : 0;
}