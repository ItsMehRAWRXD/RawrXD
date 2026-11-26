// Logic test for AggregateBandwidth.hpp (detect + override + effective).
#include "AggregateBandwidth.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace rawrxd;

static int g_fails = 0;
static void check(bool ok, const char* n) {
    std::printf("%s %s\n", ok ? "OK" : "FAIL", n);
    if (!ok) ++g_fails;
}

int main() {
    std::vector<GpuDeviceInfo> gpus(2);
    gpus[0].name = "Radeon AI PRO R9700";
    gpus[1].name = "AMD Radeon RX 7800 XT";

    // Detected combined = 1264 GB/s.
    double det = DetectedCombinedBandwidthGbps(gpus);
    std::printf("DETECTED_COMBINED_GBPS=%.1f\n", det);
    check(det > 1263.0 && det < 1265.0, "detected_1264");

    // No override -> effective == detected.
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "");
    double eff0 = EffectiveAggregateBandwidthGbps(gpus);
    check(eff0 > 1263.0 && eff0 < 1265.0, "effective_defaults_to_detected");

    // Override 1100 -> effective 1100 (reverse-engineer the lock target).
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "1100");
    double eff1 = EffectiveAggregateBandwidthGbps(gpus);
    std::printf("OVERRIDE_1100_EFFECTIVE=%.1f\n", eff1);
    check(eff1 > 1099.0 && eff1 < 1101.0, "override_1100");

    // Override 2000 -> effective 2000 (try an arbitrary value).
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "2000");
    double eff2 = EffectiveAggregateBandwidthGbps(gpus);
    std::printf("OVERRIDE_2000_EFFECTIVE=%.1f\n", eff2);
    check(eff2 > 1999.0 && eff2 < 2001.0, "override_2000");

    // Override 0 -> back to detected.
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "0");
    double eff3 = EffectiveAggregateBandwidthGbps(gpus);
    check(eff3 > 1263.0 && eff3 < 1265.0, "override_zero_uses_detected");
    _putenv_s("RAWRXD_AGGREGATE_BANDWIDTH_GBPS", "");

    std::printf("FAILS=%d\n", g_fails);
    return g_fails ? 1 : 0;
}