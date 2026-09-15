#include "Deep2B40PhysicalSeal.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

static double qtile(std::vector<double> v, double q) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    double pos = q * double(v.size() - 1);
    size_t lo = (size_t)std::floor(pos), hi = (size_t)std::ceil(pos);
    if (lo == hi) return v[lo];
    double f = pos - double(lo);
    return v[lo] * (1.0 - f) + v[hi] * f;
}

B40PhysicalStats B40PhysicalSeal::summarize(const std::vector<B40PhysicalSample>& in) {
    B40PhysicalStats s{};
    s.samples = in.size();
    if (in.empty()) return s;
    std::vector<double> tps, roof, bw, cf, ov, sk, hs;
    s.parityAll = true; s.stableAll = true;
    for (const auto& x : in) {
        tps.push_back(x.tps); roof.push_back(x.achievedVsRoofline);
        bw.push_back(x.bandwidthFraction); cf.push_back(x.computeFraction);
        ov.push_back(x.overlap); sk.push_back(x.skew); hs.push_back(x.hostSync);
        s.reloadBytes += x.reloadBytes;
        s.hostMaterializations += x.hostMaterializations;
        s.hostTokenCopies += x.hostTokenCopies;
        s.parityAll = s.parityAll && x.parity;
        s.stableAll = s.stableAll && x.stable;
    }
    s.p10Tps = qtile(tps, .10); s.medianTps = qtile(tps, .50);
    s.p10RooflineFraction = qtile(roof, .10);
    s.medianRooflineFraction = qtile(roof, .50);
    s.p10Bandwidth = qtile(bw, .10); s.p10Compute = qtile(cf, .10);
    s.medianOverlap = qtile(ov, .50); s.p90Skew = qtile(sk, .90);
    s.p90HostSync = qtile(hs, .90);
    return s;
}

B40PhysicalDecision B40PhysicalSeal::certify(const B40PhysicalStats& s,
                                             const B40PhysicalGate& g) noexcept {
    if (s.samples < g.minSamples) return {false, "SAMPLES"};
    if (!s.parityAll) return {false, "PARITY"};
    if (!s.stableAll) return {false, "OUTPUT_STABILITY"};
    if (s.reloadBytes > g.maxReloadBytes) return {false, "RELOAD"};
    if (s.hostMaterializations > g.maxHostMaterializations) return {false, "HOST_MATERIALIZATION"};
    if (s.hostTokenCopies > g.maxHostTokenCopies) return {false, "HOST_TOKEN_COPY"};
    if (s.p10Tps < g.minP10Tps) return {false, "P10_TPS"};
    if (s.medianTps < g.minMedianTps) return {false, "MEDIAN_TPS"};
    if (s.p10RooflineFraction < g.minP10RooflineFraction) return {false, "P10_ROOFLINE"};
    if (s.medianRooflineFraction < g.minMedianRooflineFraction) return {false, "MEDIAN_ROOFLINE"};
    if (s.p10Bandwidth < g.minP10Bandwidth) return {false, "P10_BANDWIDTH"};
    if (s.p10Compute < g.minP10Compute) return {false, "P10_COMPUTE"};
    if (s.medianOverlap < g.minMedianOverlap) return {false, "OVERLAP"};
    if (s.p90Skew > g.maxP90Skew) return {false, "SKEW"};
    if (s.p90HostSync > g.maxP90HostSync) return {false, "HOST_SYNC"};
    return {true, "PASS"};
}

} // namespace Deep2
