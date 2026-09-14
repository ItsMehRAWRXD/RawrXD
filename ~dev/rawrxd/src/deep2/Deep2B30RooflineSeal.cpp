#include "Deep2B30RooflineSeal.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>

namespace Deep2 {

static double quantile(std::vector<double> v, double q) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const double pos = q * double(v.size() - 1);
    const size_t lo = static_cast<size_t>(std::floor(pos));
    const size_t hi = static_cast<size_t>(std::ceil(pos));
    if (lo == hi) return v[lo];
    const double f = pos - double(lo);
    return v[lo] * (1.0 - f) + v[hi] * f;
}

B30Stats B30RooflineSeal::summarize(const std::vector<B30TokenSample>& in) {
    B30Stats s{};
    s.samples = in.size();
    if (in.empty()) return s;

    std::vector<double> target, effective, bw, overlap, skew, sync;
    target.reserve(in.size()); effective.reserve(in.size()); bw.reserve(in.size());
    overlap.reserve(in.size()); skew.reserve(in.size()); sync.reserve(in.size());

    s.parityAll = true;
    s.stableAll = true;

    for (const auto& x : in) {
        target.push_back(x.targetTps);
        effective.push_back(x.effectiveTps);
        bw.push_back(x.bandwidthFraction);
        overlap.push_back(x.overlap);
        skew.push_back(x.skew);
        sync.push_back(x.hostSyncFraction);
        s.totalReloadBytes += x.reloadBytes;
        s.totalHostMaterializations += x.hostMaterializations;
        s.gpu0Forwards += x.gpu0Forwards;
        s.gpu1Forwards += x.gpu1Forwards;
        s.parityAll = s.parityAll && x.parity;
        s.stableAll = s.stableAll && x.stableOutput;
    }

    s.p10TargetTps = quantile(target, 0.10);
    s.medianTargetTps = quantile(target, 0.50);
    s.medianEffectiveTps = quantile(effective, 0.50);
    s.p10BandwidthFraction = quantile(bw, 0.10);
    s.medianOverlap = quantile(overlap, 0.50);
    s.p90Skew = quantile(skew, 0.90);
    s.p90HostSyncFraction = quantile(sync, 0.90);

    const double mean = std::accumulate(target.begin(), target.end(), 0.0) /
                        double(target.size());
    double sq = 0.0;
    for (double x : target) {
        const double d = x - mean;
        sq += d * d;
    }
    const double stdev = std::sqrt(sq / double(target.size()));
    s.targetTpsCV = mean > 0.0 ? stdev / mean : 1.0;
    return s;
}

B30Decision B30RooflineSeal::certify(const B30Stats& s,
                                     const B30Gate& g) noexcept {
    if (s.samples < g.minSamples) return {false, "SAMPLES"};
    if (g.requireParityAll && !s.parityAll) return {false, "PARITY"};
    if (g.requireStableOutputAll && !s.stableAll) return {false, "OUTPUT_STABILITY"};
    if (g.requireBothGpus && (!s.gpu0Forwards || !s.gpu1Forwards))
        return {false, "BOTH_GPUS"};
    if (s.totalReloadBytes > g.maxSteadyReloadBytes) return {false, "RELOAD"};
    if (s.totalHostMaterializations > g.maxHostMaterializations)
        return {false, "HOST_MATERIALIZATION"};
    if (s.p10TargetTps < g.minP10TargetTps) return {false, "P10_TPS"};
    if (s.medianTargetTps < g.minMedianTargetTps) return {false, "MEDIAN_TPS"};
    if (s.p10BandwidthFraction < g.minP10BandwidthFraction)
        return {false, "P10_BANDWIDTH"};
    if (s.medianOverlap < g.minMedianOverlap) return {false, "OVERLAP"};
    if (s.p90Skew > g.maxP90Skew) return {false, "SKEW"};
    if (s.p90HostSyncFraction > g.maxP90HostSyncFraction)
        return {false, "HOST_SYNC"};
    if (s.targetTpsCV > g.maxTargetTpsCV) return {false, "TPS_STABILITY"};
    return {true, "PASS"};
}

} // namespace Deep2
