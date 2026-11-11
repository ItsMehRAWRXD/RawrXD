#include "Deep2B35DeviceTokenHandoff.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

static double qtile(std::vector<double> v, double q) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const double pos = q * double(v.size() - 1);
    const size_t lo = static_cast<size_t>(std::floor(pos));
    const size_t hi = static_cast<size_t>(std::ceil(pos));
    if (lo == hi) return v[lo];
    const double f = pos - double(lo);
    return v[lo] * (1.0 - f) + v[hi] * f;
}

B35HandoffPlan B35DeviceTokenHandoff::make(double r0, double r1) noexcept {
    B35HandoffPlan p{};
    p.producerDevice = (r0 >= r1) ? 0u : 1u;
    p.consumerMask = 3u;
    p.ringSize = 4u;
    p.hostPoll = false;
    p.hostTokenCopy = false;
    p.deviceSemaphore = true;
    p.keepNextEmbedOnDevice = true;
    return p;
}

B35Stats B35DeviceTokenHandoff::summarize(const std::vector<B35Sample>& in) {
    B35Stats s{};
    s.samples = in.size();
    if (in.empty()) return s;

    std::vector<double> tps, bw, ov, sk, hs;
    tps.reserve(in.size()); bw.reserve(in.size()); ov.reserve(in.size());
    sk.reserve(in.size()); hs.reserve(in.size());
    s.parityAll = true;
    s.stableAll = true;

    for (const auto& x : in) {
        tps.push_back(x.targetTps);
        bw.push_back(x.bandwidthFraction);
        ov.push_back(x.overlap);
        sk.push_back(x.skew);
        hs.push_back(x.hostSyncFraction);
        s.hostTokenCopies += x.hostTokenCopies;
        s.hostMaterializations += x.hostMaterializations;
        s.reloadBytes += x.reloadBytes;
        s.gpu0Forwards += x.gpu0Forwards;
        s.gpu1Forwards += x.gpu1Forwards;
        s.parityAll = s.parityAll && x.parity;
        s.stableAll = s.stableAll && x.stable;
    }

    s.p10Tps = qtile(tps, 0.10);
    s.medianTps = qtile(tps, 0.50);
    s.p10Bandwidth = qtile(bw, 0.10);
    s.medianOverlap = qtile(ov, 0.50);
    s.p90Skew = qtile(sk, 0.90);
    s.p90HostSync = qtile(hs, 0.90);
    return s;
}

B35Decision B35DeviceTokenHandoff::certify(const B35Stats& s,
                                           const B35Gate& g) noexcept {
    if (s.samples < g.minSamples) return {false,"SAMPLES"};
    if (!s.parityAll) return {false,"PARITY"};
    if (!s.stableAll) return {false,"OUTPUT_STABILITY"};
    if (!s.gpu0Forwards || !s.gpu1Forwards) return {false,"BOTH_GPUS"};
    if (s.hostTokenCopies > g.maxHostTokenCopies) return {false,"HOST_TOKEN_COPY"};
    if (s.hostMaterializations > g.maxHostMaterializations) return {false,"HOST_MATERIALIZATION"};
    if (s.reloadBytes > g.maxReloadBytes) return {false,"RELOAD"};
    if (s.p10Tps < g.minP10Tps) return {false,"P10_TPS"};
    if (s.medianTps < g.minMedianTps) return {false,"MEDIAN_TPS"};
    if (s.p10Bandwidth < g.minP10Bandwidth) return {false,"P10_BANDWIDTH"};
    if (s.medianOverlap < g.minMedianOverlap) return {false,"OVERLAP"};
    if (s.p90Skew > g.maxP90Skew) return {false,"SKEW"};
    if (s.p90HostSync > g.maxP90HostSync) return {false,"HOST_SYNC"};
    return {true,"PASS"};
}

} // namespace Deep2
