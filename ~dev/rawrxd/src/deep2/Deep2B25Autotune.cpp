#include "Deep2B25Autotune.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

std::vector<TuneCandidate> B25Autotune::enumerate(uint32_t totalRows) {
    std::vector<TuneCandidate> out;
    const uint32_t wgs[] = {64,128,256};
    const uint32_t vecs[] = {4,8,16};
    const uint32_t tiles[] = {256,512,1024};
    const uint32_t prefetch[] = {1,2,3,4};
    const double splits[] = {0.48,0.52,0.56,0.60};

    for (auto wg : wgs) for (auto v : vecs) for (auto tc : tiles)
    for (auto pf : prefetch) for (double s : splits) {
        TuneCandidate c{};
        c.workgroup = wg;
        c.vectorWidth = v;
        c.tileRows = totalRows >= 8192 ? 4u : 2u;
        c.tileCols = tc;
        c.prefetch = pf;
        c.gpu0Rows = static_cast<uint32_t>(std::llround(double(totalRows)*s));
        c.gpu0Rows = std::min(c.gpu0Rows, totalRows);
        c.gpu1Rows = totalRows - c.gpu0Rows;
        out.push_back(c);
    }
    return out;
}

TuneDecision B25Autotune::choose(const std::vector<TuneSample>& s,
                                 const TuneGate& g) noexcept {
    TuneDecision d{};
    if (s.empty()) return d;
    double bestScore = -1.0;

    for (size_t i=0;i<s.size();++i) {
        const auto& x=s[i];
        if (!x.parity) { if (d.firstFailure=="NO_SAMPLES") d.firstFailure="PARITY"; continue; }
        if (x.reloadBytes>g.maxReloadBytes) { d.firstFailure="RELOAD"; continue; }
        if (x.hostMaterializations>g.maxHostMaterializations) { d.firstFailure="HOST_MATERIALIZATION"; continue; }
        if (x.overlap<g.minOverlap) { d.firstFailure="OVERLAP"; continue; }
        if (x.skew>g.maxSkew) { d.firstFailure="SKEW"; continue; }
        if (x.hostSyncFraction>g.maxHostSyncFraction) { d.firstFailure="HOST_SYNC"; continue; }
        if (x.bandwidthFraction<g.minBandwidthFraction) { d.firstFailure="BANDWIDTH"; continue; }
        if (x.tps<g.minTps) { d.firstFailure="TPS"; continue; }

        const double score = x.tps * (0.5 + 0.5*x.bandwidthFraction) *
                             (0.5 + 0.5*x.overlap) * (1.0 - 0.5*x.skew);
        if (score>bestScore) {
            bestScore=score;
            d.best=i;
            d.pass=true;
            d.firstFailure="PASS";
        }
    }
    return d;
}

}
