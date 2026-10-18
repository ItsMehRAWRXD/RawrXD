#include "Deep2B55AsymptoticSeal.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

static double qtile(std::vector<double> v,double q) {
    if(v.empty()) return 0.0;
    std::sort(v.begin(),v.end());
    const double pos=q*double(v.size()-1);
    const size_t lo=(size_t)std::floor(pos), hi=(size_t)std::ceil(pos);
    if(lo==hi) return v[lo];
    const double f=pos-double(lo);
    return v[lo]*(1.0-f)+v[hi]*f;
}

B55Stats B55AsymptoticSeal::summarize(const std::vector<B55Sample>& in) {
    B55Stats s{};
    s.samples=in.size();
    if(in.empty()) return s;

    std::vector<double> tps,roof,bw,cf,ov,sk,hs,qi;
    s.parityAll=true; s.stableAll=true; s.bothGpusAll=true;

    for(const auto& x:in) {
        tps.push_back(x.tps); roof.push_back(x.achievedVsRoofline);
        bw.push_back(x.bandwidthFraction); cf.push_back(x.computeFraction);
        ov.push_back(x.overlap); sk.push_back(x.skew);
        hs.push_back(x.hostSync); qi.push_back(x.queueIdle);
        s.reloadBytes+=x.reloadBytes;
        s.hostMaterializations+=x.hostMaterializations;
        s.hostTokenCopies+=x.hostTokenCopies;
        s.peerCopyBytes+=x.peerCopyBytes;
        s.parityAll=s.parityAll&&x.parity;
        s.stableAll=s.stableAll&&x.stable;
        s.bothGpusAll=s.bothGpusAll&&x.bothGpus;
    }

    s.p10Tps=qtile(tps,.10);
    s.medianTps=qtile(tps,.50);
    s.p10Roofline=qtile(roof,.10);
    s.medianRoofline=qtile(roof,.50);
    s.p10Bandwidth=qtile(bw,.10);
    s.p10Compute=qtile(cf,.10);
    s.medianOverlap=qtile(ov,.50);
    s.p90Skew=qtile(sk,.90);
    s.p90HostSync=qtile(hs,.90);
    s.p90QueueIdle=qtile(qi,.90);
    return s;
}

B55Decision B55AsymptoticSeal::certify(const B55Stats& s,
                                       const B55Gate& g) noexcept {
    if(s.samples<g.minSamples) return {false,"SAMPLES"};
    if(!s.parityAll) return {false,"PARITY"};
    if(!s.stableAll) return {false,"OUTPUT_STABILITY"};
    if(!s.bothGpusAll) return {false,"BOTH_GPUS"};
    if(s.reloadBytes>g.maxReloadBytes) return {false,"RELOAD"};
    if(s.hostMaterializations>g.maxHostMaterializations) return {false,"HOST_MATERIALIZATION"};
    if(s.hostTokenCopies>g.maxHostTokenCopies) return {false,"HOST_TOKEN_COPY"};
    if(s.peerCopyBytes>g.maxPeerCopyBytes) return {false,"PEER_COPY"};
    if(s.p10Tps<g.minP10Tps) return {false,"P10_TPS"};
    if(s.medianTps<g.minMedianTps) return {false,"MEDIAN_TPS"};
    if(s.p10Roofline<g.minP10Roofline) return {false,"P10_ROOFLINE"};
    if(s.medianRoofline<g.minMedianRoofline) return {false,"MEDIAN_ROOFLINE"};
    if(s.p10Bandwidth<g.minP10Bandwidth) return {false,"P10_BANDWIDTH"};
    if(s.p10Compute<g.minP10Compute) return {false,"P10_COMPUTE"};
    if(s.medianOverlap<g.minMedianOverlap) return {false,"OVERLAP"};
    if(s.p90Skew>g.maxP90Skew) return {false,"SKEW"};
    if(s.p90HostSync>g.maxP90HostSync) return {false,"HOST_SYNC"};
    if(s.p90QueueIdle>g.maxP90QueueIdle) return {false,"QUEUE_IDLE"};
    return {true,"PASS"};
}

}
