#include "Deep2B60ModelContract.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

static double qtile(std::vector<double> v,double q) {
    if(v.empty()) return 0.0;
    std::sort(v.begin(),v.end());
    const double pos=q*double(v.size()-1);
    const size_t lo=(size_t)std::floor(pos),hi=(size_t)std::ceil(pos);
    if(lo==hi) return v[lo];
    const double f=pos-double(lo);
    return v[lo]*(1.0-f)+v[hi]*f;
}

B60Stats B60ModelContract::summarize(const std::vector<B60Sample>& in) {
    B60Stats s{};
    s.samples=in.size();
    if(in.empty()) return s;

    std::vector<double> raw,eff,roof,bw,cf,ov,sk,hs,qi;
    s.bothGpusAll=true; s.parityAll=true; s.stableAll=true;

    for(const auto& x:in) {
        raw.push_back(x.rawTps); eff.push_back(x.effectiveTps);
        roof.push_back(x.rooflineFraction);
        bw.push_back(x.bandwidthFraction); cf.push_back(x.computeFraction);
        ov.push_back(x.overlap); sk.push_back(x.skew);
        hs.push_back(x.hostSync); qi.push_back(x.queueIdle);
        s.reloadBytes+=x.reloadBytes;
        s.hostMaterializations+=x.hostMaterializations;
        s.hostTokenCopies+=x.hostTokenCopies;
        s.peerCopyBytes+=x.peerCopyBytes;
        s.bothGpusAll=s.bothGpusAll&&x.bothGpus;
        s.parityAll=s.parityAll&&x.parity;
        s.stableAll=s.stableAll&&x.stable;
    }

    s.p10RawTps=qtile(raw,.10);
    s.medianRawTps=qtile(raw,.50);
    s.medianEffectiveTps=qtile(eff,.50);
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

B60Decision B60ModelContract::certify(const B60Stats& s,
                                      const B60Contract& c) noexcept {
    if(s.samples<c.minSamples) return {false,"SAMPLES"};
    if(!s.bothGpusAll) return {false,"BOTH_GPUS"};
    if(!s.parityAll) return {false,"PARITY"};
    if(!s.stableAll) return {false,"OUTPUT_STABILITY"};
    if(s.reloadBytes) return {false,"RELOAD"};
    if(s.hostMaterializations) return {false,"HOST_MATERIALIZATION"};
    if(s.hostTokenCopies) return {false,"HOST_TOKEN_COPY"};
    if(s.peerCopyBytes) return {false,"PEER_COPY"};
    if(s.p10RawTps<c.minP10RawTps) return {false,"P10_RAW_TPS"};
    if(s.medianRawTps<c.minMedianRawTps) return {false,"MEDIAN_RAW_TPS"};
    if(s.p10Roofline<c.minP10Roofline) return {false,"P10_ROOFLINE"};
    if(s.medianRoofline<c.minMedianRoofline) return {false,"MEDIAN_ROOFLINE"};
    if(s.p10Bandwidth<c.minP10Bandwidth) return {false,"P10_BANDWIDTH"};
    if(s.p10Compute<c.minP10Compute) return {false,"P10_COMPUTE"};
    if(s.medianOverlap<c.minMedianOverlap) return {false,"OVERLAP"};
    if(s.p90Skew>c.maxP90Skew) return {false,"SKEW"};
    if(s.p90HostSync>c.maxP90HostSync) return {false,"HOST_SYNC"};
    if(s.p90QueueIdle>c.maxP90QueueIdle) return {false,"QUEUE_IDLE"};
    return {true,"PASS"};
}

}
