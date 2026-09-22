#include "Deep2B69ContractRunner.hpp"
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

B69Result B69ContractRunner::run(
    const B69Contract& c,
    const B68Calibration& cal,
    const std::vector<B67TokenTelemetry>& in) {

    B69Result r{};
    auto& s=r.stats;
    if(!cal.pass) {
        r.failure="CALIBRATION_HOLD";
        return r;
    }

    std::vector<double> tps,roof,ov,sk,hs,qi;
    s.parityAll=true; s.stableAll=true;

    for(const auto& x:in) {
        const auto d=B67LiveTelemetry::derive(x);
        if(x.wallNs==0) continue;

        tps.push_back(d.rawTps);
        roof.push_back(cal.physicalRooflineTps>0.0 ?
                       d.rawTps/cal.physicalRooflineTps : 0.0);
        ov.push_back(d.overlapFraction);
        sk.push_back(d.completionSkew);
        hs.push_back(d.hostSyncFraction);
        qi.push_back(d.queueIdleFraction);

        s.reloadBytes+=x.weightReloadBytes;
        s.hostMaterializations+=x.hostMaterializations;
        s.hostTokenCopies+=x.hostTokenCopies;
        s.peerCopyBytes+=x.peerCopyBytes;
        s.gpu0Forwards+=x.gpu0Forwards;
        s.gpu1Forwards+=x.gpu1Forwards;
        s.parityAll=s.parityAll&&x.parity;
        s.stableAll=s.stableAll&&x.stableOutput;
    }

    s.samples=tps.size();
    if(!s.samples) {
        r.failure="NO_SAMPLES";
        return r;
    }

    s.p10Tps=qtile(tps,.10);
    s.medianTps=qtile(tps,.50);
    s.p10RooflineFraction=qtile(roof,.10);
    s.medianOverlap=qtile(ov,.50);
    s.p90Skew=qtile(sk,.90);
    s.p90HostSync=qtile(hs,.90);
    s.p90QueueIdle=qtile(qi,.90);

    if(s.samples<c.minSamples) {r.failure="SAMPLES";return r;}
    if(!s.parityAll) {r.failure="PARITY";return r;}
    if(!s.stableAll) {r.failure="OUTPUT_STABILITY";return r;}
    if(!s.gpu0Forwards||!s.gpu1Forwards) {r.failure="BOTH_GPUS";return r;}
    if(s.reloadBytes) {r.failure="RELOAD";return r;}
    if(s.hostMaterializations) {r.failure="HOST_MATERIALIZATION";return r;}
    if(s.hostTokenCopies) {r.failure="HOST_TOKEN_COPY";return r;}
    if(s.peerCopyBytes) {r.failure="PEER_COPY";return r;}

    // The requested floor itself must remain physically attainable.
    if(c.minMedianTps > cal.physicalRooflineTps/cal.requiredHeadroom) {
        r.failure="TARGET_EXCEEDS_PHYSICAL_ROOFLINE";
        return r;
    }

    if(s.p10Tps<c.minP10Tps) {r.failure="P10_TPS";return r;}
    if(s.medianTps<c.minMedianTps) {r.failure="MEDIAN_TPS";return r;}
    if(s.p10RooflineFraction<c.minP10RooflineFraction) {r.failure="P10_ROOFLINE";return r;}
    if(s.medianOverlap<c.minMedianOverlap) {r.failure="OVERLAP";return r;}
    if(s.p90Skew>c.maxP90Skew) {r.failure="SKEW";return r;}
    if(s.p90HostSync>c.maxP90HostSync) {r.failure="HOST_SYNC";return r;}
    if(s.p90QueueIdle>c.maxP90QueueIdle) {r.failure="QUEUE_IDLE";return r;}

    r.pass=true;
    r.failure="PASS";
    return r;
}

} // namespace Deep2
