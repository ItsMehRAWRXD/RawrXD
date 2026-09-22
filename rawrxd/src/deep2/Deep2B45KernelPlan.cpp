#include "Deep2B45KernelPlan.hpp"
#include <algorithm>
#include <cmath>
#include <sstream>

namespace Deep2 {

static double qtile(std::vector<double> v,double q) {
    if(v.empty()) return 0.0;
    std::sort(v.begin(),v.end());
    double pos=q*double(v.size()-1);
    size_t lo=(size_t)std::floor(pos), hi=(size_t)std::ceil(pos);
    if(lo==hi) return v[lo];
    double f=pos-double(lo);
    return v[lo]*(1.0-f)+v[hi]*f;
}

B45KernelPlan B45KernelPlanner::derive(const B45Geometry& g,
                                       const B45LiveDevice& d0,
                                       const B45LiveDevice& d1) noexcept {
    B45KernelPlan p{};
    p.attentionWG = g.hidden>=4096 ? 256u : 128u;
    p.ffnWG = g.intermediate>=8192 ? 256u : 128u;
    p.rowsPerGroup = g.hidden>=8192 ? 8u : (g.hidden>=4096 ? 4u : 2u);
    p.prefetchDistance = g.hidden>=8192 ? 8u : 4u;
    p.layerFence = g.layers>=48 ? 4u : (g.layers>=24 ? 2u : 1u);
    p.expertConcurrency = g.expertsPerToken>=8 ? 8u :
                          (g.expertsPerToken>=4 ? 4u :
                          (g.expertsPerToken>0 ? 2u : 1u));
    p.flashMLA = g.useMLA && g.kvLoraRank>0;
    p.moeWaveKernel = g.experts>0 && g.expertsPerToken>0;

    double r0 = d0.nsPerRow>0.0 ? 1.0/d0.nsPerRow :
                (d0.bandwidthGBs>0.0 ? d0.bandwidthGBs : 1.0);
    double r1 = d1.nsPerRow>0.0 ? 1.0/d1.nsPerRow :
                (d1.bandwidthGBs>0.0 ? d1.bandwidthGBs : 1.0);
    double f0 = r0/(r0+r1);
    uint32_t pm = (uint32_t)std::llround(f0*1000.0);
    p.gpu0SharePermille = std::min(900u,std::max(100u,pm));
    return p;
}

std::string B45KernelPlanner::describe(const B45KernelPlan& p) {
    std::ostringstream o;
    o << "ATTN_WG=" << p.attentionWG
      << " FFN_WG=" << p.ffnWG
      << " ROWS_PER_GROUP=" << p.rowsPerGroup
      << " PREFETCH=" << p.prefetchDistance
      << " LAYER_FENCE=" << p.layerFence
      << " EXPERT_CONCURRENCY=" << p.expertConcurrency
      << " GPU0_SHARE_PERMILLE=" << p.gpu0SharePermille
      << " FLASH_MLA=" << (p.flashMLA?1:0)
      << " MOE_WAVE=" << (p.moeWaveKernel?1:0)
      << " DEVICE_LOGITS=" << (p.deviceLogits?1:0)
      << " DEVICE_TOKEN_HANDOFF=" << (p.deviceTokenHandoff?1:0);
    return o.str();
}

B45SealStats B45KernelPlanner::summarize(const std::vector<B45SealSample>& in) {
    B45SealStats s{};
    s.samples=in.size();
    if(in.empty()) return s;
    std::vector<double> tps,roof,bw,cf,ov,sk,hs;
    s.parityAll=true; s.stableAll=true;
    for(const auto& x:in) {
        tps.push_back(x.tps); roof.push_back(x.achievedVsRoofline);
        bw.push_back(x.bandwidthFraction); cf.push_back(x.computeFraction);
        ov.push_back(x.overlap); sk.push_back(x.skew); hs.push_back(x.hostSync);
        s.reloadBytes+=x.reloadBytes;
        s.hostMaterializations+=x.hostMaterializations;
        s.hostTokenCopies+=x.hostTokenCopies;
        s.parityAll=s.parityAll&&x.parity;
        s.stableAll=s.stableAll&&x.stable;
    }
    s.p10Tps=qtile(tps,.10); s.medianTps=qtile(tps,.50);
    s.p10RooflineFraction=qtile(roof,.10);
    s.medianRooflineFraction=qtile(roof,.50);
    s.p10Bandwidth=qtile(bw,.10); s.p10Compute=qtile(cf,.10);
    s.medianOverlap=qtile(ov,.50); s.p90Skew=qtile(sk,.90);
    s.p90HostSync=qtile(hs,.90);
    return s;
}

B45Decision B45KernelPlanner::certify(const B45SealStats& s,
                                      const B45SealGate& g) noexcept {
    if(s.samples<g.minSamples) return {false,"SAMPLES"};
    if(!s.parityAll) return {false,"PARITY"};
    if(!s.stableAll) return {false,"OUTPUT_STABILITY"};
    if(s.reloadBytes>g.maxReloadBytes) return {false,"RELOAD"};
    if(s.hostMaterializations>g.maxHostMaterializations) return {false,"HOST_MATERIALIZATION"};
    if(s.hostTokenCopies>g.maxHostTokenCopies) return {false,"HOST_TOKEN_COPY"};
    if(s.p10Tps<g.minP10Tps) return {false,"P10_TPS"};
    if(s.medianTps<g.minMedianTps) return {false,"MEDIAN_TPS"};
    if(s.p10RooflineFraction<g.minP10RooflineFraction) return {false,"P10_ROOFLINE"};
    if(s.medianRooflineFraction<g.minMedianRooflineFraction) return {false,"MEDIAN_ROOFLINE"};
    if(s.p10Bandwidth<g.minP10Bandwidth) return {false,"P10_BANDWIDTH"};
    if(s.p10Compute<g.minP10Compute) return {false,"P10_COMPUTE"};
    if(s.medianOverlap<g.minMedianOverlap) return {false,"OVERLAP"};
    if(s.p90Skew>g.maxP90Skew) return {false,"SKEW"};
    if(s.p90HostSync>g.maxP90HostSync) return {false,"HOST_SYNC"};
    return {true,"PASS"};
}

}
