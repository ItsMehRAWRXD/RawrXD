#include "rawrxd/src/deep2/Deep2B56LayerPhasePlanner.hpp"
#include "rawrxd/src/deep2/Deep2B57ContextKernel.hpp"
#include "rawrxd/src/deep2/Deep2B58RouteSpecializer.hpp"
#include "rawrxd/src/deep2/Deep2B59StabilityGovernor.hpp"
#include "rawrxd/src/deep2/Deep2B60ModelContract.hpp"
#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* x){std::printf("FAIL=%s\n",x);return 1;}

int main(){
    std::vector<B56LayerDesc> desc;
    for(uint32_t i=0;i<61;++i){
        desc.push_back({i,B56LayerKind::MLA,7168,18432,128,8,512});
    }
    auto layers=B56LayerPhasePlanner::make(desc);
    if(layers.size()!=61 || !layers[0].flashAttention ||
       layers[0].expertConcurrency!=1)
        return fail("B56");

    B57ContextShape cs{};
    cs.context=262144;cs.heads=64;cs.kvHeads=8;cs.headDim=128;
    cs.kvRank=512;cs.useMLA=true;
    auto cp=B57ContextKernel::make(cs);
    if(!cp.flashStreaming || !cp.pagedKv || cp.tokenTile<256)
        return fail("B57");

    std::vector<B58RouteSample> routes;
    for(uint32_t i=0;i<16;++i)
        routes.push_back({i,1000u-i*25u,8000.0+double(i)*100.0,i&1u});
    auto rp=B58RouteSpecializer::make(routes,8,6);
    if(rp.hotExperts.size()!=8 || rp.prefetchTopN!=6 ||
       !rp.deterministicPlacement || !rp.greedyHashStable)
        return fail("B58");

    B59Telemetry tele{};
    tele.recentTps=68.5;tele.baselineTps=69.0;
    tele.recentBandwidthFraction=.97;tele.recentComputeFraction=.93;
    tele.recentSkew=.012;tele.recentQueueIdle=.004;
    auto sg=B59StabilityGovernor::make(tele);
    if(sg.holdTuning || sg.disableSpeculation)
        return fail("B59");

    std::vector<B60Sample> samples;
    for(int i=0;i<336;++i){
        B60Sample s{};
        double wig=double((i%19)-9)*0.012;
        s.rawTps=70.0+wig;
        s.effectiveTps=84.0+wig*1.15;
        s.rooflineFraction=.987+double(i%5)*.0006;
        s.bandwidthFraction=.972+double(i%5)*.0008;
        s.computeFraction=.932+double(i%4)*.0015;
        s.overlap=.990+double(i%3)*.0005;
        s.skew=.007+double(i%4)*.001;
        s.hostSync=.0010+double(i%3)*.00035;
        s.queueIdle=.0020+double(i%4)*.0005;
        s.reloadBytes=0;s.hostMaterializations=0;s.hostTokenCopies=0;s.peerCopyBytes=0;
        s.bothGpus=true;s.parity=true;s.stable=true;
        samples.push_back(s);
    }

    auto st=B60ModelContract::summarize(samples);
    B60Contract contract{};
    contract.modelKey="synthetic-test";
    contract.minSamples=320;
    contract.minP10RawTps=69.5;
    contract.minMedianRawTps=69.8;
    contract.minP10Roofline=.985;
    contract.minMedianRoofline=.987;
    contract.minP10Bandwidth=.97;
    contract.minP10Compute=.92;
    contract.minMedianOverlap=.985;
    contract.maxP90Skew=.015;
    contract.maxP90HostSync=.003;
    contract.maxP90QueueIdle=.0075;

    auto dec=B60ModelContract::certify(st,contract);
    if(!dec.pass)return fail(dec.firstFailure);

    std::printf("DEEP2_BATCH56_60_SELFTEST=PASS\n");
    std::printf("B56_LAYERS=%zu WG0=%u FENCE_GROUP_LAST=%u\n",
        layers.size(),layers[0].workgroup,layers.back().layerFenceGroup);
    std::printf("B57_CONTEXT=%u TOKEN_TILE=%u HEAD_TILE=%u KV_PAGE=%u\n",
        cs.context,cp.tokenTile,cp.headTile,cp.kvPageTokens);
    std::printf("B58_HOT=%zu COLD=%zu PREFETCH=%u PIN=%u\n",
        rp.hotExperts.size(),rp.coldExperts.size(),rp.prefetchTopN,rp.pinTopN);
    std::printf("B59_HOLD=%u CONCURRENCY=%u RECERTIFY=%u\n",
        sg.holdTuning?1u:0u,sg.concurrencyScalePct,sg.recertify?1u:0u);
    std::printf("B60_SAMPLES=%zu P10_RAW_TPS=%.3f MEDIAN_RAW_TPS=%.3f MEDIAN_EFFECTIVE_TPS=%.3f\n",
        st.samples,st.p10RawTps,st.medianRawTps,st.medianEffectiveTps);
    std::printf("B60_P10_ROOF=%.6f MEDIAN_ROOF=%.6f P10_BW=%.6f P10_COMPUTE=%.6f OVERLAP=%.6f\n",
        st.p10Roofline,st.medianRoofline,st.p10Bandwidth,st.p10Compute,st.medianOverlap);
    std::printf("B60_P90_SKEW=%.6f P90_SYNC=%.6f P90_IDLE=%.6f CERT=%s\n",
        st.p90Skew,st.p90HostSync,st.p90QueueIdle,dec.firstFailure);
    return 0;
}
