#include "rawrxd/src/deep2/Deep2B51OwnerDirector.hpp"
#include "rawrxd/src/deep2/Deep2B52MemoryTail.hpp"
#include "rawrxd/src/deep2/Deep2B53ComputeTail.hpp"
#include "rawrxd/src/deep2/Deep2B54DeviceGraph.hpp"
#include "rawrxd/src/deep2/Deep2B55AsymptoticSeal.hpp"
#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* x){std::printf("FAIL=%s\n",x);return 1;}

int main(){
    B51Telemetry t{};
    t.bandwidthFraction=.91;
    t.computeFraction=.96;
    t.overlap=.98;
    t.hostSyncFraction=.004;
    t.queueIdleFraction=.008;
    auto owner=B51OwnerDirector::choose(t);
    if(owner.owner!=B51Owner::Memory || !owner.enableMemoryPath)
        return fail("B51");

    B52MemoryShape mshape{16384,8192,4,32,64};
    auto mp=B52MemoryTail::make(mshape);
    if(!mp.coalescedPackedLoads || !mp.xBroadcastLds ||
       !mp.scaleCacheRegisters || !mp.noRedundantXReads)
        return fail("B52");
    double eff=B52MemoryTail::payloadEfficiency(mshape, 90ull<<20);
    if(eff<=0.0) return fail("B52_EFF");

    B53ComputeShape cshape{16384,8192,64};
    auto variants=B53ComputeTail::enumerate(cshape);
    if(variants.size()<20) return fail("B53_ENUM");

    std::vector<B53Measured> meas;
    for(size_t i=0;i<10 && i<variants.size();++i){
        B53Measured x{};
        x.variant=variants[i];
        x.kernelNs=1200.0-double(i)*45.0;
        x.computeFraction=.86+double(i)*.01;
        x.occupancyFraction=.70+double(i)*.015;
        x.parity=true;
        meas.push_back(x);
    }
    auto cd=B53ComputeTail::choose(meas,.90,.74);
    if(!cd.pass) return fail("B53_CHOOSE");

    auto graph=B54DeviceGraph::make(61,true,false,8);
    if(graph.hostWakesPerToken!=0 || graph.hostWaitsPerToken!=0 ||
       !graph.deviceTimeline || !graph.persistentDescriptors ||
       !graph.tokenLoopsOnDevice || graph.nodes.empty())
        return fail("B54");

    std::vector<B55Sample> samples;
    for(int i=0;i<272;++i){
        B55Sample s{};
        double wig=double((i%17)-8)*0.02;
        s.tps=69.0+wig;
        s.achievedVsRoofline=.978+double(i%5)*.001;
        s.bandwidthFraction=.962+double(i%5)*.001;
        s.computeFraction=.918+double(i%4)*.002;
        s.overlap=.986+double(i%3)*.001;
        s.skew=.010+double(i%4)*.001;
        s.hostSync=.0015+double(i%3)*.0005;
        s.queueIdle=.003+double(i%4)*.0007;
        s.reloadBytes=0;s.hostMaterializations=0;s.hostTokenCopies=0;s.peerCopyBytes=0;
        s.parity=true;s.stable=true;s.bothGpus=true;
        samples.push_back(s);
    }

    auto st=B55AsymptoticSeal::summarize(samples);
    B55Gate g{};
    g.minSamples=256;
    g.minP10Tps=68.0;
    g.minMedianTps=68.5;
    g.minP10Roofline=.975;
    g.minMedianRoofline=.978;
    g.minP10Bandwidth=.95;
    g.minP10Compute=.90;
    g.minMedianOverlap=.98;
    g.maxP90Skew=.02;
    g.maxP90HostSync=.005;
    g.maxP90QueueIdle=.01;

    auto dec=B55AsymptoticSeal::certify(st,g);
    if(!dec.pass)return fail(dec.firstFailure);

    std::printf("DEEP2_BATCH51_55_SELFTEST=PASS\n");
    std::printf("B51_OWNER=%s\n",B51OwnerDirector::name(owner.owner));
    std::printf("B52_VEC=%u BURST=%u ROWS=%u X_TILE=%u PREFETCH=%u PAYLOAD_EFF=%.6f\n",
        mp.vectorBytes,mp.burstBytes,mp.rowsPerGroup,mp.xBroadcastTile,
        mp.prefetchDistance,eff);
    std::printf("B53_VARIANTS=%zu BEST_INDEX=%zu\n",variants.size(),cd.best);
    std::printf("B54_NODES=%zu EPOCH_SIZE=%u EPOCHS_PER_TOKEN=%u HOST_WAKES=%u HOST_WAITS=%u\n",
        graph.nodes.size(),graph.epochSize,graph.epochsPerToken,
        graph.hostWakesPerToken,graph.hostWaitsPerToken);
    std::printf("B55_SAMPLES=%zu P10_TPS=%.3f MEDIAN_TPS=%.3f P10_ROOF=%.6f MEDIAN_ROOF=%.6f\n",
        st.samples,st.p10Tps,st.medianTps,st.p10Roofline,st.medianRoofline);
    std::printf("B55_P10_BW=%.6f P10_COMPUTE=%.6f OVERLAP=%.6f P90_SKEW=%.6f P90_SYNC=%.6f P90_IDLE=%.6f\n",
        st.p10Bandwidth,st.p10Compute,st.medianOverlap,
        st.p90Skew,st.p90HostSync,st.p90QueueIdle);
    std::printf("B55_CERT=%s\n",dec.firstFailure);
    return 0;
}
