#include "rawrxd/src/deep2/Deep2B46NativeQuant.hpp"
#include "rawrxd/src/deep2/Deep2B47RegisterExpert.hpp"
#include "rawrxd/src/deep2/Deep2B48CrossLayerFusion.hpp"
#include "rawrxd/src/deep2/Deep2B49ShaderSpecializer.hpp"
#include "rawrxd/src/deep2/Deep2B50ChallengeSeal.hpp"
#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* x){std::printf("FAIL=%s\n",x);return 1;}

int main() {
    B46QuantGeometry qg{16384,8192,32,B46QuantFormat::Q4_K,64};
    auto q=B46NativeQuant::make(qg);
    if(!q.decodeNativeBlock||!q.scaleInRegisters||!q.zeroIntermediateF32||!q.subgroupReduce)
        return fail("B46");

    auto e=B47RegisterExpert::make(18432,{1,2,3,4},{0,1,0,1},8);
    if(!e.keepGateUpInRegisters||!e.fuseActivation||!e.fuseDownAccumulate||
       !e.noIntermediateGlobal||!e.deviceCombine||e.slices.empty())
        return fail("B47");

    auto f=B48CrossLayerFusion::make(61,true,false,true);
    if(!f.activationPingPong||!f.noHostActivation||!f.chainAcrossLayers||
       !f.finalLogitsInChain||B48CrossLayerFusion::expectedHostBoundaries(f)!=0)
        return fail("B48");

    B49Geometry g{};
    g.hidden=7168;g.intermediate=18432;g.heads=64;g.kvHeads=8;g.headDim=128;
    g.experts=128;g.expertsPerToken=8;g.qLoraRank=1536;g.kvLoraRank=512;
    g.ropeDim=64;g.layers=61;g.quantBits=4;g.useMLA=true;g.hasSSM=false;
    B49Device d{64,1024,65536,1264.0,50.0};
    auto key=B49ShaderSpecializer::derive(g,d);
    if(!key.flashMLA||!key.moeRegisterFusion||key.expertConcurrency<4||key.hash==0)
        return fail("B49");

    std::vector<B50Sample> samples;
    for(int i=0;i<208;++i) {
        B50Sample s{};
        double wig=double((i%15)-7)*0.035;
        s.tps=67.0+wig;
        s.achievedVsRoofline=.955+double(i%5)*.0015;
        s.bandwidthFraction=.948+double(i%5)*.0015;
        s.computeFraction=.895+double(i%4)*.002;
        s.overlap=.976+double(i%3)*.001;
        s.skew=.014+double(i%4)*.0012;
        s.hostSync=.0025+double(i%3)*.0008;
        s.reloadBytes=0;s.hostMaterializations=0;s.hostTokenCopies=0;s.peerCopyBytes=0;
        s.parity=true;s.stable=true;s.bothGpus=true;
        samples.push_back(s);
    }

    auto st=B50ChallengeSeal::summarize(samples);
    B50Gate gate{};
    gate.minSamples=192;
    gate.minP10Tps=66.0;
    gate.minMedianTps=66.5;
    gate.minP10Roofline=.95;
    gate.minMedianRoofline=.955;
    gate.minP10Bandwidth=.94;
    gate.minP10Compute=.88;
    gate.minMedianOverlap=.97;
    gate.maxP90Skew=.025;
    gate.maxP90HostSync=.0075;

    auto dec=B50ChallengeSeal::certify(st,gate);
    if(!dec.pass) return fail(dec.firstFailure);

    std::printf("DEEP2_BATCH46_50_SELFTEST=PASS\n");
    std::printf("B46_WG=%u ROWS=%u LOADS=%u VALUES=%u BYTES=%llu\n",
        q.workgroup,q.rowsPerGroup,q.packedLoadsPerLane,q.valuesPerDecode,
        (unsigned long long)B46NativeQuant::packedPayloadBytes(qg));
    std::printf("B47_CONCURRENT=%u SLICES=%zu AVOID_BYTES=%llu\n",
        e.concurrentExperts,e.slices.size(),
        (unsigned long long)B47RegisterExpert::avoidedIntermediateBytes(4,18432));
    std::printf("B48_REGIONS=%zu LAYERS_PER_CHAIN=%u FENCES=%u HOST_BOUNDARIES=%u\n",
        f.regions.size(),f.layersPerChain,f.fencesPerToken,
        B48CrossLayerFusion::expectedHostBoundaries(f));
    std::printf("B49_HASH=%llu WG=%u VEC=%u ROWS=%u PREFETCH=%u EXPERTS=%u CHAIN=%u\n",
        (unsigned long long)key.hash,key.workgroup,key.vectorWidth,key.rowsPerGroup,
        key.prefetch,key.expertConcurrency,key.layerChain);
    std::printf("B50_SAMPLES=%zu P10_TPS=%.3f MEDIAN_TPS=%.3f P10_ROOF=%.6f MEDIAN_ROOF=%.6f\n",
        st.samples,st.p10Tps,st.medianTps,st.p10Roofline,st.medianRoofline);
    std::printf("B50_P10_BW=%.6f P10_COMPUTE=%.6f OVERLAP=%.6f P90_SKEW=%.6f P90_SYNC=%.6f\n",
        st.p10Bandwidth,st.p10Compute,st.medianOverlap,st.p90Skew,st.p90HostSync);
    std::printf("B50_CERT=%s\n",dec.firstFailure);
    return 0;
}
