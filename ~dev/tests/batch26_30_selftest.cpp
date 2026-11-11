#include "rawrxd/src/deep2/Deep2B26AttentionSuperkernel.hpp"
#include "rawrxd/src/deep2/Deep2B27MoESuperkernel.hpp"
#include "rawrxd/src/deep2/Deep2B28DeviceLogits.hpp"
#include "rawrxd/src/deep2/Deep2B29LayerChain.hpp"
#include "rawrxd/src/deep2/Deep2B30RooflineSeal.hpp"
#include <cstdio>
#include <vector>
#include <cmath>

using namespace Deep2;

static int fail(const char* x) {
    std::printf("FAIL=%s\n", x);
    return 1;
}

int main() {
    B26AttentionShape ash{};
    ash.hidden=7168; ash.heads=64; ash.kvHeads=8; ash.headDim=128;
    ash.qLoraRank=1536; ash.kvLoraRank=512; ash.qkRopeDim=64; ash.useMLA=true;
    auto ap=B26AttentionSuperkernel::make(ash);
    if(!ap.fuseRmsNorm || !ap.fuseQkv || !ap.fuseRope || !ap.mlaCompressedPath)
        return fail("B26_PLAN");

    std::vector<B27ExpertTask> tasks = {
        {1,0,.40f,64ull<<20,true,8500.0},
        {2,1,.30f,64ull<<20,true,9200.0},
        {3,0,.20f,64ull<<20,true,7900.0},
        {4,1,.10f,64ull<<20,false,12000.0}
    };
    auto mp=B27MoESuperkernel::make(tasks,64,60);
    if(!mp.fuseGateUp || !mp.fuseSiluMul || !mp.fuseDownAccumulate ||
       !mp.deviceCombine || mp.maxConcurrentExperts<4)
        return fail("B27_PLAN");

    B28LogitsShape ls{7168,151936,4,true};
    auto lp=B28DeviceLogits::make(ls,1.0,0.92);
    if(lp.materializeFullLogits || !lp.fuseLmHeadArgmax ||
       lp.vocab0End+ (lp.vocab1End-lp.vocab1Begin) != ls.vocab)
        return fail("B28_PLAN");
    auto merged=B28DeviceLogits::merge({9.2f,123},{9.3f,456});
    if(merged.token!=456) return fail("B28_MERGE");

    auto cp=B29LayerChain::make(61,true,true);
    if(cp.hostMaterialization || cp.hostSyncsPerToken!=0 ||
       !cp.persistentActivationPingPong || !cp.deviceToDeviceEdges)
        return fail("B29_PLAN");

    std::vector<B30TokenSample> samples;
    for(int i=0;i<80;++i) {
        B30TokenSample s{};
        const double wiggle = (double((i%7)-3))*0.18;
        s.targetTps = 52.0 + wiggle;
        s.effectiveTps = 70.0 + wiggle*1.2;
        s.bandwidthFraction = 0.82 + double(i%5)*0.002;
        s.overlap = 0.91 + double(i%3)*0.003;
        s.skew = 0.031 + double(i%4)*0.002;
        s.hostSyncFraction = 0.014 + double(i%3)*0.001;
        s.reloadBytes=0;
        s.hostMaterializations=0;
        s.gpu0Forwards=61;
        s.gpu1Forwards=61;
        s.parity=true;
        s.stableOutput=true;
        samples.push_back(s);
    }

    auto st=B30RooflineSeal::summarize(samples);
    B30Gate gate{};
    gate.minSamples=64;
    gate.minP10TargetTps=50.0;
    gate.minMedianTargetTps=51.0;
    gate.minP10BandwidthFraction=.80;
    gate.minMedianOverlap=.90;
    gate.maxP90Skew=.05;
    gate.maxP90HostSyncFraction=.03;
    gate.maxTargetTpsCV=.05;
    auto dec=B30RooflineSeal::certify(st,gate);
    if(!dec.pass) return fail(dec.firstFailure);

    std::printf("DEEP2_BATCH26_30_SELFTEST=PASS\n");
    std::printf("B26_WG=%u VEC=%u ELIM_BYTES=%llu\n",
        ap.workgroup,ap.vectorWidth,
        (unsigned long long)B26AttentionSuperkernel::eliminatedIntermediateBytes(ash));
    std::printf("B27_GPU_TASKS=%u/%u CONCURRENT=%u AVOID_BYTES=%llu\n",
        mp.gpu0Tasks,mp.gpu1Tasks,mp.maxConcurrentExperts,
        (unsigned long long)B27MoESuperkernel::avoidableActivationTraffic(4,18432));
    std::printf("B28_VOCAB_SPLIT=%u/%u AVOID_D2H=%llu\n",
        lp.vocab0End,lp.vocab1End-lp.vocab1Begin,
        (unsigned long long)B28DeviceLogits::avoidedD2HBytes(ls));
    std::printf("B29_NODES=%zu LAYERS_PER_FENCE=%u EXPECTED_SUBMITS=%u\n",
        cp.nodes.size(),cp.layersPerFence,B29LayerChain::expectedSubmits(cp));
    std::printf("B30_SAMPLES=%zu P10_TPS=%.3f MEDIAN_TPS=%.3f EFFECTIVE_MEDIAN=%.3f\n",
        st.samples,st.p10TargetTps,st.medianTargetTps,st.medianEffectiveTps);
    std::printf("B30_P10_BW=%.6f OVERLAP=%.6f P90_SKEW=%.6f P90_SYNC=%.6f CV=%.6f\n",
        st.p10BandwidthFraction,st.medianOverlap,st.p90Skew,
        st.p90HostSyncFraction,st.targetTpsCV);
    std::printf("B30_CERT=%s\n",dec.firstFailure);
    return 0;
}
