#include "rawrxd/src/deep2/Deep2B21QuantPack.hpp"
#include "rawrxd/src/deep2/Deep2B22LdsReuse.hpp"
#include "rawrxd/src/deep2/Deep2B23PersistentQueue.hpp"
#include "rawrxd/src/deep2/Deep2B24SpecDecode.hpp"
#include "rawrxd/src/deep2/Deep2B25Autotune.hpp"
#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* x) { std::printf("FAIL=%s\n",x); return 1; }

int main() {
    QuantPackInput qi{8192,8192,QuantKind::Q4,32,64};
    auto qp=B21QuantPack::make(qi);
    if(!qp.prepackAtLoad || !qp.dequantInRegisters || qp.tileCols<512) return fail("B21");

    LdsReuseInput li{8192,28672,64,65536,56};
    auto lp=B22LdsReuse::make(li);
    if(!lp.cacheX || !lp.doubleBufferWeights || !lp.subgroupReduce) return fail("B22");

    auto pq=B23PersistentQueue::make(61,true,true);
    if(!pq.deviceLoop || pq.hostWakePerToken || pq.templateCommands.empty()) return fail("B23");

    SpecDecodeInput si{};
    si.requestedWidth=6; si.recentAcceptRate=.92; si.draftCostFraction=.18; si.maxSafeWidth=8; si.greedy=true;
    auto sp=B24SpecDecode::make(si);
    if(!sp.enabled || sp.width<6) return fail("B24_PLAN");
    auto vr=B24SpecDecode::verifyGreedy({1,2,3,9},{1,2,3,4});
    if(vr.accepted!=3 || vr.parity) return fail("B24_VERIFY");

    auto cand=B25Autotune::enumerate(8192);
    if(cand.size()<100) return fail("B25_ENUM");

    std::vector<TuneSample> samples;
    TuneSample a{};
    a.candidate=cand[0]; a.tps=48; a.bandwidthFraction=.78; a.overlap=.89;
    a.skew=.04; a.hostSyncFraction=.02; a.reloadBytes=0; a.hostMaterializations=0; a.parity=true;
    TuneSample b=a; b.candidate=cand[1]; b.tps=52; b.bandwidthFraction=.81; b.overlap=.91; b.skew=.03;
    samples.push_back(a); samples.push_back(b);

    TuneGate g{};
    g.minTps=50; g.minBandwidthFraction=.80; g.minOverlap=.90; g.maxSkew=.05;
    auto td=B25Autotune::choose(samples,g);
    if(!td.pass || td.best!=1) return fail("B25_CERT");

    std::printf("DEEP2_BATCH21_25_SELFTEST=PASS\n");
    std::printf("B21_TILE=%ux%u VEC=%u SWIZZLE=%u\n",qp.tileRows,qp.tileCols,qp.vectorBytes,qp.swizzle);
    std::printf("B22_LDS_STAGE=%u GROUPS_PER_CU=%u\n",lp.weightStageBytes,lp.groupsPerCU);
    std::printf("B23_RING=%u COMMANDS=%zu HOST_WAKE_PER_TOKEN=%u\n",pq.ringCapacity,pq.templateCommands.size(),pq.hostWakePerToken?1u:0u);
    std::printf("B24_SPEC_WIDTH=%u VERIFY_ACCEPTED=%u\n",sp.width,vr.accepted);
    std::printf("B25_CANDIDATES=%zu BEST_TPS=%.2f CERT=%s\n",cand.size(),samples[td.best].tps,td.firstFailure);
    return 0;
}
