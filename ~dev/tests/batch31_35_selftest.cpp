#include "rawrxd/src/deep2/Deep2B31QuantSuperkernel.hpp"
#include "rawrxd/src/deep2/Deep2B32FlashMLA.hpp"
#include "rawrxd/src/deep2/Deep2B33ExpertStriping.hpp"
#include "rawrxd/src/deep2/Deep2B34FusedKvAttention.hpp"
#include "rawrxd/src/deep2/Deep2B35DeviceTokenHandoff.hpp"

#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* x) {
    std::printf("FAIL=%s\n", x);
    return 1;
}

int main() {
    B31QuantShape qs{16384,8192,B31QuantType::Q4_K,32,64};
    auto qp=B31QuantSuperkernel::make(qs);
    if(!qp.fusedScaleDecode || !qp.registerDequant || !qp.subgroupReduce ||
       !qp.prepackedLayout || qp.blocksPerPrefetch<4)
        return fail("B31");

    B32FlashMlaShape ms{};
    ms.context=65536; ms.heads=64; ms.kvLoraRank=512;
    ms.qkNopeDim=128; ms.qkRopeDim=64; ms.vDim=128; ms.scalarBytes=2;
    auto mp=B32FlashMLA::make(ms);
    if(!mp.onlineSoftmax || !mp.noScoreMatrix || !mp.compressedKvResident ||
       !mp.fusedScoreValue)
        return fail("B32");

    std::vector<B33ExpertDesc> ex;
    for(uint32_t i=0;i<16;++i)
        ex.push_back({i, 192ull<<20, double(8000+i*100), i<8});
    B33DeviceRate d0{0.64, 24ull<<30};
    B33DeviceRate d1{0.624, 12ull<<30};
    auto sp=B33ExpertStriping::make(ex,d0,d1);
    if(sp.placement.size()!=16 || !sp.stableOwnership || sp.peerCopyOnHit)
        return fail("B33");

    B34KvAttnShape ks{};
    ks.context=32768; ks.heads=64; ks.kvHeads=8; ks.headDim=128;
    ks.scalarBytes=2; ks.useMLA=true; ks.compressedRank=512;
    auto kp=B34FusedKvAttention::make(ks);
    if(!kp.fuseKvWrite || !kp.fuseAttentionRead || !kp.noHostKvTouch ||
       !kp.noIntermediateScoreBuffer)
        return fail("B34");

    auto hp=B35DeviceTokenHandoff::make(1.0,0.94);
    if(hp.hostPoll || hp.hostTokenCopy || !hp.deviceSemaphore ||
       !hp.keepNextEmbedOnDevice || hp.producerDevice!=0)
        return fail("B35_PLAN");

    std::vector<B35Sample> samples;
    for(int i=0;i<112;++i) {
        B35Sample s{};
        double wiggle = double((i%9)-4) * 0.15;
        s.targetTps = 58.0 + wiggle;
        s.bandwidthFraction = 0.875 + double(i%5)*0.002;
        s.overlap = 0.935 + double(i%4)*0.002;
        s.skew = 0.025 + double(i%5)*0.0015;
        s.hostSyncFraction = 0.009 + double(i%4)*0.001;
        s.hostTokenCopies=0;
        s.hostMaterializations=0;
        s.reloadBytes=0;
        s.gpu0Forwards=61;
        s.gpu1Forwards=61;
        s.parity=true;
        s.stable=true;
        samples.push_back(s);
    }

    auto st=B35DeviceTokenHandoff::summarize(samples);
    B35Gate g{};
    g.minSamples=96;
    g.minP10Tps=56.0;
    g.minMedianTps=57.0;
    g.minP10Bandwidth=.85;
    g.minMedianOverlap=.92;
    g.maxP90Skew=.04;
    g.maxP90HostSync=.02;
    auto dec=B35DeviceTokenHandoff::certify(st,g);
    if(!dec.pass) return fail(dec.firstFailure);

    std::printf("DEEP2_BATCH31_35_SELFTEST=PASS\n");
    std::printf("B31_WG=%u ROWS_PER_GROUP=%u PREFETCH=%u WEIGHT_BYTES=%llu\n",
        qp.workgroup, qp.rowsPerGroup, qp.blocksPerPrefetch,
        (unsigned long long)B31QuantSuperkernel::estimatedWeightBytes(qs));
    std::printf("B32_TILE=%u HEADS_PER_GROUP=%u AVOID_SCORE_BYTES=%llu KV_READ_BYTES=%llu\n",
        mp.tokenTile, mp.headsPerGroup,
        (unsigned long long)B32FlashMLA::avoidedScoreBytes(ms),
        (unsigned long long)B32FlashMLA::compressedKvReadBytes(ms));
    std::printf("B33_EXPERTS=%u/%u BYTES=%llu/%llu\n",
        sp.gpu0Experts,sp.gpu1Experts,
        (unsigned long long)sp.gpu0Bytes,
        (unsigned long long)sp.gpu1Bytes);
    std::printf("B34_TILE=%u HEADS_PER_GROUP=%u AVOID_KV_BYTES=%llu\n",
        kp.tokenTile,kp.headsPerGroup,
        (unsigned long long)B34FusedKvAttention::avoidedKvRoundtripBytes(ks));
    std::printf("B35_SAMPLES=%zu P10_TPS=%.3f MEDIAN_TPS=%.3f P10_BW=%.6f OVERLAP=%.6f P90_SKEW=%.6f P90_SYNC=%.6f\n",
        st.samples,st.p10Tps,st.medianTps,st.p10Bandwidth,
        st.medianOverlap,st.p90Skew,st.p90HostSync);
    std::printf("B35_CERT=%s\n",dec.firstFailure);
    return 0;
}
