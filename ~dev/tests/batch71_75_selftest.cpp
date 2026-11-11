#include "rawrxd/src/deep2/Deep2B71_75Authority.hpp"
#include <cstdio>
#include <vector>
#include <fstream>

using namespace Deep2;

struct MockCounters {
    uint64_t forwardLayers=0;
    uint64_t forwardSlot[8]{};
    uint64_t hostSyncBoundaries=0;
    uint64_t hostMaterializations=0;
    uint64_t ownershipTransfers=0;
    uint64_t intraSlotHostTransfers=0;
    uint64_t liveDecodeResidentTokens=0;
    uint64_t liveDecodeTokens=0;
    uint64_t hostForwardLayerCalls=0;
    uint64_t plannedCpuLayerCalls=0;
    uint64_t gpuLayersLastToken=0;
    uint64_t layerSubmits=0;
    uint64_t opSubmits=0;
    uint64_t q4kPackedOps=0;
    uint64_t q6kPackedOps=0;
    uint64_t q2kPackedOps=0;
    uint64_t cpuF32Expands=0;
};

static int fail(const char* x){std::printf("FAIL=%s\n",x);return 1;}

static std::string receipt(double p10,double med) {
    char b[4096];
    std::snprintf(b,sizeof(b),
        "DEEP2_LIVE_CONTRACT_RECEIPT=1\n"
        "MODEL_ARCH=qwen3next\n"
        "CONTRACT=test\n"
        "SAMPLES=384\n"
        "P10_TPS=%.6f\n"
        "MEDIAN_TPS=%.6f\n"
        "PHYSICAL_ROOFLINE_TPS=55.000000\n"
        "GPU0_FORWARDS=18432\n"
        "GPU1_FORWARDS=17664\n"
        "RELOAD_BYTES=0\n"
        "HOST_MATERIALIZATIONS=0\n"
        "HOST_TOKEN_COPIES=0\n"
        "PEER_COPY_BYTES=0\n"
        "PARITY_ALL=1\n"
        "OUTPUT_STABLE_ALL=1\n"
        "CERT=PASS\n"
        "FAILURE=PASS\n",p10,med);
    return b;
}

int main() {
    MockCounters a{},b{};
    a.forwardSlot[0]=100;a.forwardSlot[1]=80;
    a.liveDecodeResidentTokens=10;
    b=a;
    b.forwardLayers+=96;
    b.forwardSlot[0]+=48;b.forwardSlot[1]+=48;
    b.liveDecodeResidentTokens+=1;
    b.liveDecodeTokens+=1;
    b.layerSubmits+=96;b.opSubmits+=400;b.q4kPackedOps+=20;
    auto sa=B71GpuCounterAdapter::capture(a);
    auto sb=B71GpuCounterAdapter::capture(b);
    auto d=B71GpuCounterAdapter::delta(sa,sb);
    if(!d.bothGpusLive||!d.residentForward||d.gpu0Forwards!=48||d.gpu1Forwards!=48)
        return fail("B71");

    auto opt=B72RawrBenchCli::parse({
        "rawr","bench","qwen3-next:80b","--contract","qwen3-next-short",
        "--tokens","384","--warmup","32","--json"});
    if(!opt.valid||!opt.useContract||opt.tokens!=384||!opt.json)
        return fail("B72");

    const std::string r0=receipt(45.2,47.0);
    auto stored=B73EvidenceStore::writeAtomic("build/evidence","authority_test",r0);
    if(!stored.pass) return fail(stored.failure);

    std::string reread;
    if(!B73EvidenceStore::readAll(stored.receiptPath,reread)||reread!=r0)
        return fail("B73_READ");

    auto replay0=B74ReceiptReplay::parseAndVerify(reread,stored.sha256);
    if(!replay0.pass) return fail(replay0.failure);

    const std::string r1=receipt(45.4,47.5);
    const std::string h1=NoDepSha256::hash(r1);
    auto replay1=B74ReceiptReplay::parseAndVerify(r1,h1);
    if(!replay1.pass) return fail(replay1.failure);

    auto reg=B74ReceiptReplay::compare(replay0,replay1,3.0,5.0);
    if(!reg.pass) return fail(reg.failure);

    std::vector<B75FleetItem> fleet={
        {"qwen3-next",true,replay1},
        {"nemotron",true,replay1},
        {"gpt-oss-120b",true,replay1},
        {"laguna",true,replay1},
        {"deepseek-v4-flash",true,replay1}
    };
    auto promotion=B75FleetPromotion::evaluate(fleet);
    if(!promotion.pass||promotion.passed!=5)
        return fail(promotion.failure);

    std::printf("DEEP2_BATCH71_75_SELFTEST=PASS\n");
    std::printf("B71_GPU_FORWARDS=%llu/%llu RESIDENT=%u\n",
        (unsigned long long)d.gpu0Forwards,(unsigned long long)d.gpu1Forwards,
        d.residentForward?1u:0u);
    std::printf("B72_MODEL=%s TOKENS=%u WARMUP=%u CONTRACT=%s\n",
        opt.model.c_str(),opt.tokens,opt.warmupTokens,opt.contractName.c_str());
    std::printf("B73_SHA256=%s ATOMIC_WRITE=PASS\n",stored.sha256.c_str());
    std::printf("B74_MEDIAN_DELTA_PCT=%.6f P10_DELTA_PCT=%.6f REPLAY=PASS\n",
        reg.medianTpsDeltaPct,reg.p10TpsDeltaPct);
    std::printf("B75_FLEET=%zu/%zu PROMOTION=%s\n",
        promotion.passed,promotion.required,promotion.failure);
    return 0;
}
