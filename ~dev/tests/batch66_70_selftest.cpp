#include "rawrxd/src/deep2/Deep2B66RuntimeMeta.hpp"
#include "rawrxd/src/deep2/Deep2B67LiveTelemetry.hpp"
#include "rawrxd/src/deep2/Deep2B68TargetCalibrator.hpp"
#include "rawrxd/src/deep2/Deep2B69ContractRunner.hpp"
#include "rawrxd/src/deep2/Deep2B70Receipt.hpp"
#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* x){std::printf("FAIL=%s\n",x);return 1;}

int main() {
    B66MetadataSource src{};
    src.str["general.architecture"]="qwen3next";
    src.f64["deep2.total_params_b"]=80.0;
    src.f64["deep2.active_params_b"]=3.0;
    src.u64["block_count"]=48;
    src.u64["embedding_length"]=2048;
    src.u64["attention.head_count"]=16;
    src.u64["attention.head_count_kv"]=2;
    src.u64["attention.key_length"]=256;
    src.u64["feed_forward_length"]=8192;
    src.u64["expert_count"]=512;
    src.u64["expert_used_count"]=10;
    src.u64["expert_shared_count"]=1;
    src.u64["context_length"]=262144;
    src.u64["attention.linear_layer_count"]=36;

    auto meta=B66RuntimeMetaBinder::bind(src);
    if(!meta.pass || meta.meta.layers!=48 || !meta.meta.useHybridLinearAttention)
        return fail("B66");

    std::vector<B67TokenTelemetry> samples;
    for(uint64_t i=0;i<352;++i) {
        B67TokenTelemetry t{};
        double tps=47.0 + double(int(i%11)-5)*0.03;
        t.wallNs=uint64_t(1e9/tps);
        t.gpu0Ns=uint64_t(double(t.wallNs)*.93);
        t.gpu1Ns=uint64_t(double(t.wallNs)*.91);
        t.overlapNs=uint64_t(double(t.wallNs)*.88);
        t.hostSyncNs=uint64_t(double(t.wallNs)*.006);
        t.queueIdleNs=uint64_t(double(t.wallNs)*.010);
        t.bytesRead=uint64_t(21.0e9);
        t.bytesWritten=uint64_t(.30e9);
        t.flops=.55e12;
        t.gpu0Forwards=48;
        t.gpu1Forwards=48;
        t.parity=true;
        t.stableOutput=true;
        samples.push_back(t);
    }

    auto d=B67LiveTelemetry::derive(samples.front());
    if(d.rawTps<40.0 || d.overlapFraction<.8)
        return fail("B67");

    B68Hardware hw{1264.0,50.0};
    B68WorkModel work{24.0e9,.75e12};
    auto cal=B68TargetCalibrator::calibrate(hw,work,samples,.95,1.03);
    if(!cal.pass || cal.physicalRooflineTps<=0.0)
        return fail("B68");

    B69Contract c{};
    c.name="qwen3-next-80b-a3b-q4-short";
    c.minSamples=320;
    c.minP10Tps=45.0;
    c.minMedianTps=46.0;
    c.minP10RooflineFraction=.80;
    c.minMedianOverlap=.90;
    c.maxP90Skew=.05;
    c.maxP90HostSync=.02;
    c.maxP90QueueIdle=.03;

    auto r=B69ContractRunner::run(c,cal,samples);
    if(!r.pass) return fail(r.failure);

    auto receipt=B70ReceiptWriter::make(meta.meta,cal,c,r);
    if(!B70ReceiptWriter::verify(receipt))
        return fail("B70_VERIFY");

    auto tampered=receipt;
    tampered.canonicalText+="TAMPER=1\n";
    if(B70ReceiptWriter::verify(tampered))
        return fail("B70_TAMPER");

    std::printf("DEEP2_BATCH66_70_SELFTEST=PASS\n");
    std::printf("B66_ARCH=%s LAYERS=%u HIDDEN=%u EXPERTS=%u TOPK=%u\n",
        meta.meta.architecture.c_str(),meta.meta.layers,meta.meta.hidden,
        meta.meta.experts,meta.meta.expertsPerToken);
    std::printf("B67_TPS=%.3f BW_GBS=%.3f COMPUTE_TFLOPS=%.3f OVERLAP=%.6f\n",
        d.rawTps,d.measuredBandwidthGBs,d.measuredComputeTFLOPs,d.overlapFraction);
    std::printf("B68_MEMORY_ROOF=%.3f COMPUTE_ROOF=%.3f PHYSICAL_ROOF=%.3f SAFE_P10=%.3f SAFE_MEDIAN=%.3f\n",
        cal.memoryRooflineTps,cal.computeRooflineTps,cal.physicalRooflineTps,
        cal.safeP10Target,cal.safeMedianTarget);
    std::printf("B69_P10=%.3f MEDIAN=%.3f ROOF_FRAC=%.6f CERT=%s\n",
        r.stats.p10Tps,r.stats.medianTps,r.stats.p10RooflineFraction,r.failure);
    std::printf("B70_SHA256=%s VERIFY=PASS TAMPER_REJECT=PASS\n",receipt.sha256Hex.c_str());
    return 0;
}
