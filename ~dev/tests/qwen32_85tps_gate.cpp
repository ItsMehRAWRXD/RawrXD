#include "deep2/Deep2Engine.h"
#include "deep2/Deep2Speculative.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace Deep2;

static bool setup(Deep2Engine& e,const char* model,bool spec) {
    EngineConfig c{};
    c.maxSeqLen=4096;
    if(!e.initialize(c)||!e.loadModel(model)) return false;
    const auto& g=e.getConfig();
    if(g.numLayers!=64||g.hiddenDim!=5120||
       g.numHeads!=40||g.numKVHeads!=8)
        return false;
    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);
    if(!e.isVulkanInitialized()||e.vulkanDeviceCount()<2) return false;
    GenerationOptions o{};
    o.temperature=0.0f;o.topK=1;o.topP=1.0f;o.seed=1;
    e.configureGeneration(o);
    e.enableVerifiedSpeculation(spec,4);
    return true;
}

static std::vector<int> run(
    Deep2Engine& e,const std::string& prompt,size_t n,InferenceStats& s)
{
    auto p=e.tokenize(prompt);
    std::vector<int> out(n);
    const size_t got=e.generate(
        p.data(),p.size(),out.data(),out.size(),&s);
    out.resize(got);
    return out;
}

int main(int argc,char** argv) {
    if(argc<2) {
        std::fprintf(stderr,"usage: qwen32_85tps_gate model.gguf [tokens]\n");
        return 2;
    }
    const char* model=argv[1];
    size_t measure=256;
    if(argc>2) {
        long v=std::strtol(argv[2],nullptr,10);
        if(v>=128&&v<=2048) measure=(size_t)v;
    }
    const std::string prompt=
        "Implement a high performance C++ lock free queue and explain "
        "the memory ordering guarantees in detail. ";

    // Exact parity witness on a bounded sequence.
    Deep2Engine ordinary;
    if(!setup(ordinary,model,false)) {
        std::fprintf(stderr,"DEEP2_QWEN25_32B_REAL_85TPS_001=HOLD setup_base\n");
        return 10;
    }
    InferenceStats bs{};
    auto base=run(ordinary,prompt,16,bs);
    if(base.size()!=16) return 11;

    Deep2Engine spec;
    if(!setup(spec,model,true)) {
        std::fprintf(stderr,"DEEP2_QWEN25_32B_REAL_85TPS_001=HOLD setup_spec\n");
        return 12;
    }
    InferenceStats ps{};
    auto probe=run(spec,prompt,16,ps);
    const bool parity=probe==base;
    if(!parity) {
        std::fprintf(stderr,
            "SPEC_GREEDY_PARITY=FAIL\n"
            "DEEP2_QWEN25_32B_REAL_85TPS_001=HOLD\n");
        return 13;
    }

    // Warm resident/speculative structures. Not part of measured authority.
    spec.reset();
    spec.enableVerifiedSpeculation(true,4);
    InferenceStats warmStats{};
    (void)run(spec,prompt,32,warmStats);
    const uint64_t up0Warm=spec.vulkanSlotWeightUploads(0);
    const uint64_t up1Warm=spec.vulkanSlotWeightUploads(1);
    const uint64_t in0Warm=spec.vulkanSlotResidentBatchInputUploads(0);
    const uint64_t in1Warm=spec.vulkanSlotResidentBatchInputUploads(1);
    const uint64_t q0Warm=spec.vulkanSlotQueueSubmits(0);
    const uint64_t q1Warm=spec.vulkanSlotQueueSubmits(1);
    const uint64_t re0Warm=spec.vulkanSlotResidentGroupOutputReallocs(0);
    const uint64_t re1Warm=spec.vulkanSlotResidentGroupOutputReallocs(1);
    const uint64_t kvdWarm=spec.vulkanSlotDirectSpecKvAppends(0);
    const uint64_t impWarm=spec.vulkanSlotSecondaryImportBytes(0);
    const uint64_t bndWarm=spec.vulkanSlotFullOutputBoundaryBytes(0);
    const uint64_t asmWarm=spec.vulkanSlotResidentFullOutputCopies(0);
    const uint64_t graphWarm=spec.vulkanSlotSpecLayerGraphSubmits(0);
    const uint64_t kb0Warm=spec.vulkanSlotQ4KBatchWeightBytes(0);
    const uint64_t kb1Warm=spec.vulkanSlotQ4KBatchWeightBytes(1);
    const uint64_t kn0Warm=spec.vulkanSlotQ4KBatchGpuNs(0);
    const uint64_t kn1Warm=spec.vulkanSlotQ4KBatchGpuNs(1);
    const uint64_t ko0Warm=spec.vulkanSlotQ4KBatch4RowOps(0);
    const uint64_t ko1Warm=spec.vulkanSlotQ4KBatch4RowOps(1);
    const uint64_t flipWarm=spec.vulkanSlotSpecArenaFlips(0);
    const uint64_t at0Warm=spec.vulkanSlotQ4KAutotuneRuns(0);
    const uint64_t at1Warm=spec.vulkanSlotQ4KAutotuneRuns(1);
    const uint64_t rc0Warm=spec.vulkanSlotRecordedQ4KSubmits(0);
    const uint64_t rc1Warm=spec.vulkanSlotRecordedQ4KSubmits(1);
    const uint64_t rcb0Warm=spec.vulkanSlotRecordedQ4KBuilds(0);
    const uint64_t rcb1Warm=spec.vulkanSlotRecordedQ4KBuilds(1);
    const uint64_t k8o0Warm=spec.vulkanSlotQ4KBatch8RowOps(0);
    const uint64_t k8o1Warm=spec.vulkanSlotQ4KBatch8RowOps(1);
    const uint64_t as0Warm=spec.vulkanSlotQ4KAsyncSubmits(0);
    const uint64_t as1Warm=spec.vulkanSlotQ4KAsyncSubmits(1);
    const uint64_t aw0Warm=spec.vulkanSlotQ4KAsyncWaitNs(0);
    const uint64_t aw1Warm=spec.vulkanSlotQ4KAsyncWaitNs(1);
    const uint64_t drWarm=spec.vulkanSlotDownloadRingSubmits(1);
    const uint64_t dwWarm=spec.vulkanSlotDownloadRingWaitNs(1);
    const bool dtq0=spec.vulkanSlotHasDedicatedTransferQueue(0);
    const bool dtq1=spec.vulkanSlotHasDedicatedTransferQueue(1);
    const uint32_t cqf0=spec.vulkanSlotComputeQueueFamily(0);
    const uint32_t cqf1=spec.vulkanSlotComputeQueueFamily(1);
    const uint32_t tqf0=spec.vulkanSlotTransferQueueFamily(0);
    const uint32_t tqf1=spec.vulkanSlotTransferQueueFamily(1);
    const uint64_t tq0Warm=spec.vulkanSlotTransferQueueSubmits(0);
    const uint64_t tq1Warm=spec.vulkanSlotTransferQueueSubmits(1);
    const bool tl0=spec.vulkanSlotTimelineSemaphoreEnabled(0);
    const bool tl1=spec.vulkanSlotTimelineSemaphoreEnabled(1);
    const uint64_t tls0Warm=spec.vulkanSlotTimelineSignals(0);
    const uint64_t tls1Warm=spec.vulkanSlotTimelineSignals(1);
    const uint64_t tlw0Warm=spec.vulkanSlotTimelineWaits(0);
    const uint64_t tlw1Warm=spec.vulkanSlotTimelineWaits(1);
    const uint64_t tlc0Warm=spec.vulkanSlotTimelineComputeTransferChains(0);
    const uint64_t tlc1Warm=spec.vulkanSlotTimelineComputeTransferChains(1);
    const uint64_t acr0Warm=spec.vulkanSlotAsyncCmdRingReuses(0);
    const uint64_t acr1Warm=spec.vulkanSlotAsyncCmdRingReuses(1);
    const uint64_t rgb0Warm=spec.vulkanSlotRecordedGroupBuilds(0);
    const uint64_t rgb1Warm=spec.vulkanSlotRecordedGroupBuilds(1);
    const uint64_t rgs0Warm=spec.vulkanSlotRecordedGroupSubmits(0);
    const uint64_t rgs1Warm=spec.vulkanSlotRecordedGroupSubmits(1);
    const uint64_t acWarm=spec.vulkanSlotSpecAcceptGpuOps(0);
    const uint64_t vhWarm=spec.vulkanSlotVerifiedHiddenHandoffs(0);
    const uint64_t lgWarm=spec.vulkanSlotLayerTimelineChains(0);
    const uint64_t rga0Warm=spec.vulkanSlotRecordedGroupAsyncSubmits(0);
    const uint64_t rga1Warm=spec.vulkanSlotRecordedGroupAsyncSubmits(1);
    const uint64_t rgw0Warm=spec.vulkanSlotRecordedGroupSyncWaits(0);
    const uint64_t rgw1Warm=spec.vulkanSlotRecordedGroupSyncWaits(1);
    const uint64_t sarWarm=spec.vulkanSlotSpecAcceptResidentOps(0);
    const uint64_t sauWarm=spec.vulkanSlotSpecAcceptInputUploadBytes(0);
    const uint64_t htsWarm=spec.vulkanSlotHiddenTimelineSubmits(0);

    double tpsRun[3]={0.0,0.0,0.0};
    SpeculativeCounters runCounters[3]{};
    bool runEnough[3]={false,false,false};
    for(int r=0;r<3;++r) {
        spec.reset();
        spec.enableVerifiedSpeculation(true,4);
        InferenceStats ms{};
        auto measured=run(spec,prompt,measure,ms);
        runCounters[r]=spec.speculativeCounters();
        runEnough[r]=measured.size()>=measure;
        tpsRun[r]=ms.decodeMs>0.0
            ? (double)measured.size()/(ms.decodeMs*0.001):0.0;
    }
    const uint64_t up0End=spec.vulkanSlotWeightUploads(0);
    const uint64_t up1End=spec.vulkanSlotWeightUploads(1);
    const uint64_t in0End=spec.vulkanSlotResidentBatchInputUploads(0);
    const uint64_t in1End=spec.vulkanSlotResidentBatchInputUploads(1);
    const uint64_t q0End=spec.vulkanSlotQueueSubmits(0);
    const uint64_t q1End=spec.vulkanSlotQueueSubmits(1);
    const uint64_t re0End=spec.vulkanSlotResidentGroupOutputReallocs(0);
    const uint64_t re1End=spec.vulkanSlotResidentGroupOutputReallocs(1);
    const uint64_t kvdEnd=spec.vulkanSlotDirectSpecKvAppends(0);
    const uint64_t impEnd=spec.vulkanSlotSecondaryImportBytes(0);
    const uint64_t bndEnd=spec.vulkanSlotFullOutputBoundaryBytes(0);
    const uint64_t asmEnd=spec.vulkanSlotResidentFullOutputCopies(0);
    const uint64_t graphEnd=spec.vulkanSlotSpecLayerGraphSubmits(0);
    const uint64_t kb0End=spec.vulkanSlotQ4KBatchWeightBytes(0);
    const uint64_t kb1End=spec.vulkanSlotQ4KBatchWeightBytes(1);
    const uint64_t kn0End=spec.vulkanSlotQ4KBatchGpuNs(0);
    const uint64_t kn1End=spec.vulkanSlotQ4KBatchGpuNs(1);
    const uint64_t ko0End=spec.vulkanSlotQ4KBatch4RowOps(0);
    const uint64_t ko1End=spec.vulkanSlotQ4KBatch4RowOps(1);
    const uint64_t flipEnd=spec.vulkanSlotSpecArenaFlips(0);
    const uint64_t at0End=spec.vulkanSlotQ4KAutotuneRuns(0);
    const uint64_t at1End=spec.vulkanSlotQ4KAutotuneRuns(1);
    const uint64_t rc0End=spec.vulkanSlotRecordedQ4KSubmits(0);
    const uint64_t rc1End=spec.vulkanSlotRecordedQ4KSubmits(1);
    const uint64_t rcb0End=spec.vulkanSlotRecordedQ4KBuilds(0);
    const uint64_t rcb1End=spec.vulkanSlotRecordedQ4KBuilds(1);
    const uint64_t k8o0End=spec.vulkanSlotQ4KBatch8RowOps(0);
    const uint64_t k8o1End=spec.vulkanSlotQ4KBatch8RowOps(1);
    const uint64_t as0End=spec.vulkanSlotQ4KAsyncSubmits(0);
    const uint64_t as1End=spec.vulkanSlotQ4KAsyncSubmits(1);
    const uint64_t aw0End=spec.vulkanSlotQ4KAsyncWaitNs(0);
    const uint64_t aw1End=spec.vulkanSlotQ4KAsyncWaitNs(1);
    const uint64_t drEnd=spec.vulkanSlotDownloadRingSubmits(1);
    const uint64_t dwEnd=spec.vulkanSlotDownloadRingWaitNs(1);
    const uint64_t tq0End=spec.vulkanSlotTransferQueueSubmits(0);
    const uint64_t tq1End=spec.vulkanSlotTransferQueueSubmits(1);
    const uint64_t tls0End=spec.vulkanSlotTimelineSignals(0);
    const uint64_t tls1End=spec.vulkanSlotTimelineSignals(1);
    const uint64_t tlw0End=spec.vulkanSlotTimelineWaits(0);
    const uint64_t tlw1End=spec.vulkanSlotTimelineWaits(1);
    const uint64_t tlc0End=spec.vulkanSlotTimelineComputeTransferChains(0);
    const uint64_t tlc1End=spec.vulkanSlotTimelineComputeTransferChains(1);
    const uint64_t acr0End=spec.vulkanSlotAsyncCmdRingReuses(0);
    const uint64_t acr1End=spec.vulkanSlotAsyncCmdRingReuses(1);
    const uint64_t rgb0End=spec.vulkanSlotRecordedGroupBuilds(0);
    const uint64_t rgb1End=spec.vulkanSlotRecordedGroupBuilds(1);
    const uint64_t rgs0End=spec.vulkanSlotRecordedGroupSubmits(0);
    const uint64_t rgs1End=spec.vulkanSlotRecordedGroupSubmits(1);
    const uint64_t acEnd=spec.vulkanSlotSpecAcceptGpuOps(0);
    const uint64_t vhEnd=spec.vulkanSlotVerifiedHiddenHandoffs(0);
    const uint64_t lgEnd=spec.vulkanSlotLayerTimelineChains(0);
    const uint64_t rga0End=spec.vulkanSlotRecordedGroupAsyncSubmits(0);
    const uint64_t rga1End=spec.vulkanSlotRecordedGroupAsyncSubmits(1);
    const uint64_t rgw0End=spec.vulkanSlotRecordedGroupSyncWaits(0);
    const uint64_t rgw1End=spec.vulkanSlotRecordedGroupSyncWaits(1);
    const uint64_t sarEnd=spec.vulkanSlotSpecAcceptResidentOps(0);
    const uint64_t sauEnd=spec.vulkanSlotSpecAcceptInputUploadBytes(0);
    const uint64_t htsEnd=spec.vulkanSlotHiddenTimelineSubmits(0);
    const uint64_t pin0=spec.vulkanSlotPinnedWeightEntries(0);
    const uint64_t pin1=spec.vulkanSlotPinnedWeightEntries(1);
    const uint64_t pinBytes0=spec.vulkanSlotPinnedWeightBytes(0);
    const uint64_t pinBytes1=spec.vulkanSlotPinnedWeightBytes(1);
    const bool zeroMeasuredUploads=
        up0End==up0Warm && up1End==up1Warm;
    const bool pinned=pin0>0&&pin1>0&&pinBytes0>0&&pinBytes1>0;
    const uint64_t measuredVerified=
        runCounters[0].verifiedOutputTokens+
        runCounters[1].verifiedOutputTokens+
        runCounters[2].verifiedOutputTokens;
    const double submitPerToken=measuredVerified
        ? (double)((q0End-q0Warm)+(q1End-q1Warm))/
          (double)measuredVerified : 1.0e30;
    const double inputUploadsPerToken=measuredVerified
        ? (double)((in0End-in0Warm)+(in1End-in1Warm))/
          (double)measuredVerified : 1.0e30;
    const bool stableGroupArena=
        re0End==re0Warm&&re1End==re1Warm;
    const bool hotpathBounded=
        submitPerToken<400.0 &&
        inputUploadsPerToken<150.0 &&
        stableGroupArena;
    const uint64_t hostBytes=(impEnd-impWarm)+(bndEnd-bndWarm);
    const double hostBytesPerToken=measuredVerified
        ? (double)hostBytes/(double)measuredVerified : 1.0e30;
    const bool residentAssembly=(asmEnd>asmWarm);
    const bool fusedGraphs=(graphEnd>graphWarm);
    // This is intentionally a generous bound. It catches regressions back to
    // full-weight or repeated full-activation materialization without
    // pretending host traffic can already be zero on non-peer Vulkan devices.
    const bool hostTrafficBounded=hostBytesPerToken < 64.0*1024.0*1024.0;
    const uint64_t b0=kb0End-kb0Warm;
    const uint64_t b1=kb1End-kb1Warm;
    const uint64_t n0=kn0End-kn0Warm;
    const uint64_t n1=kn1End-kn1Warm;
    const double gbps0=n0
        ? ((double)b0/1.0e9)/((double)n0/1.0e9) : 0.0;
    const double gbps1=n1
        ? ((double)b1/1.0e9)/((double)n1/1.0e9) : 0.0;
    const bool tiledKernel=
        ko0End>ko0Warm && ko1End>ko1Warm;
    const bool pingpong=flipEnd>flipWarm;
    const bool autotuned=
        at0End>at0Warm && at1End>at1Warm;
    const bool recordedHot=
        rc0End>rc0Warm && rc1End>rc1Warm;
    const auto& sc=runCounters[2];
    const bool costController=
        sc.costControllerSelections>0 &&
        sc.windowAttempts[2]>0 &&
        sc.windowAttempts[3]>0 &&
        sc.windowAttempts[4]>0;
    const bool asyncBoth=
        as0End>as0Warm && as1End>as1Warm;
    const bool ringLive=drEnd>drWarm;
    const uint64_t asyncWaitNs=
        (aw0End-aw0Warm)+(aw1End-aw1Warm);
    const uint64_t ringWaitNs=dwEnd-dwWarm;
    const bool asyncOverlapPath=
        asyncBoth && ringLive &&
        asyncWaitNs>0;
    const bool transferQueueUsed=
        (!dtq0 || tq0End>tq0Warm) &&
        (!dtq1 || tq1End>tq1Warm);
    const bool threeStage=
        sc.pipelinePrepareWindows>0 &&
        sc.pipelineVerifyWindows>0 &&
        sc.pipelineCommitWindows>0;
    const bool timelineUsed=
        (!tl0 || tlc0End>tlc0Warm) &&
        (!tl1 || tlc1End>tlc1Warm);
    const bool cmdRingLive=
        acr0End>acr0Warm && acr1End>acr1Warm;
    const bool recordedGroups=
        rgs0End>rgs0Warm && rgs1End>rgs1Warm;
    const bool gpuAccept=acEnd>acWarm;
    const bool hiddenHandoff=vhEnd>vhWarm;
    const bool layerTimeline=
        !tl0 || lgEnd>lgWarm;
    const bool recordedWaitFree=
        (!tl0 || rga0End>rga0Warm) &&
        (!tl1 || rga1End>rga1Warm) &&
        (rgw0End-rgw0Warm)==0 &&
        (rgw1End-rgw1Warm)==0;
    const bool residentAccept=
        sarEnd>sarWarm && (sauEnd-sauWarm)==0;
    const bool hiddenTimeline=
        !tl0 || htsEnd>htsWarm;
    const bool realWindowAmortization=
        sc.verifiedTargetWindows>0 &&
        sc.acceptedVerifiedTokens>sc.verifiedTargetWindows;
    const double tpsMin=std::min(tpsRun[0],
                         std::min(tpsRun[1],tpsRun[2]));
    double sorted[3]={tpsRun[0],tpsRun[1],tpsRun[2]};
    std::sort(sorted,sorted+3);
    const double tpsMedian=sorted[1];

    const bool enough=runEnough[0]&&runEnough[1]&&runEnough[2];
    const bool gpu=spec.vulkanDeviceCount()>=2 &&
                   !spec.vulkanStrictViolation() &&
                   spec.vulkanUnplannedFallbacks()==0;
    const bool gpu1Ready=spec.vulkanDeviceCount()>=2;
    const bool amortized=sc.targetPasses>0 &&
                         sc.verifiedPerTargetPass()>1.0;
    const bool top1Gpu=sc.gpuTop1Batches>0;
    const bool realDraft=sc.selfDraftWindows>0||sc.ngramDraftWindows>0;
    const bool batch4Gpu=
        sc.gpuBatchNormOps>0 &&
        sc.gpuBatchSwiGLUOps>0 &&
        sc.gpuBatchAttentionOps>0 &&
        sc.dualColumnSplitOps>0;
    const bool persistentKv=
        sc.kvMirrorResidentAttn>0 &&
        sc.kvMirrorDeltaTokens>0;
    const bool all85=tpsRun[0]>=85.0&&tpsRun[1]>=85.0&&tpsRun[2]>=85.0;
    const bool pipeline=sc.pipelineWindows>0&&sc.targetBatchNs>0;
    const bool pass=parity&&enough&&gpu&&amortized&&top1Gpu&&realDraft&&
                    batch4Gpu&&persistentKv&&gpu1Ready&&pipeline&&all85&&
                    zeroMeasuredUploads&&pinned&&hotpathBounded&&
                    residentAssembly&&fusedGraphs&&hostTrafficBounded&&
                    tiledKernel&&pingpong&&autotuned&&recordedHot&&
                    costController&&asyncOverlapPath&&transferQueueUsed&&
                    threeStage&&timelineUsed&&cmdRingLive&&recordedGroups&&
                    gpuAccept&&hiddenHandoff&&layerTimeline&&
                    recordedWaitFree&&residentAccept&&hiddenTimeline&&
                    realWindowAmortization;

    SpeculativeRoofline roof{};
    Emit85TpsRoofline(stderr,roof,sc,tpsMedian,4);
    std::fprintf(stderr,
        "SPEC_GREEDY_PARITY=%s\n"
        "GPU_DEVICES=%u\n"
        "GPU1_DEVICE_READY=%u\n"
        "STRICT_VIOLATION=%u\n"
        "UNPLANNED_FALLBACKS=%llu\n"
        "SELF_DRAFT_WINDOWS=%llu\n"
        "NGRAM_DRAFT_WINDOWS=%llu\n"
        "GPU_TOP1_BATCHES=%llu\n"
        "ACCEPTANCE_EWMA=%.6f\n"
        "GPU_BATCH_NORM_OPS=%llu\n"
        "GPU_BATCH_SWIGLU_OPS=%llu\n"
        "GPU_BATCH_ATTENTION_OPS=%llu\n"
        "DUAL_COLUMN_SPLIT_OPS=%llu\n"
        "BATCH4_GPU_STRUCTURES=%s\n"
        "KV_MIRROR_PERSISTENT=%s\n"
        "PIPELINE_WINDOWS=%llu\n"
        "SPEC_PROPOSAL_NS=%llu\n"
        "SPEC_VERIFY_NS=%llu\n"
        "TARGET_BATCH_NS=%llu\n"
        "SLOT0_WEIGHT_UPLOAD_DELTA_MEASURED=%llu\n"
        "SLOT1_WEIGHT_UPLOAD_DELTA_MEASURED=%llu\n"
        "SLOT0_PINNED_WEIGHT_ENTRIES=%llu\n"
        "SLOT1_PINNED_WEIGHT_ENTRIES=%llu\n"
        "SLOT0_PINNED_WEIGHT_BYTES=%llu\n"
        "SLOT1_PINNED_WEIGHT_BYTES=%llu\n"
        "SLOT0_BATCH_INPUT_UPLOADS=%llu\n"
        "SLOT1_BATCH_INPUT_UPLOADS=%llu\n"
        "ZERO_MEASURED_WEIGHT_UPLOADS=%s\n"
        "QUEUE_SUBMITS_PER_VERIFIED_TOKEN=%.6f\n"
        "BATCH_INPUT_UPLOADS_PER_VERIFIED_TOKEN=%.6f\n"
        "DIRECT_SPEC_KV_APPENDS_DELTA=%llu\n"
        "GROUP_OUTPUT_REALLOC_DELTA_SLOT0=%llu\n"
        "GROUP_OUTPUT_REALLOC_DELTA_SLOT1=%llu\n"
        "HOTPATH_OVERHEAD_BOUNDED=%s\n"
        "HOST_TRANSFER_BYTES_MEASURED=%llu\n"
        "HOST_TRANSFER_BYTES_PER_VERIFIED_TOKEN=%.3f\n"
        "RESIDENT_FULL_OUTPUT_COPIES_DELTA=%llu\n"
        "SPEC_LAYER_GRAPH_SUBMITS_DELTA=%llu\n"
        "HOST_TRAFFIC_BOUNDED=%s\n"
        "GPU0_Q4K_BATCH_BYTES=%llu\n"
        "GPU1_Q4K_BATCH_BYTES=%llu\n"
        "GPU0_Q4K_BATCH_GPU_NS=%llu\n"
        "GPU1_Q4K_BATCH_GPU_NS=%llu\n"
        "GPU0_Q4K_EFFECTIVE_GBPS=%.3f\n"
        "GPU1_Q4K_EFFECTIVE_GBPS=%.3f\n"
        "GPU0_Q4K_4ROW_OPS_DELTA=%llu\n"
        "GPU1_Q4K_4ROW_OPS_DELTA=%llu\n"
        "SPEC_ARENA_FLIPS_DELTA=%llu\n"
        "TILED_Q4K_KERNEL=%.4s\n"
        "SPEC_PINGPONG=%.4s\n"
        "GPU0_Q4K_AUTOTUNE_RUNS_DELTA=%llu\n"
        "GPU1_Q4K_AUTOTUNE_RUNS_DELTA=%llu\n"
        "GPU0_RECORDED_Q4K_SUBMITS_DELTA=%llu\n"
        "GPU1_RECORDED_Q4K_SUBMITS_DELTA=%llu\n"
        "GPU0_RECORDED_Q4K_BUILDS_DELTA=%llu\n"
        "GPU1_RECORDED_Q4K_BUILDS_DELTA=%llu\n"
        "GPU0_Q4K_8ROW_OPS_DELTA=%llu\n"
        "GPU1_Q4K_8ROW_OPS_DELTA=%llu\n"
        "WINDOW2_ATTEMPTS=%llu VERIFIED=%llu NS=%llu\n"
        "WINDOW3_ATTEMPTS=%llu VERIFIED=%llu NS=%llu\n"
        "WINDOW4_ATTEMPTS=%llu VERIFIED=%llu NS=%llu\n"
        "COST_CONTROLLER_SELECTIONS=%llu\n"
        "Q4K_AUTOTUNE=%s\n"
        "RECORDED_Q4K_HOTPATH=%s\n"
        "COST_DRIVEN_SPEC_WINDOW=%s\n"
        "GPU0_Q4K_ASYNC_SUBMITS_DELTA=%llu\n"
        "GPU1_Q4K_ASYNC_SUBMITS_DELTA=%llu\n"
        "GPU0_Q4K_ASYNC_WAIT_NS_DELTA=%llu\n"
        "GPU1_Q4K_ASYNC_WAIT_NS_DELTA=%llu\n"
        "GPU1_DOWNLOAD_RING_SUBMITS_DELTA=%llu\n"
        "GPU1_DOWNLOAD_RING_WAIT_NS_DELTA=%llu\n"
        "ASYNC_DUAL_GPU_PATH=%s\n"
        "GPU0_COMPUTE_QUEUE_FAMILY=%u\n"
        "GPU1_COMPUTE_QUEUE_FAMILY=%u\n"
        "GPU0_TRANSFER_QUEUE_FAMILY=%u\n"
        "GPU1_TRANSFER_QUEUE_FAMILY=%u\n"
        "GPU0_DEDICATED_TRANSFER_QUEUE=%u\n"
        "GPU1_DEDICATED_TRANSFER_QUEUE=%u\n"
        "GPU0_TRANSFER_QUEUE_SUBMITS_DELTA=%llu\n"
        "GPU1_TRANSFER_QUEUE_SUBMITS_DELTA=%llu\n"
        "PIPELINE_PREPARE_WINDOWS=%llu\n"
        "PIPELINE_VERIFY_WINDOWS=%llu\n"
        "PIPELINE_COMMIT_WINDOWS=%llu\n"
        "TRANSFER_QUEUE_USED=%s\n"
        "THREE_STAGE_SPEC_PIPELINE=%s\n"
        "GPU0_TIMELINE_ENABLED=%u\n"
        "GPU1_TIMELINE_ENABLED=%u\n"
        "GPU0_TIMELINE_SIGNALS_DELTA=%llu\n"
        "GPU1_TIMELINE_SIGNALS_DELTA=%llu\n"
        "GPU0_TIMELINE_WAITS_DELTA=%llu\n"
        "GPU1_TIMELINE_WAITS_DELTA=%llu\n"
        "GPU0_TIMELINE_CHAINS_DELTA=%llu\n"
        "GPU1_TIMELINE_CHAINS_DELTA=%llu\n"
        "GPU0_ASYNC_CMD_RING_REUSE_DELTA=%llu\n"
        "GPU1_ASYNC_CMD_RING_REUSE_DELTA=%llu\n"
        "TIMELINE_CHAIN_USED=%s\n"
        "ASYNC_COMMAND_RING=%s\n"
        "GPU0_RECORDED_GROUP_BUILDS_DELTA=%llu\n"
        "GPU1_RECORDED_GROUP_BUILDS_DELTA=%llu\n"
        "GPU0_RECORDED_GROUP_SUBMITS_DELTA=%llu\n"
        "GPU1_RECORDED_GROUP_SUBMITS_DELTA=%llu\n"
        "GPU_SPEC_ACCEPT_OPS_DELTA=%llu\n"
        "VERIFIED_HIDDEN_HANDOFFS_DELTA=%llu\n"
        "LAYER_TIMELINE_CHAINS_DELTA=%llu\n"
        "RECORDED_GROUP_HOTPATH=%s\n"
        "GPU_ACCEPT_PREFIX=%s\n"
        "RESIDENT_HIDDEN_HANDOFF=%s\n"
        "LAYER_TIMELINE_CHAIN=%s\n"
        "GPU0_RECORDED_GROUP_ASYNC_DELTA=%llu\n"
        "GPU1_RECORDED_GROUP_ASYNC_DELTA=%llu\n"
        "GPU0_RECORDED_GROUP_SYNC_WAITS_DELTA=%llu\n"
        "GPU1_RECORDED_GROUP_SYNC_WAITS_DELTA=%llu\n"
        "SPEC_ACCEPT_RESIDENT_OPS_DELTA=%llu\n"
        "SPEC_ACCEPT_INPUT_UPLOAD_BYTES_DELTA=%llu\n"
        "HIDDEN_TIMELINE_SUBMITS_DELTA=%llu\n"
        "SPEC_PREPARED_TOKENS=%llu\n"
        "SPEC_VERIFIED_TARGET_WINDOWS=%llu\n"
        "SPEC_ACCEPTED_VERIFIED_TOKENS=%llu\n"
        "RECORDED_GROUP_WAITFREE=%s\n"
        "SPEC_ACCEPT_RESIDENT=%s\n"
        "HIDDEN_TIMELINE_HANDOFF=%s\n"
        "REAL_WINDOW_AMORTIZATION=%s\n"
        "STEADY_RUN0_TPS=%.6f\n"
        "STEADY_RUN1_TPS=%.6f\n"
        "STEADY_RUN2_TPS=%.6f\n"
        "STEADY_MEDIAN_TPS=%.6f\n"
        "DECODE_TPS_REAL_VERIFIED_MIN=%.6f\n"
        "DEEP2_QWEN25_32B_REAL_85TPS_001=%s\n",
        parity?"PASS":"FAIL",
        spec.vulkanDeviceCount(),
        gpu1Ready?1u:0u,
        spec.vulkanStrictViolation()?1u:0u,
        (unsigned long long)spec.vulkanUnplannedFallbacks(),
        (unsigned long long)sc.selfDraftWindows,
        (unsigned long long)sc.ngramDraftWindows,
        (unsigned long long)sc.gpuTop1Batches,
        sc.acceptanceEwma,
        (unsigned long long)sc.gpuBatchNormOps,
        (unsigned long long)sc.gpuBatchSwiGLUOps,
        (unsigned long long)sc.gpuBatchAttentionOps,
        (unsigned long long)sc.dualColumnSplitOps,
        batch4Gpu?"PASS":"FAIL",
        persistentKv?"PASS":"FAIL",
        (unsigned long long)sc.pipelineWindows,
        (unsigned long long)sc.proposalNs,
        (unsigned long long)sc.verifyNs,
        (unsigned long long)sc.targetBatchNs,
        (unsigned long long)(up0End-up0Warm),
        (unsigned long long)(up1End-up1Warm),
        (unsigned long long)pin0,
        (unsigned long long)pin1,
        (unsigned long long)pinBytes0,
        (unsigned long long)pinBytes1,
        (unsigned long long)(in0End-in0Warm),
        (unsigned long long)(in1End-in1Warm),
        zeroMeasuredUploads?"PASS":"FAIL",
        submitPerToken,
        inputUploadsPerToken,
        (unsigned long long)(kvdEnd-kvdWarm),
        (unsigned long long)(re0End-re0Warm),
        (unsigned long long)(re1End-re1Warm),
        hotpathBounded?"PASS":"FAIL",
        (unsigned long long)hostBytes,
        hostBytesPerToken,
        (unsigned long long)(asmEnd-asmWarm),
        (unsigned long long)(graphEnd-graphWarm),
        hostTrafficBounded?"PASS":"FAIL",
        (unsigned long long)b0,
        (unsigned long long)b1,
        (unsigned long long)n0,
        (unsigned long long)n1,
        gbps0,gbps1,
        (unsigned long long)(ko0End-ko0Warm),
        (unsigned long long)(ko1End-ko1Warm),
        (unsigned long long)(flipEnd-flipWarm),
        tiledKernel?"PASS":"FAIL",
        pingpong?"PASS":"FAIL",
        (unsigned long long)(at0End-at0Warm),
        (unsigned long long)(at1End-at1Warm),
        (unsigned long long)(rc0End-rc0Warm),
        (unsigned long long)(rc1End-rc1Warm),
        (unsigned long long)(rcb0End-rcb0Warm),
        (unsigned long long)(rcb1End-rcb1Warm),
        (unsigned long long)(k8o0End-k8o0Warm),
        (unsigned long long)(k8o1End-k8o1Warm),
        (unsigned long long)sc.windowAttempts[2],
        (unsigned long long)sc.windowVerified[2],
        (unsigned long long)sc.windowVerifyNs[2],
        (unsigned long long)sc.windowAttempts[3],
        (unsigned long long)sc.windowVerified[3],
        (unsigned long long)sc.windowVerifyNs[3],
        (unsigned long long)sc.windowAttempts[4],
        (unsigned long long)sc.windowVerified[4],
        (unsigned long long)sc.windowVerifyNs[4],
        (unsigned long long)sc.costControllerSelections,
        autotuned?"PASS":"FAIL",
        recordedHot?"PASS":"FAIL",
        costController?"PASS":"FAIL",
        (unsigned long long)(as0End-as0Warm),
        (unsigned long long)(as1End-as1Warm),
        (unsigned long long)(aw0End-aw0Warm),
        (unsigned long long)(aw1End-aw1Warm),
        (unsigned long long)(drEnd-drWarm),
        (unsigned long long)ringWaitNs,
        asyncOverlapPath?"PASS":"FAIL",
        cqf0,cqf1,tqf0,tqf1,
        dtq0?1u:0u,dtq1?1u:0u,
        (unsigned long long)(tq0End-tq0Warm),
        (unsigned long long)(tq1End-tq1Warm),
        (unsigned long long)sc.pipelinePrepareWindows,
        (unsigned long long)sc.pipelineVerifyWindows,
        (unsigned long long)sc.pipelineCommitWindows,
        transferQueueUsed?"PASS":"FAIL",
        threeStage?"PASS":"FAIL",
        tl0?1u:0u,tl1?1u:0u,
        (unsigned long long)(tls0End-tls0Warm),
        (unsigned long long)(tls1End-tls1Warm),
        (unsigned long long)(tlw0End-tlw0Warm),
        (unsigned long long)(tlw1End-tlw1Warm),
        (unsigned long long)(tlc0End-tlc0Warm),
        (unsigned long long)(tlc1End-tlc1Warm),
        (unsigned long long)(acr0End-acr0Warm),
        (unsigned long long)(acr1End-acr1Warm),
        timelineUsed?"PASS":"FAIL",
        cmdRingLive?"PASS":"FAIL",
        (unsigned long long)(rgb0End-rgb0Warm),
        (unsigned long long)(rgb1End-rgb1Warm),
        (unsigned long long)(rgs0End-rgs0Warm),
        (unsigned long long)(rgs1End-rgs1Warm),
        (unsigned long long)(acEnd-acWarm),
        (unsigned long long)(vhEnd-vhWarm),
        (unsigned long long)(lgEnd-lgWarm),
        recordedGroups?"PASS":"FAIL",
        gpuAccept?"PASS":"FAIL",
        hiddenHandoff?"PASS":"FAIL",
        layerTimeline?"PASS":"FAIL",
        (unsigned long long)(rga0End-rga0Warm),
        (unsigned long long)(rga1End-rga1Warm),
        (unsigned long long)(rgw0End-rgw0Warm),
        (unsigned long long)(rgw1End-rgw1Warm),
        (unsigned long long)(sarEnd-sarWarm),
        (unsigned long long)(sauEnd-sauWarm),
        (unsigned long long)(htsEnd-htsWarm),
        (unsigned long long)sc.preparedSpecTokens,
        (unsigned long long)sc.verifiedTargetWindows,
        (unsigned long long)sc.acceptedVerifiedTokens,
        recordedWaitFree?"PASS":"FAIL",
        residentAccept?"PASS":"FAIL",
        hiddenTimeline?"PASS":"FAIL",
        realWindowAmortization?"PASS":"FAIL",

        tpsRun[0],tpsRun[1],tpsRun[2],tpsMedian,tpsMin,
        pass?"PASS":"HOLD");

    return pass?0:1;
}

