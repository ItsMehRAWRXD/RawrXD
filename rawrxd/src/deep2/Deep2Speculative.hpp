#pragma once
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace Deep2 {

struct SpeculativeRoofline {
    double targetModelGB = 18.49;
    double gpu0GBps = 640.0;
    double gpu1GBps = 624.0;
    double efficiency = 0.80;
    double targetOutputTPS = 85.0;

    double aggregateGBps() const noexcept {
        return gpu0GBps + gpu1GBps;
    }
    double rawTargetPassTPS() const noexcept {
        return targetModelGB > 0.0 ? aggregateGBps() / targetModelGB : 0.0;
    }
    double effectiveTargetPassTPS() const noexcept {
        return rawTargetPassTPS() * efficiency;
    }
    double minimumAcceptedPerPass() const noexcept {
        const double p=effectiveTargetPassTPS();
        return p>0.0 ? targetOutputTPS/p : 1.0e300;
    }
    bool physicallyReachableWithWindow(uint32_t window) const noexcept {
        return window>0 &&
               minimumAcceptedPerPass() <= static_cast<double>(window);
    }
};

struct SpeculativeCounters {
    uint64_t draftWindows=0;
    uint64_t proposedTokens=0;
    uint64_t acceptedTokens=0;
    uint64_t rejectedTokens=0;
    uint64_t targetPasses=0;
    uint64_t verifiedOutputTokens=0;
    uint64_t ngramDraftWindows=0;
    uint64_t selfDraftWindows=0;
    uint64_t gpuTop1Batches=0;
    uint64_t gpuBatchNormOps=0;
    uint64_t gpuBatchSwiGLUOps=0;
    uint64_t gpuBatchAttentionOps=0;
    uint64_t dualColumnSplitOps=0;
    uint64_t kvMirrorPrefixUploads=0;
    uint64_t kvMirrorDeltaTokens=0;
    uint64_t kvMirrorResidentAttn=0;
    uint64_t proposalNs=0;
    uint64_t verifyNs=0;
    uint64_t targetBatchNs=0;
    uint64_t attentionNs=0;
    uint64_t columnReduceNs=0;
    uint64_t pipelineWindows=0;
    uint64_t windowAttempts[5]{};
    uint64_t windowVerified[5]{};
    uint64_t windowVerifyNs[5]{};
    uint64_t costControllerSelections=0;
    uint64_t pipelinePrepareWindows=0;
    uint64_t pipelineVerifyWindows=0;
    uint64_t pipelineCommitWindows=0;
    uint64_t pipelineOverlapNs=0;

    double acceptanceEwma=0.50;

    double acceptedPerTargetPass() const noexcept {
        return targetPasses
            ? static_cast<double>(acceptedTokens)/static_cast<double>(targetPasses)
            : 0.0;
    }
    double verifiedPerTargetPass() const noexcept {
        return targetPasses
            ? static_cast<double>(verifiedOutputTokens)/
              static_cast<double>(targetPasses)
            : 0.0;
    }
    uint64_t preparedSpecTokens=0;
    uint64_t verifiedTargetWindows=0;
    uint64_t acceptedVerifiedTokens=0;
    uint64_t rejectedSpecWindows=0;
};

struct PreparedSpecWindow {
    std::vector<int32_t> proposals;
    uint64_t generation=0;
    uint32_t window=0;
    bool ready=false;
    void clear() {
        proposals.clear();generation=0;window=0;ready=false;
    }
};

inline void Emit85TpsRoofline(
    FILE* f,const SpeculativeRoofline& r,const SpeculativeCounters& c,
    double measuredOutputTPS,uint32_t window) noexcept
{
    FILE* o=f?f:stderr;
    std::fprintf(o,
        "GATE=DEEP2_QWEN25_32B_REAL_85TPS_001\n"
        "TARGET_MODEL_GB=%.3f\n"
        "GPU0_PEAK_GBPS=%.3f\n"
        "GPU1_PEAK_GBPS=%.3f\n"
        "AGGREGATE_PEAK_GBPS=%.3f\n"
        "ASSUMED_BW_EFFICIENCY=%.6f\n"
        "RAW_TARGET_PASS_TPS=%.6f\n"
        "EFFECTIVE_TARGET_PASS_TPS=%.6f\n"
        "MIN_ACCEPTED_PER_TARGET_PASS_FOR_85=%.6f\n"
        "SPEC_WINDOW=%u\n"
        "TARGET_PASSES=%llu\n"
        "PROPOSED_TOKENS=%llu\n"
        "ACCEPTED_TOKENS=%llu\n"
        "VERIFIED_OUTPUT_TOKENS=%llu\n"
        "GPU_BATCH_NORM_OPS=%llu\n"
        "GPU_BATCH_SWIGLU_OPS=%llu\n"
        "GPU_BATCH_ATTENTION_OPS=%llu\n"
        "DUAL_COLUMN_SPLIT_OPS=%llu\n"
        "KV_MIRROR_PREFIX_UPLOADS=%llu\n"
        "KV_MIRROR_DELTA_TOKENS=%llu\n"
        "KV_MIRROR_RESIDENT_ATTN=%llu\n"
        "SPEC_PROPOSAL_NS=%llu\n"
        "SPEC_VERIFY_NS=%llu\n"
        "TARGET_BATCH_NS=%llu\n"
        "PIPELINE_WINDOWS=%llu\n"
        "ACCEPTED_PER_TARGET_PASS=%.6f\n"
        "VERIFIED_PER_TARGET_PASS=%.6f\n"
        "MEASURED_OUTPUT_TPS=%.6f\n",
        r.targetModelGB,r.gpu0GBps,r.gpu1GBps,r.aggregateGBps(),
        r.efficiency,r.rawTargetPassTPS(),r.effectiveTargetPassTPS(),
        r.minimumAcceptedPerPass(),window,
        (unsigned long long)c.targetPasses,
        (unsigned long long)c.proposedTokens,
        (unsigned long long)c.acceptedTokens,
        (unsigned long long)c.verifiedOutputTokens,
        (unsigned long long)c.gpuBatchNormOps,
        (unsigned long long)c.gpuBatchSwiGLUOps,
        (unsigned long long)c.gpuBatchAttentionOps,
        (unsigned long long)c.dualColumnSplitOps,
        (unsigned long long)c.kvMirrorPrefixUploads,
        (unsigned long long)c.kvMirrorDeltaTokens,
        (unsigned long long)c.kvMirrorResidentAttn,
        (unsigned long long)c.proposalNs,
        (unsigned long long)c.verifyNs,
        (unsigned long long)c.targetBatchNs,
        (unsigned long long)c.pipelineWindows,

        c.acceptedPerTargetPass(),c.verifiedPerTargetPass(),
        measuredOutputTPS);
}

} // namespace Deep2
