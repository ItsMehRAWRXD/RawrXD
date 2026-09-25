// Deep2GpuForward.hpp — STREAMER_GPU_FORWARD_OPS_001 + RESIDENT_DECODE_001
#pragma once
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct GpuForwardCounters {
    uint64_t rmsNormOps = 0;
    uint64_t qkvOps = 0;
    uint64_t ropeOps = 0;
    uint64_t attnScoreOps = 0;
    uint64_t softmaxOps = 0;
    uint64_t attnValueOps = 0;
    uint64_t oProjOps = 0;
    uint64_t residualOps = 0;
    uint64_t ffnNormOps = 0;
    uint64_t ffnActOps = 0;
    uint64_t ffnResidualOps = 0;
    uint64_t forwardLayers = 0;
    uint64_t forwardSlot[8]{};
    uint64_t hostSyncBoundaries = 0;
    uint64_t hostMaterializations = 0;
    // B5_MATERIALIZATION_PROFILE_001: classify every host materialization
    // event + wall time per class. ACCOUNTING_MATCH requires the class sum
    // to equal hostMaterializations exactly.
    uint64_t matCrossDeviceHandoff = 0;   // CopyArenaHiddenTo host bounce
    uint64_t matGemvSingleRoundTrip = 0;   // tryVulkanHostGEMV single-GPU lane
    uint64_t matDualRowSingle = 0;         // dual-row single-GEMV host round-trip
    uint64_t matDualRowGroup = 0;          // dual-row grouped-GEMV host round-trip
    uint64_t matDualRowMerge = 0;          // LEGACY alias: DualRowSingle+DualRowGroup
    uint64_t matFinalDownload = 0;         // final hidden DownloadHidden
    uint64_t matOther = 0;                 // MoE/MLA/speculative residue
    uint64_t matCrossDeviceHandoffNs = 0;
    uint64_t matGemvSingleNs = 0;
    uint64_t matFinalDownloadNs = 0;
    uint64_t matOtherNs = 0;
    uint64_t ownershipTransfers = 0;
    uint64_t intraSlotHostTransfers = 0;
    uint64_t liveDecodeResidentTokens = 0;
    uint64_t liveDecodeTokens = 0;
    uint64_t hostForwardLayerCalls = 0;
    uint64_t plannedCpuLayerCalls = 0;
    uint64_t gpuLayersLastToken = 0;
    uint64_t layerSubmits = 0;
    uint64_t opSubmits = 0;
    uint64_t q4kPackedOps = 0;
    uint64_t q6kPackedOps = 0;
    uint64_t q2kPackedOps = 0;
    uint64_t cpuF32Expands = 0;
    uint64_t dualRowSplitOps = 0;
    uint64_t dualArithmeticOverlapNs = 0;
    uint64_t dualAsyncWindows=0;
    uint64_t dualAsyncOverlapNs=0;
    uint64_t dualAsyncWallNs=0;
    uint64_t hostMergeOps = 0;
    uint64_t dualRowDenseTokens = 0;
    uint64_t dualRowSlot[8]{};          // real-weight dual-row dispatches per device
    // DEEP2_RESIDENT_COST_ATTRIBUTION_001: phase-level walls for the
    // resident multi-map lane. All phases are host walls bracketing the
    // blocking calls; residentRangeGpuNs is the calibrated EndFusedLayer
    // GPU interval per slot range. Attention/KV-append execute inside the
    // fused range — their length-scaling is read from the range-GPU slope
    // across 64/128/256-token runs, not from separate per-op counters.
    uint64_t residentUploadHiddenNs = 0;
    uint64_t residentUploadHiddenCount = 0;
    uint64_t residentUploadHiddenBytes = 0;
    uint64_t residentPrimeCommitNs = 0;      // CommitWeightPrime fence wait
    uint64_t residentPrimeCommitCount = 0;
    uint64_t residentRangeNs[2] = {};        // host wall: record+submit+wait
    uint64_t residentRangeGpuNs[2] = {};    // calibrated GPU interval
    uint64_t residentRangeCount[2] = {};
    uint64_t residentHandoffNs = 0;         // CopyArenaHiddenTo host bounce
    uint64_t residentHandoffCount = 0;
    uint64_t residentHandoffBytes = 0;
    uint64_t residentFinalDownloadNs = 0;
    uint64_t residentFinalDownloadCount = 0;
    uint64_t residentQueueSubmits = 0;      // blocking submits on this lane
    uint64_t residentFenceWaits = 0;        // blocking waits on this lane
    uint64_t gpuExpertDispatches = 0;
    uint64_t mlaGpuAttentionOps = 0;
};

inline bool Deep2GpuForward_Resident(const GpuForwardCounters& c) noexcept {
    return c.forwardLayers > 0 && c.rmsNormOps > 0 && c.qkvOps > 0 &&
           c.ropeOps > 0 && c.attnScoreOps > 0 && c.residualOps > 0 &&
           c.ffnActOps > 0 && c.hostForwardLayerCalls == 0;
}

inline bool Deep2GpuForward_IsReal(const GpuForwardCounters& c, uint64_t) noexcept {
    // Allow the final-download materialization (host must sample logits),
    // but reject any cross-device host bounce or other unexpected staging.
    return Deep2GpuForward_Resident(c) && c.hostMaterializations == c.matFinalDownload;
}

// B5_MATERIALIZATION_PROFILE_001: class sum must equal the raw counter.
// DEEP2_DENSE_ROW_GPU_TIMING_AUTHORITY_001 makes the classification
// exhaustive: every hostMaterializations increment belongs to exactly one
// class (DualRowSingle / DualRowGroup / FinalOutput / CrossDevice /
// GemvStaging / Other), so ACCOUNTING_MATCH=1 is a hard invariant.
// matDualRowMerge is a LEGACY computed alias (= Single + Group), never
// incremented directly and never summed alongside its parts.
inline uint64_t Deep2GpuForward_MatClassSum(
    const GpuForwardCounters& c) noexcept {
    return c.matCrossDeviceHandoff + c.matGemvSingleRoundTrip +
           c.matDualRowSingle + c.matDualRowGroup +
           c.matFinalDownload + c.matOther;
}

inline uint64_t Deep2GpuForward_DualRowMaterializations(
    const GpuForwardCounters& c) noexcept {
    return c.matDualRowSingle + c.matDualRowGroup;
}

inline bool Deep2GpuForward_DualPhysicalGpuReal(const GpuForwardCounters& c) noexcept {
    // Authority from either:
    //   A) resident decode: both GPU slots executed >0 layers, AND no host materializations
    //   B) dual-row dense: both GPU slots performed >0 real-weight dual-row dispatches
    const bool residentEvidence =
        Deep2GpuForward_IsReal(c, 0) &&
        c.forwardSlot[0] > 0 && c.forwardSlot[1] > 0;
    const bool dualRowEvidence =
        c.dualRowSlot[0] > 0 && c.dualRowSlot[1] > 0;
    return residentEvidence || dualRowEvidence;
}

inline void Deep2GpuForward_Emit(FILE* f, const GpuForwardCounters& c, uint64_t cpuFb) noexcept {
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "DEEP2_GPU_RMSNORM_OPS=%llu\n", (unsigned long long)c.rmsNormOps);
        fprintf(o, "DEEP2_GPU_QKV_OPS=%llu\n", (unsigned long long)c.qkvOps);
        fprintf(o, "DEEP2_GPU_ROPE_OPS=%llu\n", (unsigned long long)c.ropeOps);
        fprintf(o, "DEEP2_GPU_ATTN_SCORE_OPS=%llu\n", (unsigned long long)c.attnScoreOps);
        fprintf(o, "DEEP2_GPU_SOFTMAX_OPS=%llu\n", (unsigned long long)c.softmaxOps);
        fprintf(o, "DEEP2_GPU_ATTN_VALUE_OPS=%llu\n", (unsigned long long)c.attnValueOps);
        fprintf(o, "DEEP2_GPU_O_PROJ_OPS=%llu\n", (unsigned long long)c.oProjOps);
        fprintf(o, "DEEP2_GPU_RESIDUAL_OPS=%llu\n", (unsigned long long)c.residualOps);
        fprintf(o, "DEEP2_GPU_FFN_NORM_OPS=%llu\n", (unsigned long long)c.ffnNormOps);
        fprintf(o, "DEEP2_GPU_FFN_ACT_OPS=%llu\n", (unsigned long long)c.ffnActOps);
        fprintf(o, "DEEP2_GPU_FFN_RESIDUAL_OPS=%llu\n", (unsigned long long)c.ffnResidualOps);
        fprintf(o, "DEEP2_GPU_FORWARD_LAYERS=%llu\n", (unsigned long long)c.forwardLayers);
        fprintf(o, "DEEP2_GPU_FORWARD_SLOT_0=%llu\n", (unsigned long long)c.forwardSlot[0]);
        fprintf(o, "DEEP2_GPU_FORWARD_SLOT_1=%llu\n", (unsigned long long)c.forwardSlot[1]);
        fprintf(o, "DEEP2_GPU_FORWARD_HOST_SYNC_BOUNDARIES=%llu\n",
                (unsigned long long)c.hostSyncBoundaries);
        fprintf(o, "DEEP2_GPU_FORWARD_HOST_MATERIALIZATIONS=%llu\n",
                (unsigned long long)c.hostMaterializations);
        fprintf(o, "DEEP2_GPU_OWNERSHIP_TRANSFERS=%llu\n",
                (unsigned long long)c.ownershipTransfers);
        fprintf(o, "DEEP2_INTRA_SLOT_HOST_TRANSFERS=%llu\n",
                (unsigned long long)c.intraSlotHostTransfers);
        fprintf(o, "LIVE_DECODE_RESIDENT_FORWARD=%u\n",
                c.liveDecodeResidentTokens > 0 ? 1u : 0u);
        fprintf(o, "TOKENS_DECODED=%llu\n", (unsigned long long)c.liveDecodeTokens);
        fprintf(o, "GPU_FORWARD_LAYERS_PER_TOKEN=%llu\n",
                (unsigned long long)c.gpuLayersLastToken);
        fprintf(o, "HOST_FORWARD_LAYER_CALLS=%llu\n",
                (unsigned long long)c.hostForwardLayerCalls);
        fprintf(o, "PLANNED_CPU_LAYER_CALLS=%llu\n",
                (unsigned long long)c.plannedCpuLayerCalls);
        fprintf(o, "DEEP2_GPU_RESIDENT_FORWARD=%u\n",
                Deep2GpuForward_Resident(c) ? 1u : 0u);
        fprintf(o, "DEEP2_GPU_FORWARD_FALLBACKS=%llu\n",
                (unsigned long long)c.hostForwardLayerCalls);
        fprintf(o, "DEEP2_GPU_LAYER_SUBMITS=%llu\n",
                (unsigned long long)c.layerSubmits);
        fprintf(o, "DEEP2_GPU_OP_SUBMITS=%llu\n",
                (unsigned long long)c.opSubmits);
        fprintf(o, "DEEP2_GPU_HOST_SYNC=%llu\n",
                (unsigned long long)c.hostSyncBoundaries);
        fprintf(o, "DEEP2_REAL_GPU_FORWARD=%u\n",
                Deep2GpuForward_IsReal(c, cpuFb) ? 1u : 0u);
        fprintf(o, "DEEP2_GPU_Q4K_PACKED_OPS=%llu\n",
                (unsigned long long)c.q4kPackedOps);
        fprintf(o, "DEEP2_GPU_Q6K_PACKED_OPS=%llu\n",
                (unsigned long long)c.q6kPackedOps);
        fprintf(o, "DEEP2_GPU_Q2K_PACKED_OPS=%llu\n",
                (unsigned long long)c.q2kPackedOps);
        fprintf(o, "DEEP2_GPU_CPU_F32_EXPANDS=%llu\n",
                (unsigned long long)c.cpuF32Expands);
        fprintf(o, "DEEP2_GPU_DUAL_ROW_SPLIT_OPS=%llu\n",
                (unsigned long long)c.dualRowSplitOps);
        fprintf(o, "DEEP2_GPU_DUAL_ARITH_OVERLAP_NS=%llu\n",
                (unsigned long long)c.dualArithmeticOverlapNs);
        fprintf(o, "DEEP2_GPU_HOST_MERGE_OPS=%llu\n",
                (unsigned long long)c.hostMergeOps);
        fprintf(o, "DEEP2_DUAL_ROW_DENSE_TOKENS=%llu\n",
                (unsigned long long)c.dualRowDenseTokens);
        fprintf(o, "DEEP2_DUAL_ROW_SLOT_0=%llu\n",
                (unsigned long long)c.dualRowSlot[0]);
        fprintf(o, "DEEP2_DUAL_ROW_SLOT_1=%llu\n",
                (unsigned long long)c.dualRowSlot[1]);

        fprintf(o, "DEEP2_GPU_EXPERT_DISPATCHES=%llu\n",
                (unsigned long long)c.gpuExpertDispatches);
        fprintf(o, "DEEP2_GPU_MLA_ATTN_OPS=%llu\n",
                (unsigned long long)c.mlaGpuAttentionOps);
        fprintf(o, "DEEP2_DUAL_PHYSICAL_GPU_FORWARD=%u\n",
                Deep2GpuForward_DualPhysicalGpuReal(c) ? 1u : 0u);
    };
    emit(stdout);
    if (f && f != stdout) emit(f);
}

} // namespace Deep2
