// Deep2GpuForward.hpp — STREAMER_GPU_FORWARD_OPS_001 counters + contracts
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
    uint64_t ownershipTransfers = 0;
    uint64_t intraSlotHostTransfers = 0;
};

inline bool Deep2GpuForward_IsReal(const GpuForwardCounters& c, uint64_t cpuFallback) noexcept {
    const uint64_t attn = c.attnScoreOps + c.softmaxOps + c.attnValueOps;
    const uint64_t ffn = c.ffnNormOps + c.ffnActOps + c.ffnResidualOps;
    return c.forwardLayers > 0 &&
           c.rmsNormOps > 0 &&
           c.qkvOps > 0 &&
           c.ropeOps > 0 &&
           attn > 0 &&
           c.residualOps > 0 &&
           ffn > 0 &&
           c.hostMaterializations == 0 &&
           cpuFallback == 0;
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
        fprintf(o, "DEEP2_REAL_GPU_FORWARD=%u\n",
                Deep2GpuForward_IsReal(c, cpuFb) ? 1u : 0u);
    };
    emit(stdout);
    if (f && f != stdout) emit(f);
}

} // namespace Deep2
