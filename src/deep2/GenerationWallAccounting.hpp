// GenerationWallAccounting.hpp — GENERATION_WALL_ACCOUNTING_001
//
// This is a diagnostic reconciliation surface for the K2 stream path.  The
// existing counters are deliberately emitted as *inclusive* measurements:
// shard I/O, MLA, logits, sampling, and transfer work may overlap.  The
// receipt therefore reports overlap and an explicit incomplete flag instead
// of pretending that a subtraction is a certified critical-path partition.
#pragma once

#include "MoEPlaceLiveCounters.hpp"
#include "K2MoEExpertAccounting.hpp"
#include "K2MlaOProjTiming.hpp"
#include "K2MlaStageTiming.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include "lavapath/DualStickStreamWindow.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

inline void GenerationWallAccounting_Emit(FILE* f, uint64_t wallNs,
                                          uint64_t tokenCount) {
    if (!f) f = stdout;

    const uint64_t wallUs = wallNs / 1000ull;
    const auto transfer = StreamTransfer_SnapshotRaw();
    const auto& moe = MoEPlaceLive();
    const auto& dualStick = DualStickState();

    const uint64_t shardReadUs = SPT_shardRead().load(std::memory_order_relaxed);
    const uint64_t shardOpenUs = SPT_shardOpen().load(std::memory_order_relaxed);
    const uint64_t reconstructUs = SPT_recon().load(std::memory_order_relaxed);
    const uint64_t mlaUs = SPT_mla().load(std::memory_order_relaxed);
    const uint64_t logitsUs = SPT_logits().load(std::memory_order_relaxed);
    const uint64_t sampleUs = SPT_sample().load(std::memory_order_relaxed);
    const uint64_t streamUs = SPT_stream().load(std::memory_order_relaxed);
    const uint64_t detokUs = SPT_detok().load(std::memory_order_relaxed);
    const uint64_t tokenizeUs = SPT_tokenize().load(std::memory_order_relaxed);
    const uint64_t outProjUs = OProj_WallUs().load(std::memory_order_relaxed);
    const uint64_t gpuKernelUs = OProj_KernelUs().load(std::memory_order_relaxed);
    const uint64_t gpuWaitUs = OProj_WaitUs().load(std::memory_order_relaxed);

    // These are intentionally inclusive components.  Do not use the sum as
    // a throughput authority: nested/overlapped timers can count the same
    // interval more than once.
    const uint64_t inclusiveUs = shardOpenUs + shardReadUs + reconstructUs +
        mlaUs + logitsUs + sampleUs + streamUs + detokUs + tokenizeUs +
        outProjUs + gpuWaitUs;
    const uint64_t overlapUs = inclusiveUs > wallUs ? inclusiveUs - wallUs : 0ull;
    const uint64_t unclassifiedIfDisjointUs = wallUs > inclusiveUs ? wallUs - inclusiveUs : 0ull;

    std::fprintf(f, "GENERATION_WALL_ACCOUNTING_001\n");
    std::fprintf(f, "ACCOUNTING_COMPLETE=0\n");
    std::fprintf(f, "TOKEN_COUNT=%llu\n", (unsigned long long)tokenCount);
    std::fprintf(f, "WALL_NS=%llu\n", (unsigned long long)wallNs);
    std::fprintf(f, "MODEL_WEIGHT_ACQUIRE_NS=%llu\n",
                 (unsigned long long)((shardOpenUs + reconstructUs) * 1000ull));
    std::fprintf(f, "SHARD_READ_EXPOSED_NS=%llu\n",
                 (unsigned long long)(shardReadUs * 1000ull));
    std::fprintf(f, "HOST_DEQUANT_NS=UNMEASURED\n");
    std::fprintf(f, "CPU_GEMV_NS=UNMEASURED\n");
    std::fprintf(f, "GPU_GEMV_KERNEL_NS=%llu\n",
                 (unsigned long long)(gpuKernelUs * 1000ull));
    std::fprintf(f, "H2D_TRANSFER_BYTES=%llu\n",
                 (unsigned long long)moe.h2d_bytes);
    std::fprintf(f, "H2D_TRANSFER_EXPOSED_NS=UNMEASURED\n");
    std::fprintf(f, "GPU_QUEUE_WAIT_NS=%llu\n",
                 (unsigned long long)((gpuWaitUs * 1000ull) + moe.gpu_join_wait_ns));
    std::fprintf(f, "MLA_EXPOSED_NS=%llu\n", (unsigned long long)(mlaUs * 1000ull));
    std::fprintf(f, "MOE_GPU_WORK_NS=%llu\n",
                 (unsigned long long)(moe.gpu0_work_ns + moe.gpu1_work_ns));
    std::fprintf(f, "MOE_GPU_WAIT_NS=%llu\n",
                 (unsigned long long)moe.gpu_join_wait_ns);
    std::fprintf(f, "MOE_SHARD_IO_NS=%llu\n",
                 (unsigned long long)(SPT_shardMoe().load(std::memory_order_relaxed) * 1000ull));
    std::fprintf(f, "KV_UPDATE_NS=UNMEASURED\n");
    std::fprintf(f, "LOGITS_NS=%llu\n", (unsigned long long)(logitsUs * 1000ull));
    std::fprintf(f, "SAMPLING_NS=%llu\n", (unsigned long long)(sampleUs * 1000ull));
    std::fprintf(f, "REPORTED_COMPONENT_SUM_NS=%llu\n",
                 (unsigned long long)(inclusiveUs * 1000ull));
    std::fprintf(f, "OVERLAPPED_NS=%llu\n", (unsigned long long)(overlapUs * 1000ull));
    std::fprintf(f, "UNCLASSIFIED_IF_DISJOINT_NS=%llu\n",
                 (unsigned long long)(unclassifiedIfDisjointUs * 1000ull));
    std::fprintf(f, "SHARD_READ_BYTES=%llu\n", (unsigned long long)transfer.bytesRead);
    std::fprintf(f, "SHARD_READ_OPS=%llu\n", (unsigned long long)transfer.readOps);
    std::fprintf(f, "GPU_UPLOAD_BYTES=%llu\n", (unsigned long long)transfer.bytesToGpu);
    std::fprintf(f, "MLA_STAGE_SUM_NS=%llu\n",
                 (unsigned long long)((MlaStage_QkvUs().load(std::memory_order_relaxed) +
                                      MlaStage_KvExpandUs().load(std::memory_order_relaxed) +
                                      MlaStage_AttnUs().load(std::memory_order_relaxed) +
                                      MlaStage_OProjUs().load(std::memory_order_relaxed)) * 1000ull));
    /* Backend attestation is deliberately split from performance claims.  A
       nonzero GPU counter proves that the routed worklist entered a real
       device path; it does not prove CPU/GPU numerical parity or dual-GPU
       certification. */
    std::fprintf(f, "GPU_MOE_BACKEND_RECEIPT_001\n");
    std::fprintf(f, "DUALSTICK_REQUESTED=%u\n",
                 (dualStick.requested || dualStick.planned || dualStick.armed) ? 1u : 0u);
    std::fprintf(f, "DUALSTICK_VC0_BOUND=%u\n", DualStickVc(0u) ? 1u : 0u);
    std::fprintf(f, "DUALSTICK_VC1_BOUND=%u\n", DualStickVc(1u) ? 1u : 0u);
    std::fprintf(f, "GPU0_EXPERTS=%llu\n", (unsigned long long)moe.gpu0_experts);
    std::fprintf(f, "GPU1_EXPERTS=%llu\n", (unsigned long long)moe.gpu1_experts);
    std::fprintf(f, "GPU_SUBMITS=%llu\n", (unsigned long long)moe.gpu_submits);
    std::fprintf(f, "GPU_WAITS=%llu\n", (unsigned long long)moe.gpu_waits);
    std::fprintf(f, "H2D_BYTES=%llu\n", (unsigned long long)moe.h2d_bytes);
    std::fprintf(f, "D2H_BYTES=%llu\n", (unsigned long long)moe.d2h_bytes);
    std::fprintf(f, "DEVICE_DOWN_VECTORS=%llu\n",
                 (unsigned long long)moe.device_down_vectors);
    std::fprintf(f, "DEVICE_PARTIAL_ACCUMS=%llu\n",
                 (unsigned long long)moe.device_partial_accums);
    std::fprintf(f, "D2H_PARTIAL_VECTORS=%llu\n",
                 (unsigned long long)moe.d2h_partial_vectors);
    std::fprintf(f, "HOST_EXPERT_DOWN_VECTORS=%llu\n",
                 (unsigned long long)moe.host_expert_down_vectors);
    std::fprintf(f, "MOE_GPU_EXECUTION_OBSERVED=%u\n",
                 (moe.expert_gpu_exec && moe.device_down_vectors) ? 1u : 0u);
    std::fprintf(f, "MOE_GPU_OUTPUT_PATH_OBSERVED=%u\n",
                 (moe.device_down_vectors && moe.d2h_partial_vectors &&
                  moe.host_expert_down_vectors == 0) ? 1u : 0u);
    std::fprintf(f, "MOE_DUAL_GPU_ATTESTED=%u\n",
                 (moe.product_backend_attested && moe.gpu0_experts &&
                  moe.gpu1_experts) ? 1u : 0u);
    std::fprintf(f, "MOE_PRODUCT_BACKEND_ATTESTED=%llu\n",
                 (unsigned long long)moe.product_backend_attested);
    K2MoEExpertAccounting::Instance().Emit(f);
    std::fprintf(f, "NOTES=Inclusive counters are not a critical-path partition; missing CPU/H2D/KV spans remain explicit.\n");
    std::fflush(f);
}

} // namespace Deep2
