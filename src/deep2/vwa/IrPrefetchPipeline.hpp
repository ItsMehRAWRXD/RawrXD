//=============================================================================
// IrPrefetchPipeline.hpp — IR-driven prefetch with circular token awareness
//
// Uses kExecutionIRTable to prefetch tensors before they are needed.
// Treats the IR as circular for repeated decode, so op 280 can know that
// a tensor's next use may be op 15 of the next token.
//
// Integrates with VwaScheduler via PrefetchBlocks to overlap I/O with compute.
//=============================================================================

#pragma once
#include "VirtualTensor.hpp"
#include "VwaScheduler.hpp"
#include "NextUseEvictionPolicy.hpp"
#include "VwaTypes.hpp"
#include "VwaExpert.hpp"
#include <cstdint>
#include <vector>
#include <future>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace Deep2 {
namespace vwa {

/**
 * Per-op residency request.
 * Describes what weight bytes a single IR op needs and where they should land.
 */
struct OpResidencyRequest {
    uint32_t opId;
    std::vector<uint32_t> tensorIds;       // Weight tensor IDs needed
    std::vector<uint32_t> expertIds;       // For MoEExecute, selected expert IDs
    uint32_t blockIndex;
    uint32_t gpuTarget;                    // 0/1 which GPU should hold the weights
    bool isMoE;
    uint64_t totalBytes;                   // Total bytes the op will consume
};

/**
 * Prefetch horizon: how many future ops to look ahead for prefetch candidates.
 * Tuned so that prefetch I/O completes before the op is reached.
 */
struct PrefetchConfig {
    uint32_t horizonOps = 4;           // Look ahead N ops for prefetch
    uint32_t lookaheadTensors = 3;     // Prefetch tensors from next 3 IR ops
    uint32_t maxConcurrentFetches = 8; // Max in-flight NVMe/DMA operations
    bool overlapCompute = true;        // Overlap prefetch with compute
    bool circularTokenWrap = true;     // Wrap IR for repeated token decode
};

/**
 * IrPrefetchPipeline
 *
 * Drives per-op residency:
 *   1. On op dispatch, lease the op's weight tensors via VwaScheduler.
 *   2. Release leases after op completes.
 *   3. Prefetch tensors for upcoming ops based on IR forward references.
 *   4. Apply next-use eviction when budget is exceeded.
 *
 * The pipeline runs on the IR cursor: currentOp advances as each op executes,
 * and prefetch decisions use (currentOp + lookahead) to find future needs.
 */
class IrPrefetchPipeline {
public:
    IrPrefetchPipeline(VwaScheduler& scheduler, const IrNextUseIndex* irIndex)
        : scheduler_(scheduler)
        , irIndex_(irIndex)
        , eviction_(irIndex)
        , currentOp_(0)
        , tokenOpBase_(0)
        , opCount_(300)
    {
    }

    void SetConfig(const PrefetchConfig& cfg) { config_ = cfg; }
    void SetTokenOpBase(uint32_t base) { tokenOpBase_.store(base, std::memory_order_release); }

    /**
     * Set the current IR op cursor. This updates the next-use distance
     * for eviction decisions and prefetch lookahead.
     */
    void SetCurrentOp(uint32_t opId) {
        currentOp_.store(opId, std::memory_order_release);
        eviction_.SetCurrentOp(opId);
        // Also propagate to tokenOpBase for circular wrap calculations
        // (tokenOpBase_ = (opId / tokenStride_) * tokenStride_)
        if (tokenStride_ > 0) {
            tokenOpBase_.store((opId / tokenStride_) * tokenStride_,
                               std::memory_order_release);
        }
    }

    void SetTokenStride(uint32_t stride) {
        tokenStride_ = stride;
    }

    /**
     * Prepare residency for an op: resolve virtual addresses, ensure the
     * required tensors are resident on the correct GPU.
     *
     * Returns true if all required tensors are resident or were successfully
     * faulted in. Returns false if budget cannot be satisfied.
     */
    bool PrepareOp(const OpResidencyRequest& req) {
        currentOp_.store(req.opId, std::memory_order_release);
        eviction_.SetCurrentOp(req.opId);

        // 1. Build BlockRange list for all weight tensors
        std::vector<BlockRange> ranges;
        ranges.reserve(req.tensorIds.size());

        for (uint32_t tid : req.tensorIds) {
            // The tensor is registered in VwaSpace by the mount phase.
            // We just need its full block range.
            // (For expert tensors, this will be further refined by expert selection.)
            // The VirtualTensor table is the IR-aware overlay; VwaSpace holds
            // the VirtualTensorRef. We query VwaSpace via the scheduler.
            BlockRange br{};
            br.id = tid;
            br.first = 0;
            br.count = 1; // whole tensor — will be resolved by scheduler
            ranges.push_back(br);
        }

        // 2. For MoE, refine to selected experts only
        if (req.isMoE && !req.expertIds.empty()) {
            // Use VwaExpert::PlanExpertBlocks to get exact block ranges
            // for the selected experts
            ranges.clear();
            // The expert bank lookup requires the three expert tensor IDs
            // (gate, up, down). For now, we use the first three tensor IDs
            // in the request as the MoE weight triplets.
            // In production, this comes from kExecutionIRTable's weight operands.
            // ... expert-specific block planning happens in caller
        }

        // 3. Request blocks through the scheduler (handles coalescing, I/O, DMA)
        if (!scheduler_.RequestBlocks(ranges.data(), ranges.size())) {
            return false;
        }

        return true;
    }

    /**
     * Release leases after op completes.
     * Decrements refCount on all weight tensors used by the op.
     * Does NOT immediately evict — lets next-use policy decide.
     */
    void ReleaseOp(const OpResidencyRequest& req) {
        for (uint32_t tid : req.tensorIds) {
            scheduler_.Release(tid);
        }
    }

    /**
     * Prefetch tensors that will be needed in the next N ops.
     * Uses the IR forward-reference table to identify which tensors
     * will be needed and triggers async prefetch.
     */
    void PrefetchAhead(uint32_t currentOpId) {
        if (config_.horizonOps == 0) return;

        uint32_t startLookahead = currentOpId + 1;
        uint32_t endLookahead = currentOpId + config_.horizonOps;

        // For circular token wrap, adjust if lookahead crosses opCount_
        const uint32_t opCount = irIndex_ ? irIndex_->OpCount() : opCount_;

        std::vector<BlockRange> prefetchRanges;
        prefetchRanges.reserve(config_.horizonOps * 4);

        for (uint32_t op = startLookahead; op <= endLookahead; ++op) {
            uint32_t wrappedOp = op % opCount;

            // Find tensors referenced by op[wrappedOp]
            auto tensorRefs = FindTensorsForOp(wrappedOp);
            for (uint32_t tid : tensorRefs) {
                BlockRange br{};
                br.id = tid;
                br.first = 0;
                br.count = 1;
                prefetchRanges.push_back(br);
            }
        }

        if (!prefetchRanges.empty()) {
            scheduler_.PrefetchBlocks(prefetchRanges.data(), prefetchRanges.size());
        }
    }

    /**
     * Evict tensors whose next-use distance makes them safe to evict.
     * Uses the next-use policy to select Belady-optimal victims.
     */
    void EvictAsNeeded(size_t needHostBytes, size_t needDeviceBytes) {
        // Collect evictable candidates
        std::vector<VirtualTensor*> candidates;
        // ... in production, this queries the VirtualTensor table

        size_t freedHost = 0, freedDevice = 0;
        uint32_t victim = eviction_.SelectVictim(
            candidates, needHostBytes, needDeviceBytes,
            freedHost, freedDevice);

        if (victim != UINT32_MAX) {
            scheduler_.Evict(victim);
        }
    }

    /**
     * Get residency counters for the VA-001 certificate.
     */
    struct VaCounters {
        uint64_t romFaults = 0;
        uint64_t nvmeReadBytes = 0;
        uint64_t hostToGpuBytes = 0;
        uint64_t evictBytes = 0;
        uint64_t prefetchHits = 0;
        uint64_t prefetchMisses = 0;
        uint64_t residencyHits = 0;
        uint64_t residencyMisses = 0;
        uint64_t fullDequantBytes = 0;      // Should be 0 for packed residency
        uint64_t hostMaterializations = 0;  // Should be 0
    };

    const VaCounters& Counters() const { return counters_; }

    /**
     * Record a ROM fault (cold load from backing store).
     */
    void RecordRomFault(uint64_t bytes) {
        counters_.romFaults++;
        counters_.nvmeReadBytes += bytes;
    }

    /**
     * Record a GPU transfer.
     */
    void RecordGpuTransfer(uint64_t bytes) {
        counters_.hostToGpuBytes += bytes;
    }

    /**
     * Record an eviction.
     */
    void RecordEvict(uint64_t bytes) {
        counters_.evictBytes += bytes;
    }

    /**
     * Record a full dequantization (should be 0 in packed residency mode).
     */
    void RecordFullDequant(uint64_t bytes) {
        counters_.fullDequantBytes += bytes;
    }

    /**
     * Record a host materialization (should be 0).
     */
    void RecordHostMaterialization() {
        counters_.hostMaterializations++;
    }

    /**
     * Record a residency lookup result.
     */
    void RecordResidencyHit(bool hit) {
        if (hit) counters_.residencyHits++;
        else counters_.residencyMisses++;
    }

    /**
     * Record prefetch statistics.
     */
    void RecordPrefetch(bool hit) {
        if (hit) counters_.prefetchHits++;
        else counters_.prefetchMisses++;
    }

private:
    /**
     * Find tensor IDs referenced by a specific IR op.
     * In the full implementation, this indexes into kExecutionIRTable.
     * For the standalone VWA module, we accept an externally-provided
     * function that maps opId -> tensorIds.
     */
    std::vector<uint32_t> FindTensorsForOp(uint32_t opId) {
        // Placeholder: in the engine, this queries kExecutionIRTable[opId]
        // and extracts RomTensor operand IDs.
        return std::vector<uint32_t>{};
    }

    VwaScheduler& scheduler_;
    const IrNextUseIndex* irIndex_;
    NextUseEvictionPolicy eviction_;

    PrefetchConfig config_;
    std::atomic<uint32_t> currentOp_;
    std::atomic<uint32_t> tokenOpBase_;   // Op index of current token's start
    uint32_t opCount_ = 300;
    uint32_t tokenStride_ = 300;          // Number of ops per token pass

    VaCounters counters_{};
};

} // namespace vwa
} // namespace Deep2
