//=============================================================================
// NextUseEvictionPolicy.hpp — Belady-style optimal eviction for virtual tensors
//
// Uses kExecutionIRTable to determine which tensor's next use is farthest
// in the future, rather than relying on LRU. The execution order is known
// statically from the IR, enabling near-optimal cache replacement.
//
// For repeated decode, the IR table is treated as circular with a token
// stride equal to the number of ops per token (currently 300).
//=============================================================================

#pragma once
#include "VirtualTensor.hpp"
#include "VwaTypes.hpp"
#include <cstdint>
#include <vector>
#include <algorithm>
#include <atomic>

namespace Deep2 {
namespace vwa {

/**
 * Execution-IR forward-reference lookup.
 *
 * Precomputed from kExecutionIRTable at model load time:
 *   - For each tensorId, sorted list of IR op indices that reference it.
 *   - tokenStride: number of IR ops per decode pass (300 for this model).
 *
 * This enables O(1) next-use distance queries during eviction selection.
 */
class IrNextUseIndex {
public:
    void Build(uint32_t tensorCount, uint32_t opCount, uint32_t tokenStride,
               const std::vector<std::pair<uint32_t, uint32_t>>& tensorRefs) {
        tensorCount_ = tensorCount;
        opCount_ = opCount;
        tokenStride_ = tokenStride;

        // Build per-tensor sorted ref lists
        refs_.assign(tensorCount, std::vector<uint32_t>{});
        for (const auto& [tensorId, opId] : tensorRefs) {
            if (tensorId < tensorCount && opId < opCount) {
                refs_[tensorId].push_back(opId);
            }
        }
        // Sort each tensor's ref list
        for (auto& list : refs_) {
            std::sort(list.begin(), list.end());
        }
    }

    /**
     * Compute the IR distance (number of ops) until tensorId is next used,
     * given the current op cursor.
     *
     * Circular decode model: if the next use is in a later token repetition,
     * the distance wraps from (opCount - currentOp) + nextUseOp + 1.
     */
    uint32_t NextUseDistance(uint32_t tensorId, uint32_t currentOp) const {
        if (tensorId >= tensorCount_) return UINT32_MAX;
        const auto& list = refs_[tensorId];
        if (list.empty()) return UINT32_MAX; // Never used again — evict first

        // Find first ref > currentOp
        auto it = std::upper_bound(list.begin(), list.end(), currentOp);
        if (it != list.end()) {
            // Next use in current token pass
            return static_cast<uint32_t>(*it - currentOp);
        }
        // Next use is in a future token pass (circular)
        // Distance = (end of this pass - currentOp) + (first use in next pass)
        uint32_t wrapDistance = (opCount_ - currentOp) + list.front();
        return wrapDistance;
    }

    uint32_t TokenStride() const { return tokenStride_; }
    uint32_t OpCount() const { return opCount_; }

    /**
     * Build the index from a generic IR table interface.
     *
     * The table must provide:
     *   - OpCount() → total number of IR ops
     *   - GetTensorIds(opId) → vector of tensor IDs referenced by this op
     *
     * This is the primary construction path used at model load time.
     */
    template <typename IrTable>
    void BuildFromTable(const IrTable& table) {
        uint32_t ops = table.OpCount();
        opCount_ = ops;
        tokenStride_ = ops;  // For this model, token stride == op count

        // Count unique tensors
        uint32_t maxTensorId = 0;
        std::vector<std::pair<uint32_t, uint32_t>> tensorRefs;
        tensorRefs.reserve(ops * 4);

        for (uint32_t i = 0; i < ops; ++i) {
            auto ids = table.GetTensorIds(i);
            for (uint32_t tid : ids) {
                tensorRefs.emplace_back(tid, i);
                if (tid > maxTensorId) maxTensorId = tid;
            }
        }

        tensorCount_ = maxTensorId + 1;
        Build(tensorCount_, ops, tokenStride_, tensorRefs);
    }

private:
    uint32_t tensorCount_ = 0;
    uint32_t opCount_ = 0;
    uint32_t tokenStride_ = 0;
    std::vector<std::vector<uint32_t>> refs_;
};

/*---------------------------------------------------------------------------
 * NextUseEvictionPolicy
 *
 * Selects the eviction victim as the resident-but-evictable tensor with the
 * greatest next-use distance. This approximates Belady's optimal algorithm
 * for the static portion of the workload.
 *
 * For circular decode (repeated tokens), tensors whose next use wraps to
 * the next token pass get a large distance, which is still correct — they
 * won't be needed until the next full pass.
 *---------------------------------------------------------------------------*/
class NextUseEvictionPolicy {
public:
    explicit NextUseEvictionPolicy(const IrNextUseIndex* irIndex)
        : irIndex_(irIndex) {
        // currentOp_ is updated each token iteration by the dispatcher.
        currentOp_.store(0, std::memory_order_relaxed);
    }

    void SetCurrentOp(uint32_t op) noexcept {
        currentOp_.store(op, std::memory_order_release);
    }

    /**
     * Select a victim from the eviction candidate list.
     *
     * Scans all evictable tensors and returns the tensorId whose next use
     * is farthest. This is O(candidates) but typically called only when
     * a budget miss occurs (not per-tensor per-op).
     *
     * Returns UINT32_MAX if no evictable candidate exists.
     */
    uint32_t SelectVictim(
        const std::vector<VirtualTensor*>& candidates,
        size_t needHostBytes,
        size_t needDeviceBytes,
        size_t& evictedHostBytes,
        size_t& evictedDeviceBytes) const
    {
        uint32_t bestId = UINT32_MAX;
        uint32_t bestDistance = 0;
        size_t freedHost = 0, freedDevice = 0;

        const uint32_t curOp = currentOp_.load(std::memory_order_acquire);

        for (auto* t : candidates) {
            if (!t || !t->CanEvict()) continue;

            uint32_t dist = irIndex_ ? irIndex_->NextUseDistance(t->tensorId, curOp) : UINT32_MAX;

            // Greedy: pick farthest next-use that satisfies the byte request.
            // For simplicity, pick the single best victim that frees the most
            // bytes per distance (bytes / (1 + distance) ratio).
            size_t bytes = t->hostBytes > 0 ? t->hostBytes : t->deviceBytes;
            if (bytes == 0) continue;

            double costEfficiency = static_cast<double>(bytes) / (1.0 + static_cast<double>(dist));

            if (costEfficiency > static_cast<double>(bestDistance) / (1.0 + 1.0)) {
                // Prefer high distance AND high byte count
                // Use a composite key: prioritize distance first for Belady,
                // but among similar distances prefer larger tensors
                if (dist > bestDistance || (dist == bestDistance && bytes > freedHost + freedDevice)) {
                    bestDistance = dist;
                    bestId = t->tensorId;
                    freedHost = t->hostBytes;
                    freedDevice = t->deviceBytes;
                }
            }
        }

        // If we haven't satisfied the request with the single best victim,
        // keep scanning for additional victims with large distances.
        if ((freedHost < needHostBytes || freedDevice < needDeviceBytes) &&
            bestId != UINT32_MAX) {
            // Second pass: collect additional victims in descending distance order
            // until budget is satisfied or candidates exhausted.
            for (auto* t : candidates) {
                if (!t || !t->CanEvict() || t->tensorId == bestId) continue;

                uint32_t dist = irIndex_ ? irIndex_->NextUseDistance(t->tensorId, curOp) : UINT32_MAX;

                // Only evict tensors with distance >= current best
                if (dist >= bestDistance) {
                    if (freedHost + freedDevice >= needHostBytes + needDeviceBytes) break;
                    freedHost += t->hostBytes;
                    freedDevice += t->deviceBytes;
                }
            }
        }

        evictedHostBytes = freedHost;
        evictedDeviceBytes = freedDevice;
        return bestId;
    }

    /**
     * Batch-select eviction victims to free at least needTotalBytes.
     * Returns list of tensor IDs selected for eviction, sorted by
     * descending next-use distance (evict farthest first).
     */
    std::vector<uint32_t> SelectVictimsBatch(
        const std::vector<VirtualTensor*>& candidates,
        size_t needTotalBytes) const
    {
        // Collect evictable candidates with their distances
        struct Cand {
            uint32_t tensorId;
            uint32_t distance;
            size_t bytes;
        };
        std::vector<Cand> cands;
        cands.reserve(candidates.size());

        const uint32_t curOp = currentOp_.load(std::memory_order_acquire);

        for (auto* t : candidates) {
            if (!t || !t->CanEvict()) continue;
            uint32_t dist = irIndex_ ? irIndex_->NextUseDistance(t->tensorId, curOp) : UINT32_MAX;
            size_t bytes = t->hostBytes > 0 ? t->hostBytes : t->deviceBytes;
            if (bytes > 0) {
                cands.push_back({t->tensorId, dist, bytes});
            }
        }

        // Sort by descending distance (Belady: evict farthest next use first)
        std::sort(cands.begin(), cands.end(),
                  [](const Cand& a, const Cand& b) {
                      if (a.distance != b.distance) return a.distance > b.distance;
                      return a.bytes > b.bytes; // tie-break: larger first
                  });

        std::vector<uint32_t> victims;
        size_t accumulated = 0;
        for (const auto& c : cands) {
            victims.push_back(c.tensorId);
            accumulated += c.bytes;
            if (accumulated >= needTotalBytes) break;
        }

        return victims;
    }

private:
    const IrNextUseIndex* irIndex_;
    std::atomic<uint32_t> currentOp_;
};

} // namespace vwa
} // namespace Deep2
