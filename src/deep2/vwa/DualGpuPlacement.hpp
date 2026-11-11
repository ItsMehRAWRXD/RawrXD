//=============================================================================
// DualGpuPlacement.hpp — Cost-weighted tensor placement across dual-GPU
//
// Topology:
//   GPU 0: Radeon AI PRO R9700  32 GB VRAM
//   GPU 1: Radeon RX 7800 XT    16 GB VRAM  (half-height, lower bandwidth)
//   Host:  64 GB DDR5           (separate bandwidth domain)
//   Interconnect: PCIe x16 Gen5 (0→1), separate NUMA nodes
//
// Placement goal:
//   Minimize HOST_TO_GPU_BYTES_PER_TOKEN + sync cost,
//   by placing tensors that are consumed together on the same GPU,
//   and leveraging the larger R9700 for heavy weight tensors.
//
// Cost model:
//   cost(p) = transferBytes(p) * bandwidthPenalty(p)
//             + syncCost(p)
//   where:
//     transferBytes(p) = bytes needed to bring tensor p into GPU mem
//     bandwidthPenalty(p) = 1.0 on GPU 0, 1.5 on GPU 1 (lower BW)
//                         = 2.0 from host to GPU (PCIe bottleneck)
//     syncCost(p) = if p changes GPU between consecutive ops, syncPenalty
//=============================================================================

#pragma once
#include "../QuantTypeTable.hpp"
#include "VwaTypes.hpp"
#include "VirtualTensor.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <algorithm>
#include <string>

namespace Deep2 {
namespace vwa {

struct GpuDeviceDesc {
    uint32_t id = 0;           // 0 = R9700, 1 = 7800 XT
    uint64_t vramBytes = 0;    // Total VRAM
    uint64_t vramUsed = 0;     // Currently used (resident tensors)
    double   bandwidthScore = 1.0; // 1.0 = best, higher = slower
    std::string name;
};

/**
 * Cost model for evaluating tensor placement decisions.
 *
 * The scheduler calls EvaluatePlacement() for each tensor before fetching
 * into a GPU, and selects the GPU with the lowest cost.
 */
class DualGpuPlacer {
public:
    static constexpr uint32_t kGpuCount = 2;
    static constexpr uint32_t kGpu0 = 0;  // R9700 primary
    static constexpr uint32_t kGpu1 = 1;  // 7800 XT secondary

    struct PlacementCost {
        uint32_t gpu = 0;
        double   totalCost = 0.0;
        double   transferCost = 0.0;
        double   syncCost = 0.0;
        size_t   tensorBytes = 0;
        bool     capacityExceeded = false;
    };

    /**
     * Cost factors (tunable).
     *   - hostToGpuPenalty: host → GPU transfer is ~2x slower than GPU-local
     *   - gpu1BandwidthPenalty: GPU 1 (7800 XT) has ~1.5x lower memory BW
     *   - gpuCrossSyncPenalty: moving tensors between GPUs triggers PCIe sync
     */
    struct CostFactors {
        double hostToGpuPenalty = 2.0;
        double gpu1BandwidthPenalty = 1.5;
        double interGpuSyncPenalty = 1000.0;       // sync stall cost (arbitrary units)
        double evictionPenalty = 0.5;             // cost of evicting + reloading later
        double prefetchBenefit = 0.3;             // benefit of prefetch hit (reduces sync)
    };

    DualGpuPlacer() = default;
    explicit DualGpuPlacer(std::array<GpuDeviceDesc, kGpuCount> gpus)
        : gpus_(gpus) {}

    void SetDevices(const std::array<GpuDeviceDesc, kGpuCount>& gpus) {
        gpus_ = gpus;
    }

    void SetFactors(const CostFactors& f) { factors_ = f; }
    const CostFactors& Factors() const { return factors_; }

    /**
     * Evaluate placement cost for a tensor on each GPU.
     *
     * @param tensor The VirtualTensor to evaluate.
     * @param currentGpu GPU where tensors were last accessed (for sync cost).
     *                   UINT32_MAX if not yet on any GPU.
     * @param alreadyResidentGpu GPU where the tensor is already resident
     *                           (UINT32_MAX if not resident on any GPU).
     * @param activationBytes Expected compute activation size (affects bandwidth).
     * @param prefetchHit Whether the tensor is already prefetched to host staging.
     *
     * @return PlacementCost for each GPU; caller picks the lowest totalCost.
     */
    std::array<PlacementCost, kGpuCount> EvaluatePlacement(
        const VirtualTensor& tensor,
        uint32_t currentGpu,
        uint32_t alreadyResidentGpu,
        size_t activationBytes,
        bool prefetchHit) const
    {
        std::array<PlacementCost, kGpuCount> costs{};

        for (uint32_t g = 0; g < kGpuCount; ++g) {
            auto& c = costs[g];
            c.gpu = g;
            c.tensorBytes = tensor.encodedBytes;

            // --- Transfer cost ---
            // If not already resident on this GPU, pay transfer cost
            if (alreadyResidentGpu != g) {
                double bwPenalty = (g == kGpu0) ? 1.0 : factors_.gpu1BandwidthPenalty;

                if (tensor.tier.load(std::memory_order_acquire) <= ResidencyTier::Cold ||
                    tensor.gpu.load(std::memory_order_acquire) == UINT32_MAX) {
                    // Must transfer from host (ROM-mapped) to GPU
                    c.transferCost = static_cast<double>(tensor.encodedBytes) *
                                     factors_.hostToGpuPenalty * bwPenalty;
                } else {
                    // Already on host RAM, transfer from host to GPU
                    c.transferCost = static_cast<double>(tensor.encodedBytes) *
                                     factors_.hostToGpuPenalty * bwPenalty;
                }

                if (prefetchHit) {
                    c.transferCost *= (1.0 - factors_.prefetchBenefit);
                }
            } else {
                // Already on this GPU — transfer cost is paid on host→GPU bandwidth
                // if we're pulling from host staging to GPU
                c.transferCost = 0.0; // already resident on GPU
            }

            // --- Sync cost ---
            // If this is on a different GPU than the current compute context,
            // we pay a sync penalty.
            if (currentGpu != UINT32_MAX && currentGpu != g) {
                c.syncCost = factors_.interGpuSyncPenalty;
            }

            // --- Capacity check ---
            uint64_t futureUsed = gpus_[g].vramUsed + tensor.encodedBytes;
            c.capacityExceeded = futureUsed > gpus_[g].vramBytes;

            // --- Total ---
            c.totalCost = c.transferCost + c.syncCost;
            if (c.capacityExceeded) {
                c.totalCost += 1e9; // penalize beyond capacity
            }
        }
        return costs;
    }

    /**
     * Select the optimal GPU for a tensor placement.
     *
     * @return GPU index with the lowest total cost, or UINT32_MAX if
     *         no GPU has capacity.
     */
    uint32_t SelectGpu(const VirtualTensor& tensor,
                       uint32_t currentGpu,
                       uint32_t alreadyResidentGpu,
                       size_t activationBytes,
                       bool prefetchHit) const
    {
        auto costs = EvaluatePlacement(tensor, currentGpu, alreadyResidentGpu,
                                        activationBytes, prefetchHit);

        uint32_t bestGpu = UINT32_MAX;
        double bestCost = 0.0;
        bool first = true;

        for (uint32_t g = 0; g < kGpuCount; ++g) {
            if (costs[g].capacityExceeded) continue;
            if (first || costs[g].totalCost < bestCost) {
                bestGpu = g;
                bestCost = costs[g].totalCost;
                first = false;
            }
        }

        return bestGpu;
    }

    /**
     * Estimate total bytes transferred from host to GPU for a token.
     * Used by the VA-001 gate to verify HOST_TO_GPU_BYTES_PER_TOKEN is bounded.
     */
    size_t EstimateHostToGpuBytesPerToken(const std::vector<VirtualTensor*>& tensors,
                                          const std::vector<uint32_t>& requiredTensorIds) const
    {
        size_t total = 0;
        for (uint32_t tid : requiredTensorIds) {
            for (const auto* t : tensors) {
                if (t->tensorId == tid) {
                    // Only count bytes if not already resident on the target GPU
                    if (t->gpu.load(std::memory_order_acquire) == UINT32_MAX ||
                        t->tier.load(std::memory_order_acquire) == ResidencyTier::Cold) {
                        total += t->encodedBytes;
                    }
                    break;
                }
            }
        }
        return total;
    }

    /**
     * Get bandwidth-penalized transfer cost for a tensor.
     * This is the value reported in HOST_TO_GPU_BYTES_PER_TOKEN accounting.
     */
    double ComputeHostToGpuWeightedBytes(const VirtualTensor& tensor,
                                        uint32_t targetGpu,
                                        bool prefetchHit) const
    {
        double bwPenalty = (targetGpu == kGpu0) ? 1.0 : factors_.gpu1BandwidthPenalty;
        double effectiveBytes = static_cast<double>(tensor.encodedBytes);

        if (prefetchHit) {
            effectiveBytes *= (1.0 - factors_.prefetchBenefit);
        }
        effectiveBytes *= factors_.hostToGpuPenalty * bwPenalty;

        return effectiveBytes;
    }

    /**
     * Recommend which tensors should be pinned to the larger GPU (R9700)
     * because they're needed every token step (shared attention norm,
     * embeddings, etc.).
     */
    std::vector<uint32_t> RecommendPinnedTensors(const std::vector<VirtualTensor*>& tensors) const
    {
        std::vector<uint32_t> pinned;
        for (const auto* t : tensors) {
            if (!t) continue;
            // Shared/norm tensors that are needed every op should go on GPU 0
            // (larger VRAM, primary bandwidth path).
            // Heuristic: small tensors, dense (non-expert) type
            if (t->expertCount == 0 && t->encodedBytes <= 128 * 1024 * 1024) {
                pinned.push_back(t->tensorId);
            }
        }
        return pinned;
    }

private:
    std::array<GpuDeviceDesc, kGpuCount> gpus_{};
    CostFactors factors_{};
};

} // namespace vwa
} // namespace Deep2
