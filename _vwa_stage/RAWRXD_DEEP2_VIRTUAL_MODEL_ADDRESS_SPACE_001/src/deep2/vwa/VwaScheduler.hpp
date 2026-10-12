// VwaScheduler.hpp — same VWA authority; per-range and per-IR-op leases
#pragma once
#include "VwaCoalesce.hpp"
#include "VwaDma.hpp"
#include "VwaIrResidency.hpp"
#include "VwaSpace.hpp"
#include <chrono>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace Deep2 { namespace vwa {
class VwaScheduler {
public:
    explicit VwaScheduler(VwaSpace& space) : space_(space) {}
    ~VwaScheduler();
    VwaScheduler(const VwaScheduler&) = delete;
    VwaScheduler& operator=(const VwaScheduler&) = delete;
    void SetBudget(VwaBudget b) { budget_ = b; }
    const VwaStats& Stats() const { return stats_; }
    VwaBudget& Budget() { return budget_; }
    DmaStage& Dma() { return dma_; }
    template <typename OperationIR> bool BindIR(const OperationIR* ops, size_t n) {
        if (!nextUse_.Build(ops, n)) return false;
        currentOp_ = 0;
        stats_.logicalModelBytes = space_.LogicalBytes();
        space_.ForEach([&](VirtualTensor& r) {
            r.refCount = nextUse_.RefCount(r.desc.id);
            r.nextUseOp = nextUse_.NextUseOp(r.desc.id, 0);
        });
        return true;
    }
    const IrNextUseIndex& IR() const { return nextUse_; }
    bool RequestBlocks(const BlockRange* ranges, size_t n);
    bool PrefetchBlocks(const BlockRange* ranges, size_t n);
    bool AcquireBlocks(const BlockRange& br, void*& outDevice, uint32_t& generation);
    bool Release(TensorId id);
    bool Pin(TensorId id);
    bool Evict(TensorId id);
    bool EvictToMakeRoom(size_t needHost, size_t needDevice);
    // Optional conditional expert ranges supplied AFTER router top-k selection.
    // Unknown expert choice is an error, NOT permission to load all experts.
    bool PrepareOp(uint32_t op, const BlockRange* selectedExperts,
                   size_t nSelected, std::vector<OpLease>& out);
    bool ReleaseOp(std::vector<OpLease>& leases);
    bool PrefetchAhead(uint32_t afterOp, uint32_t depth);
private:
    struct LeaseKey { uint32_t first = 0, count = 0, generation = 0; };
    bool Fulfill(const std::vector<PhysicalRange>& ranges, bool prefetch);
    ResidentRange* FindCover(VirtualTensor& r, BlockRange br);
    bool EvictRange(VirtualTensor& r, uint32_t first, uint32_t generation);
    bool HasRoom(size_t host, size_t device) const {
        return host <= budget_.maxHostBytes - (std::min)(budget_.maxHostBytes, budget_.usedHost) &&
               device <= budget_.maxDeviceBytes - (std::min)(budget_.maxDeviceBytes, budget_.usedDevice);
    }
    uint64_t NowUs() const {
        using clock = std::chrono::steady_clock;
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                    clock::now().time_since_epoch()).count());
    }
    VwaSpace& space_;
    VwaBudget budget_{};
    VwaStats stats_{};
    DmaStage dma_{};
    IrNextUseIndex nextUse_{};
    uint32_t currentOp_ = 0;
    uint64_t seq_ = 1;
    uint32_t rangeGeneration_ = 1;
    std::unordered_map<TensorId, std::vector<LeaseKey>> liveLeases_;
};
// View into the canonical scheduler, not a second cache or admission system.
class IrPrefetchPipeline {
public:
    explicit IrPrefetchPipeline(VwaScheduler& scheduler) : scheduler_(scheduler) {}
    bool PrefetchAhead(uint32_t op, uint32_t depth) {
        return scheduler_.PrefetchAhead(op, depth);
    }
private:
    VwaScheduler& scheduler_;
};
} }
