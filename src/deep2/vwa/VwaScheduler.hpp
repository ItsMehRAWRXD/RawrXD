// vwa/VwaScheduler.hpp — RequestBlocks / Acquire / Prefetch / Evict
#pragma once
#include "VwaCoalesce.hpp"
#include "VwaDma.hpp"
#include "VwaSpace.hpp"
#include <chrono>
#include <cstdlib>
#include <vector>

namespace Deep2 {
namespace vwa {

class VwaScheduler {
public:
    explicit VwaScheduler(VwaSpace& space) : space_(space) {}

    void SetBudget(VwaBudget b) { budget_ = b; }
    const VwaStats& Stats() const { return stats_; }
    VwaBudget& Budget() { return budget_; }
    DmaStage& Dma() { return dma_; }

    bool RequestBlocks(const BlockRange* ranges, size_t n);
    bool PrefetchBlocks(const BlockRange* ranges, size_t n);
    bool AcquireBlocks(const BlockRange& br, void*& outDevice, uint32_t& gen);
    bool Release(TensorId id);
    bool Pin(TensorId id);
    bool Evict(TensorId id);
    bool EvictToMakeRoom(size_t needHost, size_t needDevice);

private:
    bool Fulfill(const std::vector<PhysicalRange>& phys, bool isPrefetch);
    bool EnsureHost(VirtualTensorRef& r);
    bool EnsureDevice(VirtualTensorRef& r);
    uint64_t NowUs() const {
        using clock = std::chrono::steady_clock;
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                clock::now().time_since_epoch()).count());
    }

    VwaSpace& space_;
    VwaBudget budget_{};
    VwaStats stats_{};
    DmaStage dma_{};
    uint64_t seq_ = 1;
};

} // namespace vwa
} // namespace Deep2
