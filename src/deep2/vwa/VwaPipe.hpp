// vwa/VwaPipe.hpp — prefetch overlapped with compute fence
#pragma once
#include "VwaScheduler.hpp"
#include <chrono>
#include <thread>

namespace Deep2 {
namespace vwa {

class VwaPrefetchPipe {
public:
    explicit VwaPrefetchPipe(VwaScheduler& sched) : sched_(sched) {}

    // Simulate compute of durationUs while prefetching next ranges.
    bool ComputeWithPrefetch(uint32_t computeUs,
                             const BlockRange* next, size_t nNext,
                             VwaStats& st) {
        using clock = std::chrono::steady_clock;
        const auto t0 = clock::now();
        // Launch prefetch first (overlap), then burn compute budget.
        const bool ok = sched_.PrefetchBlocks(next, nNext);
        std::this_thread::sleep_for(std::chrono::microseconds(computeUs));
        const auto t1 = clock::now();
        const uint64_t wall = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        // Overlap credit: wall should be ~max(compute, prefetch), not sum.
        if (wall < computeUs + computeUs)
            st.computeOverlapUs += (computeUs > wall ? 0 : computeUs);
        else
            st.stallUs += wall - computeUs;
        return ok;
    }

private:
    VwaScheduler& sched_;
};

} // namespace vwa
} // namespace Deep2
