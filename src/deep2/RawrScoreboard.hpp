// RawrScoreboard.hpp — READY execute; missing issue; no space reclaim.
#pragma once
#include "RawrNoTpResidency.hpp"
#include <atomic>
#include <cstdint>

namespace Deep2 {

struct TensorReady {
    std::atomic<bool> ready{false};
    std::atomic<bool> failed{false};
    WeightLease lease{};
};

struct TensorLife {
    std::atomic<uint32_t> consumersRemaining{1};
    WeightLease lease{};
};

inline void completeConsumer(TensorLife& t) {
    if (t.consumersRemaining.fetch_sub(1, std::memory_order_acq_rel) == 1)
        t.lease.bytes = nullptr;
}

struct KvPage {
    uint32_t layer = 0;
    uint32_t sequence = 0;
    uint32_t tokenBegin = 0;
    uint32_t tokenCount = 0;
    uint64_t bytes = 0;
    bool hot = false;
};

struct ScoreboardOp {
    uint32_t layer = 0;
    RawrWorkingSet workingSet{};
    int runnable = 0;
};

inline std::atomic<uint32_t>& RawrScoreboardTicks() {
    static std::atomic<uint32_t> n{0};
    return n;
}

inline void RawrScoreboardNoteExecute() {
    RawrScoreboardTicks().fetch_add(1, std::memory_order_relaxed);
}

inline int RawrReclaimUntilFits(RawrWorkingSet& miss, RawrSpaceState& space,
                                uint64_t (*evictLastUse)(),
                                uint64_t (*evictColdKv)()) {
    int steps = 0;
    while (!RawrSpaceSufficient(miss, space) && steps < 8) {
        if (evictLastUse) space.reclaimableBytes += evictLastUse();
        if (evictColdKv) {
            const uint64_t dropped = evictColdKv();
            if (space.occupiedBytes > dropped) space.occupiedBytes -= dropped;
            else space.occupiedBytes = 0;
            if (miss.kvHotBytes > dropped) miss.kvHotBytes -= dropped;
        }
        ++steps;
    }
    return RawrSpaceSufficient(miss, space) ? 1 : 0;
}

} // namespace Deep2
