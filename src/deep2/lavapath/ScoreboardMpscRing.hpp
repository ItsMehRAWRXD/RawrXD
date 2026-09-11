#pragma once
/* ScoreboardMpscRing — MPSC: claim-tail, write, publish ready bit. ≤99. */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

template <typename T, uint32_t Cap>
struct MpscRing {
    struct Slot {
        T v{};
        std::atomic<uint32_t> ready{0};
    };
    Slot slot[Cap]{};
    alignas(64) std::atomic<uint32_t> head{0};
    alignas(64) std::atomic<uint32_t> claim{0};

    int push(T v) {
        for (;;) {
            uint32_t t = claim.load(std::memory_order_relaxed);
            const uint32_t n = (t + 1u) % Cap;
            if (n == head.load(std::memory_order_acquire))
                return 0;
            if (!claim.compare_exchange_weak(t, n, std::memory_order_acq_rel,
                                             std::memory_order_relaxed))
                continue;
            slot[t].v = v;
            slot[t].ready.store(1, std::memory_order_release);
            return 1;
        }
    }

    int pop(T& out) {
        const uint32_t h = head.load(std::memory_order_relaxed);
        if (!slot[h].ready.load(std::memory_order_acquire))
            return 0;
        out = slot[h].v;
        slot[h].ready.store(0, std::memory_order_release);
        head.store((h + 1u) % Cap, std::memory_order_release);
        return 1;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
