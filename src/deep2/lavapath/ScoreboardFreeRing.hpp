#pragma once
/* ScoreboardFreeRing — bounded free-ring for window/slot IDs. ≤99. */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

template <uint32_t Cap>
struct ScoreboardFreeRing {
    uint32_t slot[Cap]{};
    std::atomic<uint32_t> head{0};
    std::atomic<uint32_t> tail{0};
    uint32_t n = 0;

    int init(uint32_t count) noexcept {
        if (!count || count > Cap)
            return 0;
        n = count;
        head.store(0, std::memory_order_relaxed);
        tail.store(count, std::memory_order_relaxed);
        for (uint32_t i = 0; i < count; ++i)
            slot[i] = i;
        return 1;
    }

    int acquire(uint32_t& out) noexcept {
        for (;;) {
            uint32_t h = head.load(std::memory_order_relaxed);
            uint32_t t = tail.load(std::memory_order_acquire);
            if (h == t)
                return 0;
            uint32_t v = slot[h % Cap];
            if (head.compare_exchange_weak(h, h + 1, std::memory_order_acq_rel,
                                           std::memory_order_relaxed)) {
                out = v;
                return 1;
            }
        }
    }

    int release(uint32_t id) noexcept {
        for (;;) {
            uint32_t t = tail.load(std::memory_order_relaxed);
            uint32_t h = head.load(std::memory_order_acquire);
            if ((t - h) >= n)
                return 0;
            slot[t % Cap] = id;
            if (tail.compare_exchange_weak(t, t + 1, std::memory_order_acq_rel,
                                           std::memory_order_relaxed))
                return 1;
        }
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
