#pragma once
/* ScoreboardRing — SPSC tip ring. ≤99. */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

template <typename T, uint32_t Cap>
struct LockFreeRing {
    T buf[Cap]{};
    alignas(64) std::atomic<uint32_t> head{0};
    alignas(64) std::atomic<uint32_t> tail{0};

    int push(T v) {
        const uint32_t t = tail.load(std::memory_order_relaxed);
        const uint32_t n = (t + 1u) % Cap;
        if (n == head.load(std::memory_order_acquire))
            return 0;
        buf[t] = v;
        tail.store(n, std::memory_order_release);
        return 1;
    }

    int pop(T& out) {
        const uint32_t h = head.load(std::memory_order_relaxed);
        if (h == tail.load(std::memory_order_acquire))
            return 0;
        out = buf[h];
        head.store((h + 1u) % Cap, std::memory_order_release);
        return 1;
    }

    int empty() const {
        return head.load(std::memory_order_relaxed) ==
               tail.load(std::memory_order_relaxed);
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
