#pragma once
/* WindowPool — circulating PhysicalWindow free stack. ≤99. */
#include "ScoreboardTypes.hpp"

namespace Deep2 {
namespace scoreboard {

struct WindowPool {
    static constexpr uint32_t kMax = 64;
    PhysicalWindow win[kMax]{};
    uint32_t freeStack[kMax]{};
    uint32_t nFree = 0;
    uint32_t n = 0;
    DeviceId deviceId = -1;

    int init(uint32_t count, uint64_t bytes, DeviceId dev) {
        if (!count || count > kMax)
            return 0;
        n = count;
        nFree = count;
        deviceId = dev;
        for (uint32_t i = 0; i < count; ++i) {
            win[i].windowId = i;
            win[i].deviceId = dev;
            win[i].capacityBytes = bytes;
            win[i].allocatedBytes.store(0, std::memory_order_relaxed);
            win[i].locked.store(0, std::memory_order_relaxed);
            win[i].base = nullptr;
            freeStack[i] = i;
        }
        return 1;
    }

    PhysicalWindow* acquire() {
        if (!nFree)
            return nullptr;
        const uint32_t id = freeStack[--nFree];
        win[id].locked.store(1, std::memory_order_release);
        return &win[id];
    }

    void release(PhysicalWindow* w) {
        if (!w || w->windowId >= n)
            return;
        w->allocatedBytes.store(0, std::memory_order_relaxed);
        w->locked.store(0, std::memory_order_release);
        freeStack[nFree++] = w->windowId;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
