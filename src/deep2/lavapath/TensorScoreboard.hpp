#pragma once
/* TensorScoreboard — CAS residency + recycle; LIVE=0. ≤99.
   GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 INVERSION_LOCKED=1. */
#include "ScoreboardTypes.hpp"
#include "ScoreboardRing.hpp"
#include "WindowPool.hpp"

namespace Deep2 {
namespace scoreboard {

struct TensorScoreboard {
    static constexpr uint32_t kCap = 4096;
    static constexpr uint32_t kQ = 1024;
    TensorScore desc[kCap]{};
    uint32_t n = 0;
    WindowPool* ramPool = nullptr;
    LockFreeRing<TensorId, kQ> ioQ{}, ramQ{}, gpuQ{}, readyQ{}, execQ{}, retireQ{};

    int bind(uint32_t count, WindowPool* ram) {
        if (!count || count > kCap) return 0;
        n = count; ramPool = ram; return 1;
    }

    int initTensor(TensorId id, uint64_t off, uint64_t bytes, uint32_t first,
                   uint32_t last, uint32_t consumers, DeviceId dev) {
        if (id >= n) return 0;
        TensorScore& t = desc[id];
        t.id = id; t.backingOffset = off; t.backingBytes = bytes;
        t.firstUse = first; t.lastUse = last;
        t.consumersRemaining.store(consumers, std::memory_order_relaxed);
        t.state.store((uint32_t)ResidencyState::Absent, std::memory_order_relaxed);
        t.preferredDevice = t.currentDevice = dev;
        t.ramWindow = t.gpuWindow = nullptr;
        return 1;
    }

    int transition(TensorId id, ResidencyState expect, ResidencyState next) {
        if (id >= n) return 0;
        uint32_t cur = (uint32_t)expect;
        if (!desc[id].state.compare_exchange_strong(
                cur, (uint32_t)next, std::memory_order_acq_rel,
                std::memory_order_relaxed))
            return 0;
        if (next == ResidencyState::IoPending) ioQ.push(id);
        else if (next == ResidencyState::RamReady) ramQ.push(id);
        else if (next == ResidencyState::GpuPending) gpuQ.push(id);
        else if (next == ResidencyState::GpuReady) readyQ.push(id);
        else if (next == ResidencyState::Executing) execQ.push(id);
        else if (next == ResidencyState::Retired) retireQ.push(id);
        return 1;
    }

    int enqueueIo(TensorId id) {
        if (id >= n || !ramPool) return 0;
        PhysicalWindow* w = ramPool->acquire();
        if (!w) return 0;
        desc[id].ramWindow = w;
        if (!transition(id, ResidencyState::Absent, ResidencyState::IoPending)) {
            ramPool->release(w); desc[id].ramWindow = nullptr; return 0;
        }
        return 1;
    }

    int onConsumerDone(TensorId id) {
        if (id >= n) return 0;
        const uint32_t prev =
            desc[id].consumersRemaining.fetch_sub(1, std::memory_order_acq_rel);
        if (prev != 1) return 1;
        if (!transition(id, ResidencyState::Executing, ResidencyState::Retired))
            return 0;
        if (desc[id].ramWindow && ramPool) {
            ramPool->release(desc[id].ramWindow);
            desc[id].ramWindow = nullptr;
        }
        return 1;
    }

    int pollIo(TensorId& o) { return ioQ.pop(o); }
    int pollRam(TensorId& o) { return ramQ.pop(o); }
    int pollGpu(TensorId& o) { return gpuQ.pop(o); }
    int pollReady(TensorId& o) { return readyQ.pop(o); }
    int pollRetire(TensorId& o) { return retireQ.pop(o); }
    TensorScore* get(TensorId id) { return id < n ? &desc[id] : nullptr; }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
