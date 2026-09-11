#pragma once
/* VulkanDispatchBridge — fence pool acquire/submit/poll/wait. LIVE=0. ≤99. */
#include "ScoreboardTypes.hpp"
#include "VulkanDispatchFns.hpp"
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct FenceSlot {
    VkFenceOpaque fence = nullptr;
    std::atomic<uint32_t> busy{0};
    uint64_t seq = 0;
};

struct VulkanDispatchBridge {
    static constexpr uint32_t kFences = 64;
    VkDispatchFns fn{};
    FenceSlot pool[kFences]{};
    std::atomic<uint64_t> nextSeq{1};

    int bind(const VkDispatchFns& f) {
        if (!f.device || !f.createFence || !f.waitFences || !f.queueSubmit)
            return 0;
        fn = f;
        for (uint32_t i = 0; i < kFences; ++i) {
            VkFenceOpaque out = nullptr;
            if (fn.createFence(fn.device, &out, fn.ud) != 0 || !out)
                return 0;
            pool[i].fence = out;
            pool[i].busy.store(0, std::memory_order_relaxed);
        }
        return 1;
    }

    int acquire(uint32_t& slotOut, uint64_t& seqOut) {
        for (uint32_t i = 0; i < kFences; ++i) {
            uint32_t exp = 0;
            if (!pool[i].busy.compare_exchange_strong(
                    exp, 1, std::memory_order_acq_rel, std::memory_order_relaxed))
                continue;
            if (fn.resetFences)
                (void)fn.resetFences(fn.device, 1, &pool[i].fence, fn.ud);
            seqOut = nextSeq.fetch_add(1, std::memory_order_relaxed);
            pool[i].seq = seqOut;
            slotOut = i;
            return 1;
        }
        return 0;
    }

    int submit(uint32_t slot, void* submitInfo, uint32_t n) {
        if (slot >= kFences || !pool[slot].busy.load(std::memory_order_acquire))
            return 0;
        return fn.queueSubmit(fn.queue, n, submitInfo, pool[slot].fence, fn.ud) == 0
                   ? 1
                   : 0;
    }

    int poll(uint32_t slot) {
        if (slot >= kFences || !fn.getFenceStatus)
            return 0;
        return fn.getFenceStatus(fn.device, pool[slot].fence, fn.ud) == 0 ? 1 : 0;
    }

    int wait(uint32_t slot, uint64_t timeoutNs) {
        if (slot >= kFences)
            return 0;
        return fn.waitFences(fn.device, 1, &pool[slot].fence, 1, timeoutNs, fn.ud) == 0
                   ? 1
                   : 0;
    }

    void release(uint32_t slot) {
        if (slot < kFences)
            pool[slot].busy.store(0, std::memory_order_release);
    }

    int armToken(HwToken& tok, uint32_t slot) {
        if (slot >= kFences)
            return 0;
        tok.native = pool[slot].fence;
        tok.fence.store(pool[slot].seq, std::memory_order_release);
        tok.done.store(0, std::memory_order_release);
        return 1;
    }

    int completeToken(HwToken& tok, uint32_t slot) {
        if (!poll(slot))
            return 0;
        tok.done.store(1, std::memory_order_release);
        release(slot);
        return 1;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
