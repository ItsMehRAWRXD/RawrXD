#pragma once
/* ScoreboardAsyncDispatch — fence-armed IO/upload/exec transitions. LIVE=0. ≤99. */
#include "TensorScoreboard.hpp"
#include "VulkanDispatchBridge.hpp"

namespace Deep2 {
namespace scoreboard {

struct ScoreboardAsyncDispatch {
    TensorScoreboard* sb = nullptr;
    VulkanDispatchBridge* vk = nullptr;

    int bind(TensorScoreboard* s, VulkanDispatchBridge* b) {
        if (!s || !b)
            return 0;
        sb = s;
        vk = b;
        return 1;
    }

    /* Arm GPU upload: RamReady -> GpuPending + fence token. */
    int beginUpload(TensorId id, void* submitInfo, uint32_t submitCount,
                    uint32_t& fenceSlot) {
        if (!sb || !vk || id >= sb->n)
            return 0;
        TensorScore& t = sb->desc[id];
        if (!sb->transition(id, ResidencyState::RamReady, ResidencyState::GpuPending))
            return 0;
        uint64_t seq = 0;
        if (!vk->acquire(fenceSlot, seq)) {
            (void)sb->transition(id, ResidencyState::GpuPending, ResidencyState::RamReady);
            return 0;
        }
        if (!vk->armToken(t.upload, fenceSlot)) {
            vk->release(fenceSlot);
            (void)sb->transition(id, ResidencyState::GpuPending, ResidencyState::RamReady);
            return 0;
        }
        if (!vk->submit(fenceSlot, submitInfo, submitCount)) {
            vk->release(fenceSlot);
            t.upload.done.store(0, std::memory_order_relaxed);
            (void)sb->transition(id, ResidencyState::GpuPending, ResidencyState::RamReady);
            return 0;
        }
        return 1;
    }

    int finishUpload(TensorId id, uint32_t fenceSlot, PhysicalWindow* gpuWin) {
        if (!sb || !vk || id >= sb->n)
            return 0;
        TensorScore& t = sb->desc[id];
        if (!vk->completeToken(t.upload, fenceSlot))
            return 0;
        t.gpuWindow = gpuWin;
        return sb->transition(id, ResidencyState::GpuPending, ResidencyState::GpuReady);
    }

    int beginExec(TensorId id, void* submitInfo, uint32_t submitCount,
                  uint32_t& fenceSlot) {
        if (!sb || !vk || id >= sb->n)
            return 0;
        TensorScore& t = sb->desc[id];
        if (!sb->transition(id, ResidencyState::GpuReady, ResidencyState::Executing))
            return 0;
        uint64_t seq = 0;
        if (!vk->acquire(fenceSlot, seq)) {
            (void)sb->transition(id, ResidencyState::Executing, ResidencyState::GpuReady);
            return 0;
        }
        if (!vk->armToken(t.exec, fenceSlot)) {
            vk->release(fenceSlot);
            (void)sb->transition(id, ResidencyState::Executing, ResidencyState::GpuReady);
            return 0;
        }
        if (!vk->submit(fenceSlot, submitInfo, submitCount)) {
            vk->release(fenceSlot);
            (void)sb->transition(id, ResidencyState::Executing, ResidencyState::GpuReady);
            return 0;
        }
        return 1;
    }

    int finishExec(TensorId id, uint32_t fenceSlot) {
        if (!sb || !vk || id >= sb->n)
            return 0;
        return vk->completeToken(sb->desc[id].exec, fenceSlot);
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
