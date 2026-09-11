#pragma once
/* TimelineSubmit — upload/exec queue submit + track. LIVE=0. ≤99. */
#include "TimelineDispatch.hpp"

namespace Deep2 {
namespace scoreboard {

inline int timelineSubmitUpload(TimelineDispatch& d, TensorId id, void* cmds,
                                uint32_t nCmd, TimelineSignal& sig) {
    if (!d.sb || id >= d.sb->n || !d.fn.transferQ)
        return 0;
    TensorScore& t = d.sb->desc[id];
    if (!d.sb->transition(id, ResidencyState::RamReady, ResidencyState::GpuPending))
        return 0;
    sig.value = d.nextVal.fetch_add(1, std::memory_order_relaxed);
    sig.semaphore = d.timeline;
    t.upload.fence.store(sig.value, std::memory_order_release);
    t.upload.done.store(0, std::memory_order_release);
    t.upload.native = d.timeline;
    if (d.fn.queueSubmit(d.fn.transferQ, cmds, nCmd, nullptr, 0, d.timeline,
                         sig.value, d.fn.ud) != 0) {
        (void)d.sb->transition(id, ResidencyState::GpuPending, ResidencyState::RamReady);
        return 0;
    }
    AsyncSubmission sub{id,      sig.value, SyncOp::RamToGpu, ResidencyState::GpuPending,
                        ResidencyState::GpuReady, 0, &t.upload};
    if (!d.track(sub)) {
        (void)d.sb->transition(id, ResidencyState::GpuPending, ResidencyState::RamReady);
        return 0;
    }
    return 1;
}

inline int timelineSubmitExec(TimelineDispatch& d, TensorId id, void* cmds,
                              uint32_t nCmd, uint64_t waitUpload, TimelineSignal& sig) {
    if (!d.sb || id >= d.sb->n || !d.fn.computeQ)
        return 0;
    TensorScore& t = d.sb->desc[id];
    if (!d.sb->transition(id, ResidencyState::GpuReady, ResidencyState::Executing))
        return 0;
    sig.value = d.nextVal.fetch_add(1, std::memory_order_relaxed);
    sig.semaphore = d.timeline;
    t.exec.fence.store(sig.value, std::memory_order_release);
    t.exec.done.store(0, std::memory_order_release);
    t.exec.native = d.timeline;
    VkSem wSem = waitUpload ? d.timeline : nullptr;
    if (d.fn.queueSubmit(d.fn.computeQ, cmds, nCmd, wSem, waitUpload, d.timeline,
                         sig.value, d.fn.ud) != 0) {
        (void)d.sb->transition(id, ResidencyState::Executing, ResidencyState::GpuReady);
        return 0;
    }
    AsyncSubmission sub{id,      sig.value, SyncOp::GpuKernel, ResidencyState::Executing,
                        ResidencyState::Retired, 1, &t.exec};
    if (!d.track(sub)) {
        (void)d.sb->transition(id, ResidencyState::Executing, ResidencyState::GpuReady);
        return 0;
    }
    return 1;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
