#pragma once
/* ScoreboardExecutionEngine — readiness loop. SCHEDULER_LIVE=0. ≤99. */
#include "ScoreboardNextRunnable.hpp"
#include "ScoreboardSubmitExec.hpp"
#include "TimelineDispatch.hpp"
#include "TimelineSubmit.hpp"
#include "MultiGpuCostFunction.hpp"
#include "ScoreboardInvariants.hpp"

namespace Deep2 {
namespace scoreboard {

struct ScoreboardExecutionEngine {
    TensorScoreboard* sb = nullptr;
    TimelineDispatch* tl = nullptr;
    MultiGpuCostFunction cost{};
    uint32_t step = 0;

    int bind(TensorScoreboard* s, TimelineDispatch* t) {
        if (!s || !INVERSION_LOCKED)
            return 0;
        sb = s;
        tl = t;
        return 1;
    }

    int pumpOnce(void* uploadCmds, uint32_t nUp, void* execCmds, uint32_t nEx) {
        if (!sb)
            return 0;
        Runnable r{};
        uint32_t n = 0;
        while (nextRunnable(*sb, r) && n < 64u) {
            ++n;
            TimelineSignal sig{};
            if (r.kind == RunnableKind::ReadyExec) {
                TensorScore* t = sb->get(r.id);
                const uint32_t st =
                    t ? t->state.load(std::memory_order_acquire) : 0u;
                if (st != (uint32_t)ResidencyState::GpuReady)
                    continue; /* drop stale readyQ after retire/exec */
                if (P3Hooks().submitExec)
                    (void)DispatchReadyExec(*sb, r.id);
                else {
                    /* Keep GpuReady for later armed P3 dispatch; requeue. */
                    (void)sb->readyQ.push(r.id);
                    break;
                }
            } else if (r.kind == RunnableKind::Upload) {
                if (tl)
                    (void)timelineSubmitUpload(*tl, r.id, uploadCmds, nUp, sig);
                else
                    (void)sb->transition(r.id, ResidencyState::RamReady,
                                         ResidencyState::GpuPending);
            } else if (r.kind == RunnableKind::Io) {
                (void)sb->transition(r.id, ResidencyState::IoPending,
                                     ResidencyState::RamReady);
            } else if (r.kind == RunnableKind::GpuPending) {
                (void)sb->transition(r.id, ResidencyState::GpuPending,
                                     ResidencyState::GpuReady);
            } else if (r.kind == RunnableKind::Retire) {
                (void)sb->onConsumerDone(r.id);
            }
        }
        if (tl)
            (void)tl->poll(32);
        return (int)n;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
