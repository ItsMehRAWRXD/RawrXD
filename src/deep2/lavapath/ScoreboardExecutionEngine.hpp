#pragma once
/* ScoreboardExecutionEngine — readiness loop (≠ layer join). LIVE=0. ≤99. */
#include "ScoreboardNextRunnable.hpp"
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

    /* Non-blocking pump: ready work then HW poll. No sleep_for / tick pace. */
    int pumpOnce(void* uploadCmds, uint32_t nUp, void* execCmds, uint32_t nEx) {
        if (!sb)
            return 0;
        Runnable r{};
        uint32_t n = 0;
        while (nextRunnable(*sb, r) && n < 64u) {
            ++n;
            TimelineSignal sig{};
            if (r.kind == RunnableKind::ReadyExec) {
                if (tl)
                    (void)timelineSubmitExec(*tl, r.id, execCmds, nEx, 0, sig);
                else
                    (void)sb->transition(r.id, ResidencyState::GpuReady,
                                         ResidencyState::Executing);
            } else if (r.kind == RunnableKind::Upload) {
                if (tl)
                    (void)timelineSubmitUpload(*tl, r.id, uploadCmds, nUp, sig);
                else
                    (void)sb->transition(r.id, ResidencyState::RamReady,
                                         ResidencyState::GpuPending);
            } else if (r.kind == RunnableKind::Io) {
                /* Tip advance: IoPending → RamReady (≠ ElasticResidency). */
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

    int runSteps(uint32_t totalSteps, void* up, uint32_t nUp, void* ex, uint32_t nEx) {
        if (!sb || !totalSteps)
            return 0;
        for (step = 0; step < totalSteps; ++step)
            (void)pumpOnce(up, nUp, ex, nEx);
        return 1;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
