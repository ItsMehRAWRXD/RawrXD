#pragma once
/* ProductScoreboardPrime — P1 BindModel/Prime/RunUntilTokenCommit.
   GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 SOURCE_WIRED only. LIVE=0.
   No ElasticResidency, no HOST_DECODE apply, no join removal. ≤99. */
#include "OpenModelIndex.hpp"
#include "ScoreboardExecutionEngine.hpp"
#include "ScoreboardInvariants.hpp"
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct ProductScoreboardPrime {
    /* Metadata→TensorScore only. ≠ weight arenas / model-byte admission. */
    static int BindModel(const OpenModelIndex& index, TensorScoreboard& sb,
                         WindowPool* ram) noexcept {
        if (!INVERSION_LOCKED || !LOADMODEL_DEMOTED_TO_OPEN_INDEX)
            return 0;
        if (!index.nTensors || !ram)
            return 0;
        return index.primeScoreboard(sb, ram);
    }

    /* Dependency tick: Absent in [firstUse,lastUse] → IoPending queue. */
    static int Prime(TensorScoreboard& sb, uint32_t tokenStep) noexcept {
        if (!sb.n)
            return 0;
        int n = 0;
        for (uint32_t i = 0; i < sb.n; ++i) {
            TensorScore* t = sb.get(i);
            if (!t)
                continue;
            const uint32_t st = t->state.load(std::memory_order_acquire);
            if (st != (uint32_t)ResidencyState::Absent)
                continue;
            if (tokenStep < t->firstUse || tokenStep > t->lastUse)
                continue;
            if (sb.enqueueIo(i))
                ++n;
        }
        return n > 0 ? 1 : 0;
    }

    /* Bounded pump. Token only if liveCommit observes real product commit. */
    static int RunUntilTokenCommit(ScoreboardExecutionEngine& eng,
                                   uint32_t maxPumpSteps,
                                   uint32_t& committedToken,
                                   const std::atomic<uint32_t>* liveCommit =
                                       nullptr) noexcept {
        committedToken = 0;
        if (!eng.sb || !maxPumpSteps)
            return 0;
        /* Does not flip SCOREBOARD_SCHEDULER_LIVE; witness seal owns that. */
        for (uint32_t i = 0; i < maxPumpSteps; ++i) {
            (void)eng.pumpOnce(nullptr, 0, nullptr, 0);
            if (liveCommit) {
                const uint32_t c = liveCommit->load(std::memory_order_acquire);
                if (c > 0) {
                    committedToken = c;
                    return 1;
                }
            }
        }
        return 0; /* NOT_RUN ≠ PASS — no invented TOKEN_COMMIT */
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
