#pragma once
/* ProductScoreboardSeal — measured P1; SCHEDULER_LIVE always 0. ≤99. */
#include "ScoreboardInvariants.hpp"
#include "ScoreboardRunId.hpp"
#include <cstdio>

namespace Deep2 {
namespace scoreboard {

inline void SealProductScoreboardP1(FILE* f, uint32_t /*generatedTokens*/) {
    if (!f)
        return;
    ProductScoreboardWitness& w = P1Wit();
    const int pathLive = ComputeP1ProductPathLive();
    const int decodePass = pathLive;
    EmitRunId(f);
    std::fprintf(f,
                 "GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001\n"
                 "KIND=P1_PRODUCT_PATH_WITNESS\n"
                 "MODEL=TinyLlama\n"
                 "P1_SOURCE_WIRED=1\n"
                 "OPEN_INDEX_ENTER=%u\n"
                 "SESSION_ENTER=%u\n"
                 "SCOREBOARD_BIND_OBSERVED=%u\n"
                 "SCOREBOARD_PRIME_OBSERVED=%u\n"
                 "SCOREBOARD_PUMP_COUNT=%u\n"
                 "SCOREBOARD_WORK_ADVANCED=%u\n"
                 "REAL_KERNEL_DISPATCH_OBSERVED=%u\n"
                 "GENERATED_TOKENS=%u\n"
                 "TOKEN_IN=%u\n"
                 "TOKEN_OUT=%u\n"
                 "TOKEN_COMMIT_PASS=%u\n"
                 "P1_PRODUCT_PATH_LIVE=%d\n"
                 "PRODUCT_SCOREBOARD_DECODE_PASS=%d\n"
                 "SCOREBOARD_SCHEDULER_LIVE=0\n"
                 "SCOREBOARD_WAIT_PER_LAYER=%d\n"
                 "WAIT_PER_LAYER_LIVE=%d\n"
                 "PROMOTE=%d\n"
                 "TIP_CLIMB=HOLD\n"
                 "R28_APPLY=HELD\n"
                 "APPLY_HOST_DECODE=0\n"
                 "DUALSTICK_REOPENED=0\n",
                 w.openIndexEnter.load(std::memory_order_acquire),
                 w.sessionEnter.load(std::memory_order_acquire),
                 w.bindObs.load(std::memory_order_acquire),
                 w.primeObs.load(std::memory_order_acquire),
                 w.pumpCount.load(std::memory_order_acquire),
                 w.pumpWorkCount.load(std::memory_order_acquire),
                 w.realKernelDispatch.load(std::memory_order_acquire),
                 w.generatedTokens.load(std::memory_order_acquire),
                 w.tokenIn.load(std::memory_order_acquire),
                 w.tokenOut.load(std::memory_order_acquire),
                 w.tokenCommit.load(std::memory_order_acquire), pathLive,
                 decodePass, SCOREBOARD_WAIT_PER_LAYER, WAIT_PER_LAYER_LIVE,
                 PROMOTE);
}

} /* namespace scoreboard */
} /* namespace Deep2 */
