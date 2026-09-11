#pragma once
/* ProductScoreboardP3Seal — measured P3 tip; LIVE stays 0. ≤99. */
#include "ScoreboardSubmitExec.hpp"
#include "ProductScoreboardWitness.hpp"
#include "ScoreboardInvariants.hpp"
#include <cstdio>

namespace Deep2 {
namespace scoreboard {

inline void SealProductScoreboardP3(FILE* f) noexcept {
    if (!f)
        return;
    ScoreboardDispatchHooks& h = P3Hooks();
    ProductScoreboardWitness& w = P1Wit();
    const uint32_t re = h.readyExecObs.load(std::memory_order_acquire);
    const uint32_t su = h.submitObs.load(std::memory_order_acquire);
    const uint32_t ke = h.kernelObs.load(std::memory_order_acquire);
    const uint32_t co = h.completeObs.load(std::memory_order_acquire);
    const uint32_t cd = h.consumerDecObs.load(std::memory_order_acquire);
    const uint32_t rt = h.retireObs.load(std::memory_order_acquire);
    const uint32_t rc = h.recycleObs.load(std::memory_order_acquire);
    const uint32_t tok = w.generatedTokens.load(std::memory_order_acquire);
    const uint32_t commit = w.tokenCommit.load(std::memory_order_acquire);
    const int chain = (re && su && ke && co && cd && rt && rc && tok && commit)
                          ? 1
                          : 0;
    std::fprintf(f,
                 "GATE=G3_DEEP2_SCOREBOARD_P3_DISPATCH_AUTH_001\n"
                 "KIND=P3_DISPATCH_WITNESS\n"
                 "MODEL=TinyLlama\n"
                 "P3_SOURCE_WIRED=1\n"
                 "P3_READYEXEC_OBSERVED=%u\n"
                 "P3_SUBMIT_OBSERVED=%u\n"
                 "P3_KERNEL_OBSERVED=%u\n"
                 "P3_COMPLETION_OBSERVED=%u\n"
                 "P3_CONSUMER_DEC_OBSERVED=%u\n"
                 "P3_RETIRE_OBSERVED=%u\n"
                 "P3_RECYCLE_OBSERVED=%u\n"
                 "GENERATED_TOKENS=%u\n"
                 "TOKEN_COMMIT_PASS=%u\n"
                 "SCOREBOARD_DISPATCH_AUTHORITY=%d\n"
                 "SCOREBOARD_SCHEDULER_LIVE=0\n"
                 "SCOREBOARD_WAIT_PER_LAYER=%d\n"
                 "WAIT_PER_LAYER_LIVE=%d\n"
                 "PROMOTE=%d\n"
                 "TIP_CLIMB=HOLD\n"
                 "R28_APPLY=HELD\n",
                 re, su, ke, co, cd, rt, rc, tok, commit, chain,
                 SCOREBOARD_WAIT_PER_LAYER, WAIT_PER_LAYER_LIVE, PROMOTE);
}

} /* namespace scoreboard */
} /* namespace Deep2 */
