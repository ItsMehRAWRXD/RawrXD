#pragma once
/* ProductScoreboardP3Seal — P3 + fence3 + interlayer tip; LIVE=0. ≤99. */
#include "ScoreboardSubmitExec.hpp"
#include "ScoreboardMultiOpObs.hpp"
#include "ScoreboardInterLayer.hpp"
#include "ScoreboardFenceObs.hpp"
#include "ProductScoreboardWitness.hpp"
#include "ScoreboardInvariants.hpp"
#include "ScoreboardRunId.hpp"
#include <cstdio>

namespace Deep2 {
namespace scoreboard {

inline void SealProductScoreboardP3(FILE* f) noexcept {
    if (!f)
        return;
    ScoreboardDispatchHooks& h = P3Hooks();
    InterLayerObs& il = InterLayer();
    ScoreboardFenceObs& fo = FenceObs();
    ProductScoreboardWitness& w = P1Wit();
    const uint32_t re = h.readyExecObs.load(std::memory_order_acquire);
    const uint32_t su = h.submitObs.load(std::memory_order_acquire);
    const uint32_t ke = h.kernelObs.load(std::memory_order_acquire);
    const uint32_t co = h.completeObs.load(std::memory_order_acquire);
    const uint32_t rt = h.retireObs.load(std::memory_order_acquire);
    const uint32_t rc = h.recycleObs.load(std::memory_order_acquire);
    const uint32_t dl =
        MultiOpObs().distinctLayers.load(std::memory_order_acquire);
    const uint32_t tok = w.generatedTokens.load(std::memory_order_acquire);
    const uint32_t commit = w.tokenCommit.load(std::memory_order_acquire);
    const int chain = (re && su && ke && co && rt && rc && tok && commit) ? 1 : 0;
    const int multi =
        (re > 1 && su > 1 && ke > 1 && co > 1 && dl > 1 && rt && rc && tok &&
         commit)
            ? 1
            : 0;
    const int j3 =
        fo.fence3Demoted.load(std::memory_order_acquire) > 0 ? 1 : 0;
    const int ilOwn = InterLayerProgressOwnedTip();
    /* Measured — never forced to 0 while loop still issues. */
    const uint32_t seqIss =
        il.sequentialNPlus1Issue.load(std::memory_order_acquire);
    EmitRunId(f);
    std::fprintf(
        f,
        "GATE=G3_DEEP2_SCOREBOARD_P3_DISPATCH_AUTH_001\n"
        "KIND=P3_DISPATCH_WITNESS\n"
        "P3_READYEXEC_OBSERVED=%u\n"
        "P3_SUBMIT_OBSERVED=%u\n"
        "P3_KERNEL_OBSERVED=%u\n"
        "P3_COMPLETION_OBSERVED=%u\n"
        "P3_RETIRE_OBSERVED=%u\n"
        "P3_RECYCLE_OBSERVED=%u\n"
        "P3_DISTINCT_LAYERS=%u\n"
        "P3_MULTI_OP_OBSERVED=%d\n"
        "FENCE3_ATTEMPTS=%u\n"
        "FENCE3_DEMOTED=%u\n"
        "FENCE3_FALLBACK_JOIN=%u\n"
        "FENCE3_PUMP_WORK=%u\n"
        "JOINOUTPREFETCH_DEMOTED=%d\n"
        "N_COMPLETION_OBSERVED=%u\n"
        "INTERLAYER_RELEASE_ATTEMPTS=%u\n"
        "INTERLAYER_RELEASE_WINS=%u\n"
        "INTERLAYER_DUPLICATES_DROPPED=%u\n"
        "N_PLUS_1_DEP_RELEASE_OBSERVED=%u\n"
        "N_PLUS_1_READYEXEC_FROM_SCOREBOARD=%u\n"
        "N_PLUS_1_SUBMIT_FROM_SCOREBOARD=%u\n"
        "SEQUENTIAL_N_PLUS_1_ISSUE_COUNT=%u\n"
        "INTER_LAYER_PROGRESS_SCOREBOARD_OWNED=%d\n"
        "SEQUENTIAL_LAYER_ADVANCE_AUTHORITY=%u\n"
        "GENERATED_TOKENS=%u\n"
        "TOKEN_COMMIT_PASS=%u\n"
        "SCOREBOARD_DISPATCH_AUTHORITY=%d\n"
        "SCOREBOARD_SCHEDULER_LIVE=0\n"
        "SCOREBOARD_WAIT_PER_LAYER=%d\n"
        "WAIT_PER_LAYER_LIVE=%d\n"
        "PROMOTE=%d\n"
        "TIP_CLIMB=HOLD\n"
        "R28_APPLY=HELD\n",
        re, su, ke, co, rt, rc, dl, multi,
        fo.fence3Attempts.load(std::memory_order_acquire),
        fo.fence3Demoted.load(std::memory_order_acquire),
        fo.fence3FallbackJoin.load(std::memory_order_acquire),
        fo.fence3PumpWork.load(std::memory_order_acquire), j3,
        il.nCompletionObs.load(std::memory_order_acquire),
        il.releaseAttempts.load(std::memory_order_acquire),
        il.releaseWins.load(std::memory_order_acquire),
        il.releaseDupDropped.load(std::memory_order_acquire),
        il.nPlus1DepReleaseObs.load(std::memory_order_acquire),
        il.nPlus1ReadyFromSbObs.load(std::memory_order_acquire),
        il.nPlus1SubmitFromSbObs.load(std::memory_order_acquire), seqIss, ilOwn,
        1u /* SEQUENTIAL_LAYER_ADVANCE_AUTHORITY held until loop demoted */, tok,
        commit, chain, SCOREBOARD_WAIT_PER_LAYER, WAIT_PER_LAYER_LIVE, PROMOTE);
}

} /* namespace scoreboard */
} /* namespace Deep2 */
