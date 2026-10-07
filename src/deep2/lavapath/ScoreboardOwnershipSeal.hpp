#pragma once
#include "ScoreboardOwnershipGate.hpp"
#include <cstdio>
namespace rawrxd::deep2 {
inline void EmitOwnershipSeal(FILE*out) noexcept {
 if(!out)return; const auto g=ReadOwnershipGate();
 std::fprintf(out,"N_COMPLETION_OBSERVED=%u\n",g.completionN);
 std::fprintf(out,"RELEASE_WINS=%u\n",g.releaseWins);
 std::fprintf(out,"RELEASE_DUPLICATES_DROPPED=%u\n",g.releaseDupDrops);
 std::fprintf(out,"N_PLUS_1_READY_FROM_SCOREBOARD=%u\n",g.nPlus1Ready);
 std::fprintf(out,"N_PLUS_1_SUBMIT_FROM_SCOREBOARD=%u\n",g.nPlus1Submit);
 std::fprintf(out,"SCOREBOARD_ISSUE_COUNT=%u\n",g.scoreboardIssue);
 std::fprintf(out,"SEQUENTIAL_N_PLUS_1_ISSUE_COUNT=%u\n",g.sequentialIssue);
 std::fprintf(out,"INTER_LAYER_PROGRESS_SCOREBOARD_OWNED=%u\n",g.interLayerOwned()?1u:0u);
 std::fprintf(out,"SCHEDULER_OWNERSHIP_ELIGIBLE=%u\n",g.schedulerOwnershipEligible()?1u:0u);
 std::fprintf(out,"SCOREBOARD_SCHEDULER_LIVE=0\n");
}
}
