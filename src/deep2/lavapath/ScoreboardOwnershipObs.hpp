#pragma once
#include <atomic>
#include <cstdint>
namespace rawrxd::deep2 {
struct ScoreboardOwnershipObs {
 std::atomic<uint32_t> completionN{0}, releaseWins{0}, releaseDupDrops{0};
 std::atomic<uint32_t> nPlus1Ready{0}, nPlus1Submit{0};
 std::atomic<uint32_t> sequentialIssue{0}, scoreboardIssue{0};
 void reset() noexcept { completionN=0; releaseWins=0; releaseDupDrops=0; nPlus1Ready=0; nPlus1Submit=0; sequentialIssue=0; scoreboardIssue=0; }
};
inline ScoreboardOwnershipObs& OwnershipObs() noexcept { static ScoreboardOwnershipObs s; return s; }
inline std::atomic<uint32_t>& WalkEnsureCrutch() noexcept { static std::atomic<uint32_t> w{0}; return w; }
}
