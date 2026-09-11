#pragma once
/* ProductScoreboardWitness — P1 measured session counters. ≤99.
   SCOREBOARD_SCHEDULER_LIVE stays 0 until P3. */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct ProductScoreboardWitness {
    std::atomic<uint32_t> openIndexEnter{0};
    std::atomic<uint32_t> sessionEnter{0};
    std::atomic<uint32_t> bindObs{0};
    std::atomic<uint32_t> primeObs{0};
    std::atomic<uint32_t> pumpCount{0};
    std::atomic<uint32_t> pumpWorkCount{0};
    std::atomic<uint32_t> realKernelDispatch{0};
    std::atomic<uint32_t> generatedTokens{0};
    std::atomic<uint32_t> tokenCommit{0};
    std::atomic<uint32_t> tokenIn{0};
    std::atomic<uint32_t> tokenOut{0};
    std::atomic<uint32_t> committedTokens{0};
};

inline ProductScoreboardWitness& P1Wit() {
    static ProductScoreboardWitness w;
    return w;
}

inline void P1ResetWitness() noexcept {
    ProductScoreboardWitness& w = P1Wit();
    w.openIndexEnter.store(0, std::memory_order_relaxed);
    w.sessionEnter.store(0, std::memory_order_relaxed);
    w.bindObs.store(0, std::memory_order_relaxed);
    w.primeObs.store(0, std::memory_order_relaxed);
    w.pumpCount.store(0, std::memory_order_relaxed);
    w.pumpWorkCount.store(0, std::memory_order_relaxed);
    w.realKernelDispatch.store(0, std::memory_order_relaxed);
    w.generatedTokens.store(0, std::memory_order_relaxed);
    w.tokenCommit.store(0, std::memory_order_relaxed);
    w.tokenIn.store(0, std::memory_order_relaxed);
    w.tokenOut.store(0, std::memory_order_relaxed);
    w.committedTokens.store(0, std::memory_order_relaxed);
}

inline void MarkRealKernelDispatch() noexcept {
    P1Wit().realKernelDispatch.store(1, std::memory_order_release);
}

inline void MarkTokenCommit(uint32_t tokenId) noexcept {
    ProductScoreboardWitness& w = P1Wit();
    w.committedTokens.fetch_add(1, std::memory_order_acq_rel);
    w.generatedTokens.fetch_add(1, std::memory_order_acq_rel);
    w.tokenOut.store(tokenId, std::memory_order_release);
    w.tokenCommit.store(1, std::memory_order_release);
}

inline int ComputeP1ProductPathLive() noexcept {
    ProductScoreboardWitness& w = P1Wit();
    return w.openIndexEnter.load(std::memory_order_acquire) &&
                   w.sessionEnter.load(std::memory_order_acquire) &&
                   w.bindObs.load(std::memory_order_acquire) &&
                   w.primeObs.load(std::memory_order_acquire) &&
                   w.pumpCount.load(std::memory_order_acquire) > 0 &&
                   w.pumpWorkCount.load(std::memory_order_acquire) > 0 &&
                   w.realKernelDispatch.load(std::memory_order_acquire) &&
                   w.generatedTokens.load(std::memory_order_acquire) > 0 &&
                   w.tokenCommit.load(std::memory_order_acquire)
               ? 1
               : 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
