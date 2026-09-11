#pragma once
/* Decode step — ProductRun orchestration only. ≤99 lines. */
#include "ProductRuntime.hpp"
#include "ProductPathInvariants.hpp"
#include "ProductScoreboardBind.hpp"
#include "RxRunStateHooks.hpp"
#include "TokenWallNs.hpp"
#include <chrono>
#include <string>

namespace rawr::product_run {

inline void RunDecodeStream(ProductRuntime& rt, const char* prompt,
                            uint32_t maxTokens, const TokenFn& onPiece,
                            Result& r, int& userCancel) {
    Deep2::GenerationOptions opts{};
    opts.maxTokens = maxTokens;
    opts.temperature = 0.f;
    opts.topK = 1;
    opts.seed = 42;
    rt.control.Clear();
    rt.Eng().clearCancel();
    userCancel = 0;
    rxow::OnGenerateEntered();
    rxow::OnDecodeStep0();
    /* P1: Prime→pumpOnce then legacy generateStream (≠ scheduler LIVE). */
    (void)Deep2::scoreboard::PumpProductDecode();
    const auto t0 = std::chrono::steady_clock::now();
    uint64_t lastCommitNs = 0;
    rt.Eng().generateStream(prompt, opts, [&](int32_t tokenId,
                                              const std::string& piece) {
        if (IsCancelled(rt.control) || rt.Eng().isCancelRequested()) {
            userCancel = 1;
            return false;
        }
        r.text += piece;
        ++r.generatedTokens;
        if (r.generatedTokens == 1) {
            r.firstToken = 1;
            Deep2::scoreboard::P1Wit().tokenIn.store((uint32_t)tokenId,
                                                    std::memory_order_release);
        }
        Deep2::scoreboard::MarkTokenCommit((uint32_t)tokenId);
        {
            const uint64_t now = Deep2::tokenwall::NowNs();
            if (lastCommitNs)
                Deep2::tokenwall::EmitCommitted(
                    stderr, r.generatedTokens, r.generatedTokens - 1u,
                    Deep2::tokenwall::DeltaNs(lastCommitNs, now), 1u);
            lastCommitNs = now;
        }
        if (onPiece && !onPiece(piece)) {
            userCancel = 1;
            (void)rt.CancelGeneration();
            return false;
        }
        return !(IsCancelled(rt.control) || rt.Eng().isCancelRequested());
    });
    r.wallNs = (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    r.textBytes = (uint64_t)r.text.size();
    r.streamFinished = 1;
    Deep2::scoreboard::SealProductScoreboardP1(stderr, r.generatedTokens);
    Deep2::scoreboard::SealProductScoreboardP3(stderr);
}

} // namespace rawr::product_run
