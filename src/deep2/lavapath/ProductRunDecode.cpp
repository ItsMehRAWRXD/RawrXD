/* Decode step — out-of-line so seh Open path stays stable. ≤99 lines. */
#include "ProductRunDecode.hpp"
#include "ProductPathInvariants.hpp"
#include "ProductScoreboardBind.hpp"
#include "ProductScoreboardIssuanceSeal.hpp"
#include "ScoreboardOwnershipSeal.hpp"
#include "ScoreboardProgressSeal.hpp"
#include "RxRunStateHooks.hpp"
#include "TokenWallNs.hpp"
#include <chrono>
#include <cstdio>
#include <string>

namespace rawr::product_run {

void RunDecodeStream(ProductRuntime& rt, const char* prompt, uint32_t maxTokens,
                     const TokenFn& onPiece, Result& r, int& userCancel) {
    Deep2::GenerationOptions opts{};
    opts.maxTokens = maxTokens;
    opts.temperature = 0.f;
    opts.topK = 1;
    opts.seed = 42;
    rt.control.Clear();
    /* Pin engine once. Callback must NOT call rt.Eng() — llama32 heap thrash
     * poisons ext≈0x100000001 (STREAM_SEH READ VA=ext+0x2A9). */
    if (rt.ext && !ProductRuntime::ExtPlausible(rt.ext)) {
        std::fprintf(stderr, "PRODUCT_RUNTIME_EXT_WILD=%p CLEAR=1 decode\n",
                     (void*)rt.ext);
        std::fflush(stderr);
        rt.ext = nullptr;
    }
    Deep2::Deep2Engine* engp =
        (rt.ext && ProductRuntime::ExtPlausible(rt.ext)) ? rt.ext : &rt.engine;
    engp->clearCancel();
    userCancel = 0;
    rxow::OnGenerateEntered();
    rxow::OnDecodeStep0();
    (void)Deep2::scoreboard::PumpProductDecode();
    const auto t0 = std::chrono::steady_clock::now();
    uint64_t lastCommitNs = 0;
    engp->generateStream(prompt, opts, [&](int32_t tokenId,
                                           const std::string& piece) {
        if (IsCancelled(rt.control) || engp->isCancelRequested()) {
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
            rt.control.RequestCancel();
            engp->requestCancel();
            return false;
        }
        return !(IsCancelled(rt.control) || engp->isCancelRequested());
    });
    r.wallNs = (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    r.textBytes = (uint64_t)r.text.size();
    r.streamFinished = 1;
    Deep2::scoreboard::SealProductScoreboardP1(stderr, r.generatedTokens);
    Deep2::scoreboard::SealProductScoreboardP3(stderr);
    Deep2::scoreboard::SealProductScoreboardIssuance(stderr);
    Deep2::scoreboard::EmitOwnershipSeal(stderr);
    Deep2::scoreboard::EmitProgressIndependenceSeal(stderr);
}

} // namespace rawr::product_run
