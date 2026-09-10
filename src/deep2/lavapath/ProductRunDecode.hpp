#pragma once
/* Decode step — ProductRun orchestration only. ≤99 lines. */
#include "ProductRuntime.hpp"
#include "ProductPathInvariants.hpp"
#include "RxRunStateHooks.hpp"
#include "HostFutureConsumerPrefetch.hpp"
#include "TokenWallNs.hpp"
#include <chrono>
#include <cstdlib>
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
    const char* hd = std::getenv("RAWRXD_HOST_DECODE");
    const int host = hd && hd[0] == '1';
    if (host) {
        Deep2::hostfc::MarkProductDecode();
        const auto& mw = rt.Eng().getModelWeights();
        uint32_t n = mw.numLayers ? (uint32_t)mw.numLayers : rt.graphNodes;
        /* Bind before Arm/Enter/Prefetch; elastic residency stays off. */
        Deep2::hostfc::BindK3cConsumer(K3C_ConsumeResolved);
        Deep2::hostfc::ArmFromProductRun(n);
        Deep2::hostfc::BindNvme(rt.Eng().HostNvme());
        if (n > 1 && mw.layers.size() > 1) {
            const auto& w = mw.layers[1].wq.data ? mw.layers[1].wq
                                                 : mw.layers[1].attnQ_a;
            Deep2::hostfc::BindHostWeight(w.data, w.sizeBytes, w.fileOffset);
        }
        Deep2::hostfc::EnterLayer(0, n ? n : 2);
    }
    const auto t0 = std::chrono::steady_clock::now();
    uint64_t lastCommitNs = 0;
    rt.Eng().generateStream(prompt, opts, [&](int32_t, const std::string& piece) {
        if (IsCancelled(rt.control) || rt.Eng().isCancelRequested()) {
            userCancel = 1;
            return false;
        }
        r.text += piece;
        ++r.generatedTokens;
        if (r.generatedTokens == 1) r.firstToken = 1;
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
        if (IsCancelled(rt.control) || rt.Eng().isCancelRequested()) {
            userCancel = 1;
            return false;
        }
        return true;
    });
    r.wallNs = (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    r.textBytes = (uint64_t)r.text.size();
    r.streamFinished = 1;
    if (host)
        Deep2::hostfc::SealDecode(r.firstToken && r.generatedTokens > 0, stderr);
}

} // namespace rawr::product_run
