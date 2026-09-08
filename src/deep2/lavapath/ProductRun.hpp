#pragma once
/* One production pipeline — CLI/IDE/bench/agent call ProductRun only. */
#include "../Deep2Engine.h"
#include "../RawrRunSession.hpp"
#include "ProductReceipt.hpp"
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>

namespace rawr::product_run {

using TokenFn = std::function<bool(const std::string& piece)>;

struct Request {
    const char* modelAlias = nullptr;
    const char* prompt = nullptr;
    uint32_t maxTokens = 256;
    Deep2::Deep2Engine* engine = nullptr;
    int keepOpen = 0;
    TokenFn onPiece;
};

inline Result ProductRun(const Request& req) {
    Result r{};
    if (!req.modelAlias || !req.modelAlias[0]) {
        r.failedStage = "RESOLVE";
        r.failedOwner = "MODEL_ALIAS";
        r.exitReason = "FAIL";
        EmitReceipt(stderr, r);
        return r;
    }
    Deep2::Deep2Engine owned;
    Deep2::Deep2Engine& e = req.engine ? *req.engine : owned;
    Deep2::rawr_run::RunWitness w{};
    if (!e.isModelLoaded()) {
        if (!Deep2::rawr_run::OpenSession(e, req.modelAlias, w)) {
            r.modelResolved = w.modelAliasResolved;
            r.failedStage = w.modelAliasResolved ? "LOAD" : "RESOLVE";
            r.failedOwner = w.modelAliasResolved ? "GGUF_OPEN" : "MODEL_ALIAS";
            r.exitReason = "FAIL";
            EmitReceipt(stderr, r);
            return r;
        }
    } else {
        w.modelAliasResolved = 1;
        w.ggufOpened = 1;
        w.tokenizerReady = e.tokenize("hi").empty() ? 0 : 1;
        w.modelName = req.modelAlias;
    }
    r.modelResolved = 1;
    r.modelOpen = e.isModelLoaded() ? 1 : 0;
    r.tokenizerReady = w.tokenizerReady;
    r.modelPath = w.modelPath;
    r.modelName = w.modelName.empty() ? req.modelAlias : w.modelName;
    if (!r.modelOpen) {
        r.failedStage = "LOAD";
        r.failedOwner = "GGUF_OPEN";
        r.exitReason = "FAIL";
        EmitReceipt(stderr, r);
        return r;
    }
    r.runtimeReady = 1;
    r.streamEnter = 1;
    const char* prompt = (req.prompt && req.prompt[0]) ? req.prompt : "hi";
    (void)Deep2::rawr_run::FormatChatPrompt(e, prompt, &w);
    Deep2::GenerationOptions opts{};
    opts.maxTokens = req.maxTokens ? req.maxTokens : 256u;
    opts.temperature = 0.f;
    opts.topK = 1;
    opts.seed = 42;
    e.clearCancel();
    int userCancel = 0;
    const auto t0 = std::chrono::steady_clock::now();
    e.generateStream(prompt, opts, [&](int32_t, const std::string& piece) {
        r.text += piece;
        ++r.generatedTokens;
        if (r.generatedTokens == 1) r.firstToken = 1;
        if (req.onPiece && !req.onPiece(piece)) {
            userCancel = 1;
            e.requestCancel();
            return false;
        }
        if (e.isCancelRequested()) {
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
    if (userCancel || e.isCancelRequested()) {
        r.exitReason = "CANCELLED";
        r.productPass = 0;
        r.failedStage = "NONE";
        r.failedOwner = "NONE";
    } else {
        r.exitReason = r.firstToken ? "COMPLETE" : "FAIL";
        r.productPass = FunctionalComplete(r);
        if (!r.productPass) {
            r.failedStage = "GENERATE_STREAM";
            r.failedOwner = "FIRST_OWNER_RUNTIME";
        }
    }
    EmitReceipt(stderr, r);
    if (!req.engine && !req.keepOpen) e.unloadModel();
    return r;
}

} // namespace rawr::product_run
