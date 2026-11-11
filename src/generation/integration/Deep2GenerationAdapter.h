#pragma once
// =============================================================================
// Deep2GenerationAdapter.h
// Bridges the modular generation control plane (modules 1-7) to Deep2Engine.
// The adapter owns the CancelSource, wires the 3 lambdas, and calls
// generateRobust() which returns a fully-populated GenerationResult.
// =============================================================================

#include "../module1_types.h"
#include "../module2_cancel.h"
#include "../module5_context.h"
#include "../module6_generate.h"
#include "../module7_glue.h"

#include <string>

class Deep2GenerationAdapter {
public:
    Deep2GenerationAdapter() : cancelSource_() {}

    // --- Simple generate — hides CancelSource from caller ---
    GenerationResult generate(
        Deep2Engine* engine,
        const std::string& prompt,
        uint32_t maxTokens
    ) {
        GenerateParams params;
        params.prompt = prompt;
        params.maxGenerateLength = maxTokens;
        params.maxOutputBytes = 1u << 20;  // 1 MB
        params.timeoutMs = 0.0;           // no timeout

        CancelSource cs;
        return generateRobust(engine, params, cs);
    }

    // --- Full generate with all parameters ---
    GenerationResult generate(
        Deep2Engine* engine,
        const GenerateParams& params,
        CancelSource& cancelSource
    ) {
        return generateRobust(engine, params, cancelSource);
    }

    // --- Streaming generate with per-token callback ---
    // The callback receives sanitized UTF-8 text chunks.
    // Return false from the callback to cancel generation.
    GenerationResult generateStream(
        Deep2Engine* engine,
        const std::string& prompt,
        uint32_t maxTokens,
        std::function<bool(const std::string& token)> onToken
    ) {
        GenerateParams params;
        params.prompt = prompt;
        params.maxGenerateLength = maxTokens;
        params.maxOutputBytes = 1u << 20;

        CancelSource cancelSource;

        TokenContext ctx;
        ctx.startTime = std::chrono::high_resolution_clock::now();
        ctx.maxTokens = maxTokens;
        ctx.maxOutputBytes = params.maxOutputBytes;

        if (!preFlightValidate(params, ctx, engine != nullptr && engine->isReady())) {
            GenerationResult result;
            finalizeResult(result, ctx);
            return result;
        }

        CancelToken cancelToken = cancelSource.getToken();
        StopStringMatcher stopMatcher(params.stopStrings);

        GenerationResult result;
        bool callbackCancelled = false;

        bool ok = engine->generate(
            params.prompt.c_str(),

            // Lambda 1: Token stream — calls user callback
            [&](const char* token, uint32_t idx) {
                if (ctx.shouldStop() || callbackCancelled) return;
                if (cancelToken.stopRequested()) { ctx.latchCancel(); return; }
                if (idx >= ctx.maxTokens) {
                    if (ctx.terminalReason == FinishReason::NotFinished)
                        ctx.terminalReason = FinishReason::Length;
                    return;
                }

                std::string safe = ctx.utf8Sanitizer.sanitize(token);
                if (safe.empty()) return;

                ctx.markFirstToken();

                if (!params.stopStrings.empty()) {
                    std::string matched = stopMatcher.check(safe);
                    if (!matched.empty()) {
                        if (ctx.terminalReason == FinishReason::NotFinished)
                            ctx.terminalReason = FinishReason::StopString;
                        return;
                    }
                }

                if (!ctx.tryAppend(safe)) {
                    ctx.latchNonEngineError("Output exceeded maximum byte limit");
                    cancelSource.requestStop();
                    return;
                }

                ctx.setTokenCount(idx + 1);

                // Call user callback — false means cancel
                if (onToken && !onToken(safe)) {
                    callbackCancelled = true;
                    ctx.latchCancel();
                    cancelSource.requestStop();
                }
            },

            // Lambda 2: Engine error
            [&](const char* err) { ctx.latchEngineError(err); },

            // Lambda 3: Non-engine error
            [&](const char* err) { ctx.latchNonEngineError(err); }
        );

        if (!ok && ctx.terminalReason == FinishReason::NotFinished) {
            ctx.latchEngineError("Engine returned false without error callback");
        }
        if (ctx.terminalReason == FinishReason::NotFinished) {
            ctx.terminalReason = FinishReason::EndId;
        }

        cancelSource.requestStop();
        finalizeResult(result, ctx);
        return result;
    }

private:
    CancelSource cancelSource_;
};