#pragma once
// =============================================================================
// Module 6: Generation Logic
// The main generateRobust() function. Uses Modules 1-5.
// No goto. No C++17/20 features. Pure C++14.
// =============================================================================

#include <chrono>
#include <functional>
#include <memory>
#include <thread>

// Include all modules
#include "module1_types.h"
#include "module2_cancel.h"
#include "module3_utf8.h"
#include "module4_stopstring.h"
#include "module5_context.h"

// --- Helper: finalize result from context ---
static void finalizeResult(GenerationResult& result, TokenContext& ctx) {
    // Flush remaining UTF-8 bytes
    std::string tail = ctx.utf8Sanitizer.flush();
    if (!tail.empty()) {
        std::lock_guard<std::mutex> lk(ctx.mtx);
        ctx.accumulated += tail;
    }

    // Compute timing
    std::chrono::high_resolution_clock::time_point t1
        = std::chrono::high_resolution_clock::now();
    long long elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        t1 - ctx.startTime).count();

    {
        std::lock_guard<std::mutex> lk(ctx.mtx);
        result.text = ctx.accumulated;
        result.tokensGenerated = ctx.tokenCount;
    }

    result.latencyMs = (elapsedUs > 0)
        ? (static_cast<double>(elapsedUs) / 1000.0)
        : 0.0;

    result.tokensPerSecond = (result.tokensGenerated > 0 && elapsedUs > 0)
        ? (static_cast<double>(result.tokensGenerated) * 1000000.0
           / static_cast<double>(elapsedUs))
        : 0.0;

    result.timeToFirstTokenMs = ctx.firstTokenSeen
        ? (std::chrono::duration_cast<std::chrono::microseconds>(
              ctx.firstTokenTime - ctx.startTime).count() / 1000.0)
        : 0.0;

    result.finishReason = ctx.terminalReason.load(std::memory_order_acquire);
    result.errorSource  = ctx.terminalSource.load(std::memory_order_acquire);

    // Map enums to strings — pure lookup, no constexpr
    static const char* finishReasonNames[] = {
        "not_finished", "stop", "length", "cancelled",
        "engine_error", "non_engine_error", "stop_string"
    };
    static const char* errorSourceNames[] = {
        "", "engine", "non_engine"
    };

    uint8_t fr = static_cast<uint8_t>(result.finishReason);
    uint8_t es = static_cast<uint8_t>(result.errorSource);

    if (fr < 7) {
        result.finishReasonStr = finishReasonNames[fr];
    } else {
        result.finishReasonStr = "unknown";
    }

    if (es < 3) {
        result.errorSourceStr = errorSourceNames[es];
    } else {
        result.errorSourceStr = "unknown";
    }

    if (result.errorSource == ErrorSource::Engine) {
        result.errorMessage = ctx.engineErrorMsg;
    } else if (result.errorSource == ErrorSource::NonEngine) {
        result.errorMessage = ctx.nonEngineErrorMsg;
    }
}

// --- Helper: pre-flight validation ---
// Returns true if validation passed, false if it failed
// (ctx will have the error latched on failure).
static bool preFlightValidate(const GenerateParams& params,
                              TokenContext& ctx,
                              bool engineReady) {
    if (params.prompt.empty()) {
        ctx.latchNonEngineError("Empty prompt");
        return false;
    }

    if (params.prompt.size() > MAX_PROMPT_LENGTH) {
        std::string msg = "Prompt exceeds max length (";
        msg += std::to_string(MAX_PROMPT_LENGTH);
        msg += " bytes)";
        ctx.latchNonEngineError(msg.c_str());
        return false;
    }

    if (!engineReady) {
        ctx.latchNonEngineError("Engine not initialized or not ready");
        return false;
    }

    if (params.maxGenerateLength == 0) {
        ctx.latchNonEngineError("maxGenerateLength must be > 0");
        return false;
    }

    return true;
}

// --- Main entry point ---
GenerationResult generateRobust(
    class Deep2Engine* engine,
    const GenerateParams& params,
    CancelSource& cancelSource) {

    GenerationResult result;
    TokenContext ctx;

    ctx.startTime = std::chrono::high_resolution_clock::now();
    ctx.maxTokens = params.maxGenerateLength;
    ctx.maxOutputBytes = params.maxOutputBytes;

    // --- Pre-flight validation (no goto — just early-return) ---
    if (!preFlightValidate(params, ctx, engine != nullptr && engine->isReady())) {
        finalizeResult(result, ctx);
        return result;
    }

    // --- Cancellation token for this generation ---
    CancelToken cancelToken = cancelSource.getToken();

    // --- Stop string matcher ---
    StopStringMatcher stopMatcher(params.stopStrings);

    // --- Timeout thread (optional) ---
    std::unique_ptr<std::thread> timeoutThread;
    if (params.timeoutMs > 0.0) {
        long long timeoutUs = static_cast<long long>(params.timeoutMs * 1000.0);
        auto deadline = ctx.startTime + std::chrono::microseconds(timeoutUs);

        timeoutThread.reset(new std::thread([&ctx, deadline, &cancelSource]() {
            while (!ctx.shouldStop()) {
                auto now = std::chrono::high_resolution_clock::now();
                if (now >= deadline) {
                    ctx.latchNonEngineError("Generation timed out");
                    cancelSource.requestStop();
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }));
    }

    // --- Cancellation watcher thread ---
    std::thread cancelWatcher([&ctx, &cancelSource]() {
        while (!cancelSource.stopRequested() && !ctx.shouldStop()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (cancelSource.stopRequested()) {
            ctx.latchCancel();
        }
    });

    // --- Engine generate with 3 lambdas ---
    // All error/callback logic is funneled through TokenContext
    // which uses one-shot atomic latches to prevent double-fire.
    bool engineOk = engine->generate(
        params.prompt.c_str(),

        // Lambda 1: Token stream callback
        [&ctx, &params, &stopMatcher, &cancelToken, &cancelSource](
            const char* token, uint32_t idx
        ) {
            // --- Already stopping? Drop token silently ---
            if (ctx.shouldStop()) {
                return;
            }

            // --- Cancel requested? ---
            if (cancelToken.stopRequested()) {
                ctx.latchCancel();
                return;
            }

            // --- Max token count ---
            if (idx >= ctx.maxTokens) {
                if (ctx.terminalReason.load(std::memory_order_acquire) == FinishReason::NotFinished) {
                    ctx.terminalReason.store(FinishReason::Length, std::memory_order_release);
                }
                return;
            }

            // --- UTF-8 sanitize ---
            std::string safe = ctx.utf8Sanitizer.sanitize(token);
            if (safe.empty()) {
                return;  // Incomplete sequence, wait for more tokens
            }

            // --- First token timing ---
            ctx.markFirstToken();

            // --- Stop string check ---
            if (!params.stopStrings.empty()) {
                std::string matched = stopMatcher.check(safe);
                if (!matched.empty()) {
                    if (ctx.terminalReason.load(std::memory_order_acquire) == FinishReason::NotFinished) {
                        ctx.terminalReason.store(FinishReason::StopString, std::memory_order_release);
                    }
                    return;
                }
            }

            // --- Max output bytes ---
            if (!ctx.tryAppend(safe)) {
                ctx.latchNonEngineError("Output exceeded maximum byte limit");
                cancelSource.requestStop();
                return;
            }

            // --- Update token count ---
            ctx.setTokenCount(idx + 1);
        },

        // Lambda 2: Engine-internal error callback
        [&ctx](const char* err) {
            ctx.latchEngineError(err);
        },

        // Lambda 3: Non-engine error callback
        [&ctx](const char* err) {
            ctx.latchNonEngineError(err);
        }
    );

    // --- Engine returned false without latching a reason? ---
    if (!engineOk && ctx.terminalReason.load(std::memory_order_acquire) == FinishReason::NotFinished) {
        ctx.latchEngineError("Engine returned false without error callback");
    }

    // --- Normal completion (no terminal reason set)? ---
    if (ctx.terminalReason.load(std::memory_order_acquire) == FinishReason::NotFinished) {
        ctx.terminalReason.store(FinishReason::EndId, std::memory_order_release);
    }

    // Mark generation as finished
    ctx.markFinished();

    // --- Join threads ---
    cancelSource.requestStop();  // Wake up watchers
    if (timeoutThread && timeoutThread->joinable()) {
        timeoutThread->join();
    }
    if (cancelWatcher.joinable()) {
        cancelWatcher.join();
    }

    // --- Finalize and return ---
    finalizeResult(result, ctx);
    return result;
}