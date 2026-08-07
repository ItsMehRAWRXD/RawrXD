// =============================================================================
// Module 6: Generation Logic
// Core orchestrator. Validates inputs, manages timeout thread,
// drives the engine, handles stop strings, UTF-8, and cancellation.
// No external dependencies beyond standard library + Modules 1-5.
// =============================================================================

#pragma once
#include "module1_types.h"
#include "module2_cancel.h"
#include "module3_utf8.h"
#include "module4_stop.h"
#include "module5_context.h"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <sstream>

// --- Engine Interface ---
// RawrXD's inference engine implements this.
class IGenerationEngine {
public:
    virtual ~IGenerationEngine() {}

    // Returns true on success, false on engine error.
    // onToken is called for every generated token.
    // onError is called for engine-internal errors.
    // cancelToken should be polled to honour external cancellation.
    virtual bool generate(
        const std::string&   prompt,
        uint32_t             maxTokens,
        double               temperature,
        float                topP,
        int64_t              topK,
        bool                 enableThinking,
        const TokenCallback& onToken,
        const ErrorCallback& onError,
        const CancelToken&   cancelToken
    ) = 0;
};

// --- Generation Logic ---
class GenerationLogic {
public:
    explicit GenerationLogic(IGenerationEngine* engine)
        : engine_(engine)
    {}

    GenerationResult generate(const GenerateParams& params,
                              const CancelToken&      externalCancel) {
        GenerationResult result;

        // --- Input validation ---
        if (params.prompt.empty()) {
            result.finishReason = FinishReason::NonEngineError;
            result.errorSource  = ErrorSource::NonEngine;
            result.errorMessage = "Prompt is empty";
            return result;
        }
        if (params.prompt.size() > MAX_PROMPT_LENGTH) {
            result.finishReason = FinishReason::NonEngineError;
            result.errorSource  = ErrorSource::NonEngine;
            result.errorMessage = "Prompt exceeds maximum length";
            return result;
        }
        if (params.maxGenerateLength == 0) {
            result.finishReason = FinishReason::Length;
            result.finishReasonStr = "Length";
            return result;
        }

        // --- Context & helpers ---
        TokenContext           ctx;
        Utf8StreamingSanitizer sanitizer;
        StopStringMatcher      stopMatcher;
        for (const auto& s : params.stopStrings) {
            stopMatcher.addStopString(s);
        }

        // --- Internal cancellation source ---
        CancelSource internalCancel;

        // --- Timeout thread (only if timeoutMs > 0) ---
        std::atomic<bool> done(false);
        std::mutex         doneMtx;
        std::condition_variable doneCv;
        std::thread        timeoutThread;

        if (params.timeoutMs > 0.0) {
            timeoutThread = std::thread([&]() {
                std::unique_lock<std::mutex> lk(doneMtx);
                auto ms = static_cast<int64_t>(params.timeoutMs);
                doneCv.wait_for(lk, std::chrono::milliseconds(ms),
                    [&]() { return done.load(std::memory_order_acquire); });
                if (!done.load(std::memory_order_acquire)) {
                    internalCancel.requestStop();
                }
            });
        }

        // --- Combined cancel check ---
        auto isCancelled = [&]() -> bool {
            return internalCancel.stopRequested() ||
                   (externalCancel.stopPossible() && externalCancel.stopRequested());
        };

        // --- Token callback ---
        std::string accumulatedText;
        bool engineReturned = false;
        std::string engineErrorMsg;

        TokenCallback onToken = [&](const char* token, uint32_t len) {
            if (ctx.isFinished() || isCancelled()) {
                return;
            }

            // UTF-8 sanitize
            std::string clean = sanitizer.sanitize(token);
            if (clean.empty()) {
                ctx.addToken(len);
                return;
            }

            // Stop-string check
            std::string matchedStop;
            size_t consumed = 0;
            if (stopMatcher.hasStopStrings() &&
                stopMatcher.feedString(clean, consumed, matchedStop)) {
                // Emit only the part before the stop string
                accumulatedText += clean.substr(0, consumed - matchedStop.size());
                ctx.addToken(len);
                ctx.setFinished(FinishReason::StopString);
                return;
            }

            accumulatedText += clean;
            ctx.addToken(len);

            // Length / byte limits
            if (ctx.tokenCount() >= params.maxGenerateLength) {
                ctx.setFinished(FinishReason::Length);
                return;
            }
            if (ctx.byteCount() >= params.maxOutputBytes) {
                ctx.setFinished(FinishReason::Length);
                return;
            }
        };

        ErrorCallback onError = [&](const char* msg) {
            engineErrorMsg = msg ? msg : "Unknown engine error";
        };

        // --- Run engine ---
        CancelToken combinedCancel = internalCancel.getToken();
        engineReturned = engine_>-generate(
            params.prompt,
            params.maxGenerateLength,
            params.temperature,
            params.topP,
            params.topK,
            params.enableThinking,
            onToken,
            onError,
            combinedCancel
        );

        // --- Signal timeout thread to exit early ---
        done.store(true, std::memory_order_release);
        doneCv.notify_all();
        if (timeoutThread.joinable()) {
            timeoutThread.join();
        }

        // --- Build result ---
        ctx.populateResult(result);
        result.text = accumulatedText;

        // Flush any trailing incomplete UTF-8
        std::string trailing = sanitizer.flush();
        if (!trailing.empty()) {
            result.text += trailing;
        }

        if (!engineReturned) {
            // Engine reported failure
            if (!ctx.isFinished()) {
                ctx.setFinished(FinishReason::EngineError, ErrorSource::Engine);
            }
            result.errorMessage = engineErrorMsg.empty()
                ? "Engine generation failed"
                : engineErrorMsg;
            result.errorSourceStr = "Engine";
        }

        if (isCancelled() && !ctx.isFinished()) {
            ctx.setFinished(FinishReason::Cancelled);
        }

        // Finalize strings
        switch (ctx.finishReason()) {
            case FinishReason::EndId:       result.finishReasonStr = "EndId"; break;
            case FinishReason::Length:      result.finishReasonStr = "Length"; break;
            case FinishReason::Cancelled:   result.finishReasonStr = "Cancelled"; break;
            case FinishReason::EngineError: result.finishReasonStr = "EngineError"; break;
            case FinishReason::NonEngineError: result.finishReasonStr = "NonEngineError"; break;
            case FinishReason::StopString:  result.finishReasonStr = "StopString"; break;
            default:                        result.finishReasonStr = "NotFinished"; break;
        }

        switch (ctx.errorSource()) {
            case ErrorSource::Engine:    result.errorSourceStr = "Engine"; break;
            case ErrorSource::NonEngine: result.errorSourceStr = "NonEngine"; break;
            default:                   result.errorSourceStr = "None"; break;
        }

        return result;
    }

private:
    IGenerationEngine* engine_;
};
