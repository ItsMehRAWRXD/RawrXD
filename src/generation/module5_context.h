#pragma once
// =============================================================================
// Module 5: Token Context
// Shared mutable state for a single generation call.
// Thread-safe via mutex on accumulated text; atomics on flags.
// No external dependencies beyond Modules 1, 3, 4.
// =============================================================================

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>

// Include Module 1
#include "module1_types.h"
// Include Module 3
#include "module3_utf8.h"
// Include Module 4
#include "module4_stopstring.h"

struct TokenContext {
    // --- Mutex-protected state ---
    mutable std::mutex mtx;
    std::string        accumulated;
    uint32_t           tokenCount;
    uint32_t           maxTokens;
    uint32_t           maxOutputBytes;

    // --- Timing ---
    std::chrono::high_resolution_clock::time_point startTime;
    std::chrono::high_resolution_clock::time_point firstTokenTime;
    bool               firstTokenSeen;

    // --- Atomic flags (lock-free) ---
    std::atomic<bool>  cancelled;
    std::atomic<bool>  engineErrorFired;
    std::atomic<bool>  nonEngineErrorFired;
    std::atomic<bool>  finished;

    // --- Error messages (set once, read during finalize) ---
    std::string        engineErrorMsg;
    std::string        nonEngineErrorMsg;

    // --- Terminal state ---
    std::atomic<FinishReason> terminalReason;
    std::atomic<ErrorSource>  terminalSource;

    // --- Helpers ---
    Utf8StreamingSanitizer utf8Sanitizer;

    TokenContext()
        : tokenCount(0)
        , maxTokens(512)
        , maxOutputBytes(1u << 20)
        , firstTokenSeen(false)
        , cancelled(false)
        , engineErrorFired(false)
        , nonEngineErrorFired(false)
        , finished(false)
        , terminalReason(FinishReason::NotFinished)
        , terminalSource(ErrorSource::None)
    {}

    // Thread-safe append
    bool tryAppend(const std::string& text) {
        std::lock_guard<std::mutex> lk(mtx);
        if (accumulated.size() + text.size() > maxOutputBytes) {
            return false;  // Would exceed limit
        }
        accumulated += text;
        return true;
    }

    // Thread-safe set token count
    void setTokenCount(uint32_t count) {
        std::lock_guard<std::mutex> lk(mtx);
        tokenCount = count;
    }

    // One-shot latch for engine error
    bool latchEngineError(const char* msg) {
        if (engineErrorFired.exchange(true)) {
            return false;  // Already fired
        }
        engineErrorMsg = (msg != nullptr) ? std::string(msg) : std::string("Unknown engine error");
        terminalReason.store(FinishReason::EngineError, std::memory_order_release);
        terminalSource.store(ErrorSource::Engine, std::memory_order_release);
        return true;
    }

    // One-shot latch for non-engine error
    bool latchNonEngineError(const char* msg) {
        if (nonEngineErrorFired.exchange(true)) {
            return false;  // Already fired
        }
        nonEngineErrorMsg = (msg != nullptr) ? std::string(msg) : std::string("Unknown error");
        terminalReason.store(FinishReason::NonEngineError, std::memory_order_release);
        terminalSource.store(ErrorSource::NonEngine, std::memory_order_release);
        return true;
    }

    // One-shot latch for cancellation
    bool latchCancel() {
        if (cancelled.exchange(true)) {
            return false;  // Already cancelled
        }
        if (terminalReason.load(std::memory_order_acquire) == FinishReason::NotFinished) {
            terminalReason.store(FinishReason::Cancelled, std::memory_order_release);
            terminalSource.store(ErrorSource::NonEngine, std::memory_order_release);
        }
        return true;
    }

    // Record first token time (one-shot)
    void markFirstToken() {
        if (!firstTokenSeen) {
            firstTokenSeen = true;
            firstTokenTime = std::chrono::high_resolution_clock::now();
        }
    }

    // Check if generation should stop
    bool shouldStop() const {
        return cancelled.load(std::memory_order_acquire)
            || engineErrorFired.load(std::memory_order_acquire)
            || nonEngineErrorFired.load(std::memory_order_acquire)
            || finished.load(std::memory_order_acquire);
    }

    // Mark generation as finished
    void markFinished() {
        finished.store(true, std::memory_order_release);
    }
};