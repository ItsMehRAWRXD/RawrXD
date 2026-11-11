// =============================================================================
// Module 5: Token Context
// Tracks generation state: token count, byte count, timing, finished flag.
// Thread-safe via atomic operations.
// No external dependencies.
// =============================================================================

#pragma once
#include <cstdint>
#include <atomic>
#include <chrono>
#include "module1_types.h"

class TokenContext {
public:
    TokenContext()
        : tokenCount_(0)
        , byteCount_(0)
        , finished_(false)
        , finishReason_(FinishReason::NotFinished)
        , errorSource_(ErrorSource::None)
        , startTime_(std::chrono::steady_clock::now())
        , firstTokenTime_(std::chrono::steady_clock::time_point())
    {}

    // --- Token tracking ---
    void addToken(uint32_t tokenLen) {
        tokenCount_.fetch_add(1, std::memory_order_relaxed);
        byteCount_.fetch_add(tokenLen, std::memory_order_relaxed);

        // Record time-to-first-token on first token
        auto expected = std::chrono::steady_clock::time_point();
        auto now = std::chrono::steady_clock::now();
        // Compare-and-swap for firstTokenTime_
        // We use a bool flag instead since time_point CAS is tricky
        if (!firstTokenRecorded_.exchange(true, std::memory_order_acq_rel)) {
            firstTokenTime_ = now;
        }
    }

    uint32_t tokenCount() const {
        return tokenCount_.load(std::memory_order_relaxed);
    }

    uint32_t byteCount() const {
        return byteCount_.load(std::memory_order_relaxed);
    }

    // --- Finished flag ---
    void setFinished(FinishReason reason, ErrorSource source = ErrorSource::None) {
        finishReason_.store(reason, std::memory_order_release);
        errorSource_.store(source, std::memory_order_release);
        finished_.store(true, std::memory_order_release);
    }

    bool isFinished() const {
        return finished_.load(std::memory_order_acquire);
    }

    FinishReason finishReason() const {
        return finishReason_.load(std::memory_order_acquire);
    }

    ErrorSource errorSource() const {
        return errorSource_.load(std::memory_order_acquire);
    }

    // --- Timing ---
    double elapsedMs() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double, std::milli>(now - startTime_).count();
    }

    double timeToFirstTokenMs() const {
        if (!firstTokenRecorded_.load(std::memory_order_acquire)) {
            return 0.0;
        }
        return std::chrono::duration<double, std::milli>(
            firstTokenTime_ - startTime_).count();
    }

    double tokensPerSecond() const {
        double elapsed = elapsedMs() / 1000.0;
        if (elapsed <= 0.0) return 0.0;
        uint32_t tokens = tokenCount_.load(std::memory_order_relaxed);
        return static_cast<double>(tokens) / elapsed;
    }

    // --- Populate result struct ---
    void populateResult(GenerationResult& result) const {
        result.tokensGenerated = tokenCount();
        result.latencyMs = elapsedMs();
        result.tokensPerSecond = tokensPerSecond();
        result.timeToFirstTokenMs = timeToFirstTokenMs();
        result.finishReason = finishReason();
        result.errorSource = errorSource();
    }

private:
    std::atomic<uint32_t>                    tokenCount_;
    std::atomic<uint32_t>                    byteCount_;
    std::atomic<bool>                       finished_;
    std::atomic<FinishReason>              finishReason_;
    std::atomic<ErrorSource>                errorSource_;
    std::chrono::steady_clock::time_point    startTime_;
    std::chrono::steady_clock::time_point    firstTokenTime_;
    std::atomic<bool>                       firstTokenRecorded_;
};
