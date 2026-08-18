// ============================================================================
// K2TimeLimitedServing.hpp — K2-TLS: Time-Limited Serving
// ============================================================================
//
// Scheduler-level inference budget. The model execution remains cooperative:
// callers check the budget at safe boundaries and return TIME_LIMIT rather
// than killing the process.
//
// Intended boundaries:
//   - before/after token generation
//   - between transformer layers
//   - before expensive tensor residency operations
//   - before output projection
//   - before tokenizer/rendering work
//
// No threads, dependencies, or external libraries. Reusable beyond K2.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>

namespace rawrxd::deep2 {

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------
enum class K2TLSStatus : uint8_t {
    OK = 0,
    TIME_LIMIT,
    TOKEN_LIMIT,
    CANCELLED,
    MEMORY_LIMIT,
    ERROR
};

const char* K2TLSStatusName(K2TLSStatus status);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
struct K2TLSConfig {
    // Maximum wall-clock lifetime of one request. 0 = unlimited.
    uint64_t maxMilliseconds = 0;

    // Maximum number of newly generated tokens. 0 = unlimited.
    uint32_t maxNewTokens = 0;

    // Optional memory/residency policy. 0 = disabled.
    uint64_t maxResidentBytes = 0;

    // Checkpoint interval for inner loops (advisory).
    uint32_t checkpointEvery = 1;
};

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------
struct K2TLSResult {
    K2TLSStatus status = K2TLSStatus::OK;

    uint32_t generatedTokens = 0;
    uint32_t completedLayers = 0;

    uint64_t elapsedMilliseconds = 0;
    uint64_t peakResidentBytes = 0;

    // Set when the request produced usable partial output before the
    // deadline/token limit was reached.
    bool partialResult = false;

    std::string message;

    bool success() const {
        return status == K2TLSStatus::OK;
    }

    bool interrupted() const {
        return status == K2TLSStatus::TIME_LIMIT ||
               status == K2TLSStatus::TOKEN_LIMIT ||
               status == K2TLSStatus::CANCELLED;
    }
};

// ---------------------------------------------------------------------------
// Time limit tracker
// ---------------------------------------------------------------------------
class K2TimeLimit {
public:
    using Clock = std::chrono::steady_clock;

    explicit K2TimeLimit(const K2TLSConfig& config);

    void reset();

    // Budget checks
    bool expired() const;
    bool tokenLimitReached(uint32_t generatedTokens) const;
    bool memoryLimitReached(uint64_t residentBytes) const;

    K2TLSStatus check(uint32_t generatedTokens = 0,
                      uint64_t residentBytes = 0) const;

    // Cancellation
    void cancel();
    bool cancelled() const;

    // Accounting
    uint64_t elapsedMilliseconds() const;
    uint64_t remainingMilliseconds() const;

    uint64_t maxMilliseconds() const { return config_.maxMilliseconds; }
    uint32_t maxNewTokens() const { return config_.maxNewTokens; }
    const K2TLSConfig& config() const { return config_; }

private:
    K2TLSConfig config_;
    Clock::time_point start_;
    bool cancelled_ = false;
};

// ---------------------------------------------------------------------------
// RAII request scope
// ---------------------------------------------------------------------------
class K2TLSRequestScope {
public:
    using CleanupFn = std::function<void()>;

    explicit K2TLSRequestScope(CleanupFn cleanup = {});
    ~K2TLSRequestScope();

    K2TLSRequestScope(const K2TLSRequestScope&) = delete;
    K2TLSRequestScope& operator=(const K2TLSRequestScope&) = delete;

    void cleanupNow();
    bool cleaned() const;

private:
    CleanupFn cleanup_;
    bool cleaned_ = false;
};

// ---------------------------------------------------------------------------
// Generic generation runner
// ---------------------------------------------------------------------------
template <typename ExecuteToken, typename Checkpoint>
K2TLSResult RunTimeLimitedGeneration(
    const K2TLSConfig& config,
    ExecuteToken&& executeToken,
    Checkpoint&& checkpoint,
    K2TLSRequestScope* requestScope = nullptr)
{
    K2TimeLimit budget(config);
    K2TLSResult result;

    uint32_t generated = 0;
    uint64_t residentBytes = 0;

    while (true) {
        const K2TLSStatus preStatus = budget.check(generated, residentBytes);

        if (preStatus != K2TLSStatus::OK) {
            result.status = preStatus;
            result.generatedTokens = generated;
            result.elapsedMilliseconds = budget.elapsedMilliseconds();
            result.partialResult = generated > 0;

            if (preStatus == K2TLSStatus::TIME_LIMIT) {
                result.message = "K2-TLS time limit reached";
            } else if (preStatus == K2TLSStatus::TOKEN_LIMIT) {
                result.message = "K2-TLS token limit reached";
            } else if (preStatus == K2TLSStatus::CANCELLED) {
                result.message = "K2-TLS request cancelled";
            } else if (preStatus == K2TLSStatus::MEMORY_LIMIT) {
                result.message = "K2-TLS memory limit reached";
            }

            if (requestScope) requestScope->cleanupNow();
            return result;
        }

        if (!checkpoint(generated, residentBytes)) {
            result.status = K2TLSStatus::ERROR;
            result.generatedTokens = generated;
            result.elapsedMilliseconds = budget.elapsedMilliseconds();
            result.partialResult = generated > 0;
            result.message = "K2-TLS checkpoint failed";

            if (requestScope) requestScope->cleanupNow();
            return result;
        }

        const bool tokenOK = executeToken();

        if (!tokenOK) {
            result.status = K2TLSStatus::ERROR;
            result.generatedTokens = generated;
            result.elapsedMilliseconds = budget.elapsedMilliseconds();
            result.partialResult = generated > 0;
            result.message = "K2-TLS token execution failed";

            if (requestScope) requestScope->cleanupNow();
            return result;
        }

        ++generated;

        // Check immediately after the expensive token operation.
        const K2TLSStatus postStatus = budget.check(generated, residentBytes);

        if (postStatus != K2TLSStatus::OK) {
            result.status = postStatus;
            result.generatedTokens = generated;
            result.elapsedMilliseconds = budget.elapsedMilliseconds();
            result.partialResult = generated > 0;

            if (postStatus == K2TLSStatus::TIME_LIMIT) {
                result.message = "K2-TLS time limit reached after token";
            } else if (postStatus == K2TLSStatus::TOKEN_LIMIT) {
                result.message = "K2-TLS token limit reached";
            }

            if (requestScope) requestScope->cleanupNow();
            return result;
        }
    }
}

} // namespace rawrxd::deep2
