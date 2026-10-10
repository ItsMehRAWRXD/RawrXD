// ============================================================================
// File: src/agent/adaptive_retry.hpp
//
// Purpose: Adaptive Retry System with Circuit Breakers, Jitter, and Per-Operation Policies
// Production-ready implementation for enterprise agentic execution
//
// Design Principles:
// - Zero exceptions, structured results only (PatchResult style)
// - NO DEPENDENCIES: pure C++20 standard library only. No Qt, no third-party.
// - Thread-safe with mutex protection
// - Configurable per-operation-type policies
// - Circuit breaker pattern for cascading failure prevention
// - Exponential backoff with jitter for thundering herd prevention
// - Observable metrics for monitoring and tuning
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <random>
#include <optional>

// Forward declaration for metrics callback
using RetryMetricsCallback = std::function<void(const std::string& operation, const std::string& metric, double value)>;

// ============================================================================
// RetryPolicy — Per-operation-type retry configuration
// ============================================================================
struct RetryPolicy {
    // Identity
    std::string operationType;        // e.g., "llm_invocation", "file_edit", "build", "test"
    std::string description;          // Human-readable description
    
    // Retry configuration
    int maxAttempts = 3;              // Total attempts (1 = no retry)
    int baseDelayMs = 1000;           // Initial delay before first retry
    int maxDelayMs = 30000;           // Cap on delay
    double backoffMultiplier = 2.0;   // Exponential factor
    double jitterFactor = 0.1;        // Random jitter ±factor (0.0-1.0)
    
    // Circuit breaker
    bool enableCircuitBreaker = true;
    int failureThreshold = 5;         // Failures before opening circuit
    int successThreshold = 2;         // Successes to close circuit (half-open)
    int circuitTimeoutMs = 60000;     // Time before half-open attempt
    
    // Retryable error classification
    std::vector<std::string> retryableErrorPatterns;  // Substring match on error
    std::vector<std::string> nonRetryableErrorPatterns; // Substring match - never retry
    
    // Validation
    bool validate() const {
        return maxAttempts >= 1 && baseDelayMs > 0 && maxDelayMs >= baseDelayMs &&
               backoffMultiplier >= 1.0 && jitterFactor >= 0.0 && jitterFactor <= 1.0 &&
               failureThreshold > 0 && successThreshold > 0 && circuitTimeoutMs > 0;
    }
    
    // Default policies for common operation types
    static RetryPolicy defaultLLMInvocation() {
        RetryPolicy p;
        p.operationType = "llm_invocation";
        p.description = "LLM API calls (Ollama, Claude, OpenAI)";
        p.maxAttempts = 3;
        p.baseDelayMs = 2000;
        p.maxDelayMs = 30000;
        p.backoffMultiplier = 2.0;
        p.jitterFactor = 0.2;
        p.retryableErrorPatterns = {"timeout", "connection", "503", "504", "rate limit", "temporary"};
        p.nonRetryableErrorPatterns = {"401", "403", "invalid", "unauthorized", "quota exceeded"};
        return p;
    }
    
    static RetryPolicy defaultFileOperation() {
        RetryPolicy p;
        p.operationType = "file_operation";
        p.description = "File read/write/edit operations";
        p.maxAttempts = 3;
        p.baseDelayMs = 500;
        p.maxDelayMs = 5000;
        p.backoffMultiplier = 1.5;
        p.jitterFactor = 0.1;
        p.retryableErrorPatterns = {"locked", "busy", "permission denied", "sharing violation"};
        p.nonRetryableErrorPatterns = {"not found", "access denied", "disk full", "invalid path"};
        return p;
    }
    
    static RetryPolicy defaultBuildOperation() {
        RetryPolicy p;
        p.operationType = "build";
        p.description = "Build system execution (CMake, MSBuild, etc.)";
        p.maxAttempts = 2;
        p.baseDelayMs = 5000;
        p.maxDelayMs = 60000;
        p.backoffMultiplier = 2.0;
        p.jitterFactor = 0.1;
        p.retryableErrorPatterns = {"transient", "intermittent", "resource temporarily unavailable"};
        p.nonRetryableErrorPatterns = {"syntax error", "missing dependency", "compilation failed"};
        return p;
    }
    
    static RetryPolicy defaultTestOperation() {
        RetryPolicy p;
        p.operationType = "test";
        p.description = "Test execution";
        p.maxAttempts = 2;
        p.baseDelayMs = 3000;
        p.maxDelayMs = 30000;
        p.backoffMultiplier = 2.0;
        p.jitterFactor = 0.15;
        p.retryableErrorPatterns = {"flaky", "timeout", "intermittent", "resource"};
        p.nonRetryableErrorPatterns = {"assertion failed", "compilation error", "missing test"};
        return p;
    }
    
    static RetryPolicy defaultGitOperation() {
        RetryPolicy p;
        p.operationType = "git";
        p.description = "Git operations (commit, push, pull, merge)";
        p.maxAttempts = 3;
        p.baseDelayMs = 1000;
        p.maxDelayMs = 15000;
        p.backoffMultiplier = 2.0;
        p.jitterFactor = 0.1;
        p.retryableErrorPatterns = {"lock", "index.lock", "could not lock", "rejected", "non-fast-forward"};
        p.nonRetryableErrorPatterns = {"not a git repository", "permission denied", "authentication failed"};
        return p;
    }
    
    // Serialize to JSON
    std::string toJSON() const;
    
    // Deserialize from JSON
    static RetryPolicy fromJSON(const std::string& json);
};

// ============================================================================
// CircuitBreakerState — Circuit breaker state machine
// ============================================================================
enum class CircuitState {
    Closed,      // Normal operation, requests pass through
    Open,        // Failing fast, requests rejected immediately
    HalfOpen     // Testing if service recovered, limited requests allowed
};

struct CircuitBreakerSnapshot {
    std::string operationType;
    CircuitState state = CircuitState::Closed;
    int failureCount = 0;
    int successCount = 0;
    int64_t lastFailureTime = 0;
    int64_t lastStateChange = 0;

    std::string stateString() const {
        switch (state) {
            case CircuitState::Closed:   return "closed";
            case CircuitState::Open:     return "open";
            case CircuitState::HalfOpen: return "half_open";
        }
        return "unknown";
    }

    CircuitState getState() const { return state; }
    int getFailureCount() const { return failureCount; }
    int getSuccessCount() const { return successCount; }
};

struct CircuitBreaker {
    std::string operationType;
    std::atomic<CircuitState> state{CircuitState::Closed};
    std::atomic<int> failureCount{0};
    std::atomic<int> successCount{0};
    std::atomic<int64_t> lastFailureTime{0};  // epoch ms
    std::atomic<int64_t> lastStateChange{0};  // epoch ms
    std::mutex mutex;  // For complex state transitions
    
    // Configuration (immutable after construction)
    int failureThreshold;
    int successThreshold;
    int circuitTimeoutMs;
    
    CircuitBreaker() = default;
    CircuitBreaker(const std::string& opType, int failThresh, int succThresh, int timeoutMs)
        : operationType(opType), failureThreshold(failThresh), successThreshold(succThresh), circuitTimeoutMs(timeoutMs) {}
    
    // Check if request should be allowed
    bool allowRequest() {
        auto currentState = state.load();
        
        if (currentState == CircuitState::Closed) {
            return true;
        }
        
        if (currentState == CircuitState::Open) {
            // Check if timeout expired to transition to half-open
            int64_t now = nowMs();
            if (now - lastStateChange.load() >= circuitTimeoutMs) {
                std::lock_guard<std::mutex> lock(mutex);
                if (state.load() == CircuitState::Open) {
                    state.store(CircuitState::HalfOpen);
                    lastStateChange.store(now);
                    successCount.store(0);
                    return true; // Allow one test request
                }
            }
            return false; // Circuit open, reject
        }
        
        // HalfOpen - allow limited requests
        return true;
    }
    
    // Record success
    void recordSuccess() {
        auto currentState = state.load();
        
        if (currentState == CircuitState::HalfOpen) {
            int successes = ++successCount;
            if (successes >= successThreshold) {
                std::lock_guard<std::mutex> lock(mutex);
                if (state.load() == CircuitState::HalfOpen) {
                    state.store(CircuitState::Closed);
                    failureCount.store(0);
                    lastStateChange.store(nowMs());
                }
            }
        } else if (currentState == CircuitState::Closed) {
            failureCount.store(0); // Reset failure count on success
        }
    }
    
    // Record failure
    void recordFailure() {
        auto currentState = state.load();
        
        if (currentState == CircuitState::Closed) {
            int failures = ++failureCount;
            if (failures >= failureThreshold) {
                std::lock_guard<std::mutex> lock(mutex);
                if (state.load() == CircuitState::Closed) {
                    state.store(CircuitState::Open);
                    lastStateChange.store(nowMs());
                }
            }
        } else if (currentState == CircuitState::HalfOpen) {
            // Any failure in half-open goes back to open
            std::lock_guard<std::mutex> lock(mutex);
            if (state.load() == CircuitState::HalfOpen) {
                state.store(CircuitState::Open);
                lastStateChange.store(nowMs());
                successCount.store(0);
            }
        }
        // If already Open, stay Open
    }
    
    // Get current state for monitoring
    CircuitState getState() const { return state.load(); }
    int getFailureCount() const { return failureCount.load(); }
    int getSuccessCount() const { return successCount.load(); }
    
    std::string stateString() const {
        switch (state.load()) {
            case CircuitState::Closed:   return "closed";
            case CircuitState::Open:     return "open";
            case CircuitState::HalfOpen: return "half_open";
        }
        return "unknown";
    }
    
private:
    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// ============================================================================
// RetryResult — Structured result for retry operations
// ============================================================================
struct RetryResult {
    bool success = false;
    std::string result;           // Operation result on success
    std::string errorMessage;     // Error message on failure
    int attemptsMade = 0;         // Total attempts including initial
    int64_t totalElapsedMs = 0;   // Total time spent
    bool circuitBreakerTriggered = false;
    std::vector<std::string> attemptErrors;  // Errors from each attempt

    // Factory methods (named to avoid clashing with the data members)
    static RetryResult makeOk(const std::string& resultValue, int attempts, int64_t elapsedMs,
                              const std::vector<std::string>& errors = {}) {
        RetryResult r;
        r.success = true;
        r.result = resultValue;
        r.attemptsMade = attempts;
        r.totalElapsedMs = elapsedMs;
        r.attemptErrors = errors;
        return r;
    }

    static RetryResult makeError(const std::string& message, int attempts, int64_t elapsedMs,
                                 bool circuitBreaker = false,
                                 const std::vector<std::string>& errors = {}) {
        RetryResult r;
        r.success = false;
        r.errorMessage = message;
        r.attemptsMade = attempts;
        r.totalElapsedMs = elapsedMs;
        r.circuitBreakerTriggered = circuitBreaker;
        r.attemptErrors = errors;
        return r;
    }
};

// ============================================================================
// AdaptiveRetryEngine — Core retry execution engine
// ============================================================================
class AdaptiveRetryEngine {
public:
    using OperationFn = std::function<std::string()>;  // Returns result or throws
    using ShouldRetryFn = std::function<bool(const std::string& error)>;
    
    explicit AdaptiveRetryEngine();
    ~AdaptiveRetryEngine();
    
    // ---- Policy Management ----
    
    // Register a retry policy for an operation type
    void registerPolicy(const RetryPolicy& policy);
    
    // Get policy for operation type (returns default if not found)
    const RetryPolicy* getPolicy(const std::string& operationType) const;
    
    // Get all registered policies
    std::vector<RetryPolicy> getAllPolicies() const;
    
    // Remove a policy
    bool removePolicy(const std::string& operationType);
    
    // Load policies from JSON file
    bool loadPoliciesFromFile(const std::string& filePath);
    
    // Save policies to JSON file
    bool savePoliciesToFile(const std::string& filePath) const;
    
    // ---- Execution ----
    
    // Execute with adaptive retry
    // Returns RetryResult with success/failure details
    RetryResult execute(const std::string& operationType, OperationFn operation);
    
    // Execute with custom should-retry predicate
    RetryResult execute(const std::string& operationType, OperationFn operation, ShouldRetryFn shouldRetry);
    
    // ---- Circuit Breaker Management ----
    
    // Manually open/close circuit breaker for an operation type
    void forceCircuitOpen(const std::string& operationType);
    void forceCircuitClosed(const std::string& operationType);
    
    // Get circuit breaker state
    std::optional<CircuitBreakerSnapshot> getCircuitBreaker(const std::string& operationType) const;
    
    // Get all circuit breaker states
    std::vector<CircuitBreakerSnapshot> getAllCircuitBreakers() const;
    
    // ---- Metrics & Monitoring ----
    
    // Set metrics callback
    void setMetricsCallback(RetryMetricsCallback cb) { m_metricsCb = cb; }
    
    // Get statistics for an operation type
    struct OperationStats {
        std::string operationType;
        int64_t totalExecutions = 0;
        int64_t successfulExecutions = 0;
        int64_t failedExecutions = 0;
        int64_t totalRetries = 0;
        int64_t totalTimeMs = 0;
        double avgAttemptsPerExecution = 0.0;
        CircuitState circuitState = CircuitState::Closed;
    };
    
    OperationStats getStats(const std::string& operationType) const;
    std::vector<OperationStats> getAllStats() const;
    
    // Reset statistics
    void resetStats(const std::string& operationType);
    void resetAllStats();
    
    // Export statistics as JSON
    std::string exportStatsJSON() const;
    
private:
    // Internal execution with delay calculation
    int calculateDelay(const RetryPolicy& policy, int attempt, std::mt19937& rng) const;
    
    // Check if error is retryable per policy
    bool isRetryableError(const RetryPolicy& policy, const std::string& error) const;
    
    // Emit metrics
    void emitMetric(const std::string& operation, const std::string& metric, double value) const;
    
    // Storage
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, RetryPolicy> m_policies;
    std::unordered_map<std::string, std::unique_ptr<CircuitBreaker>> m_circuitBreakers;
    
    // Statistics
    struct Stats {
        std::atomic<int64_t> totalExecutions{0};
        std::atomic<int64_t> successfulExecutions{0};
        std::atomic<int64_t> failedExecutions{0};
        std::atomic<int64_t> totalRetries{0};
        std::atomic<int64_t> totalTimeMs{0};
    };
    std::unordered_map<std::string, std::unique_ptr<Stats>> m_stats;
    
    // Metrics callback
    RetryMetricsCallback m_metricsCb;
    
    // Random generator for jitter
    mutable std::mutex m_rngMutex;
    std::mt19937 m_rng;
    
    // Current time in ms
    static int64_t nowMs();
};

// ============================================================================
// Convenience: Global instance accessor
// ============================================================================
AdaptiveRetryEngine& getGlobalRetryEngine();

// ============================================================================
// Integration helpers — dependency-free
// ============================================================================
//
// RawrXD is a NO-DEPENDENCY project: no Qt, no external libraries. These
// helpers therefore take plain function objects so any front-end (Win32 IDE,
// CLI, HTTP server) can wire its own bridge in without this engine knowing
// about it.
//
//   // Execute an async operation with retry + circuit protection.
//   bool ok = retryCall("llm_invocation", [] { return bridge->executeWish(w); });

// Execute an operation with the named retry policy. The operation must throw
// on failure (std::runtime_error etc.) or return normally on success.
// Returns true when the operation succeeded on some attempt.
bool retryCall(const std::string& operationType,
               const std::function<void()>& operation);

// Overload returning the operation's value.
std::string retryCallWithResult(const std::string& operationType,
                                const std::function<std::string()>& operation);

// Classify an error string using the policy's retryable/non-retryable patterns.
bool isRetryableUnderPolicy(const std::string& operationType, const std::string& error);