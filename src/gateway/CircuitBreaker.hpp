/**
 * CircuitBreaker.hpp
 *
 * Phase N Batch 4/5: Circuit Breaker & Resilience Patterns
 *
 * Circuit breaker, retry, bulkhead, and timeout patterns for
 * building resilient distributed systems.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <future>
#include <queue>

namespace Gateway {

// ============================================================================
// Forward Declarations
// ============================================================================

class CircuitBreaker;
class RetryPolicy;
class Bulkhead;
class Timeout;
class ResiliencePipeline;

// ============================================================================
// Circuit Breaker State
// ============================================================================

enum class CircuitState {
    CLOSED,     // Normal operation
    OPEN,       // Failing, rejecting requests
    HALF_OPEN   // Testing if service recovered
};

std::string CircuitStateToString(CircuitState state);

// ============================================================================
// Circuit Breaker
// ============================================================================

/**
 * Circuit breaker pattern implementation.
 */
class CircuitBreaker {
public:
    struct Config {
        std::string name;
        uint32_t failureThreshold;
        uint32_t successThreshold;
        std::chrono::seconds openDuration;
        std::chrono::seconds halfOpenMaxCalls;
        std::optional<std::function<bool(const std::exception&)>> shouldHandleException;
        bool automaticTransition;
    };
    
    struct Metrics {
        uint64_t callsSucceeded;
        uint64_t callsFailed;
        uint64_t callsRejected;
        uint64_t stateTransitions;
        CircuitState currentState;
        std::chrono::system_clock::time_point lastStateChange;
        std::optional<std::chrono::system_clock::time_point> nextAttempt;
    };
    
    explicit CircuitBreaker(const Config& config);
    
    // Execution
    template<typename T>
    T Execute(std::function<T()> action);
    
    template<typename T>
    std::optional<T> Execute(std::function<T()> action,
                               std::function<T()> fallback);
    
    // Async execution
    template<typename T>
    std::future<T> ExecuteAsync(std::function<T()> action);
    
    // State management
    CircuitState GetState() const;
    bool IsClosed() const { return GetState() == CircuitState::CLOSED; }
    bool IsOpen() const { return GetState() == CircuitState::OPEN; }
    bool IsHalfOpen() const { return GetState() == CircuitState::HALF_OPEN; }
    
    void Trip();
    void Reset();
    void Isolate();
    
    // Manual state transition
    void TransitionTo(CircuitState newState);
    
    // Metrics
    Metrics GetMetrics() const;
    void ResetMetrics();
    
    // Events
    using StateChangeCallback = std::function<void(CircuitState, CircuitState)>;
    void OnStateChange(StateChangeCallback callback);
    
    using FailureCallback = std::function<void(const std::exception&)>;
    void OnFailure(FailureCallback callback);
    
    using SuccessCallback = std::function<void()>;
    void OnSuccess(SuccessCallback callback);
    
private:
    Config config_;
    std::atomic<CircuitState> state_;
    std::atomic<uint32_t> failureCount_;
    std::atomic<uint32_t> successCount_;
    std::atomic<uint32_t> halfOpenCalls_;
    std::chrono::system_clock::time_point lastFailureTime_;
    std::chrono::system_clock::time_point stateChangedAt_;
    
    mutable std::mutex mutex_;
    
    Metrics metrics_;
    mutable std::mutex metricsMutex_;
    
    StateChangeCallback stateChangeCallback_;
    FailureCallback failureCallback_;
    SuccessCallback successCallback_;
    
    void RecordSuccess();
    void RecordFailure(const std::exception& e);
    bool ShouldHandleException(const std::exception& e) const;
    void TransitionState(CircuitState newState);
    bool CanAttempt();
};

// ============================================================================
// Retry Policy
// ============================================================================

/**
 * Retry policy configuration.
 */
class RetryPolicy {
public:
    enum class BackoffStrategy {
        FIXED,
        LINEAR,
        EXPONENTIAL,
        EXPONENTIAL_WITH_JITTER
    };
    
    struct Config {
        uint32_t maxRetries;
        std::chrono::milliseconds baseDelay;
        std::chrono::milliseconds maxDelay;
        BackoffStrategy backoffStrategy;
        std::vector<std::string> retryableExceptions;
        std::optional<std::function<bool(const std::exception&)>> shouldRetry;
        bool retryOnTimeout;
    };
    
    explicit RetryPolicy(const Config& config);
    
    // Static factory methods
    static RetryPolicy NoRetry();
    static RetryPolicy FixedDelay(uint32_t maxRetries, std::chrono::milliseconds delay);
    static RetryPolicy ExponentialBackoff(uint32_t maxRetries,
                                           std::chrono::milliseconds baseDelay,
                                           std::chrono::milliseconds maxDelay);
    static RetryPolicy ExponentialBackoffWithJitter(uint32_t maxRetries,
                                                      std::chrono::milliseconds baseDelay,
                                                      std::chrono::milliseconds maxDelay);
    
    // Execution
    template<typename T>
    T Execute(std::function<T()> action);
    
    template<typename T>
    std::optional<T> Execute(std::function<T()> action,
                               std::function<void(uint32_t, const std::exception&)> onRetry);
    
    // Async execution
    template<typename T>
    std::future<T> ExecuteAsync(std::function<T()> action);
    
    // Policy checks
    bool ShouldRetry(uint32_t attempt, const std::exception& e) const;
    std::chrono::milliseconds GetDelay(uint32_t attempt) const;
    
    // Metrics
    struct RetryMetrics {
        uint64_t totalAttempts;
        uint64_t successfulRetries;
        uint64_t failedRetries;
        uint64_t successes;
        uint64_t failures;
        double averageRetries;
    };
    RetryMetrics GetMetrics() const;
    void ResetMetrics();
    
private:
    Config config_;
    RetryMetrics metrics_;
    mutable std::mutex mutex_;
    
    std::chrono::milliseconds CalculateExponentialDelay(uint32_t attempt) const;
    std::chrono::milliseconds CalculateJitterDelay(uint32_t attempt) const;
    bool IsRetryableException(const std::exception& e) const;
};

// ============================================================================
// Bulkhead
// ============================================================================

/**
 * Bulkhead pattern implementation (resource isolation).
 */
class Bulkhead {
public:
    struct Config {
        std::string name;
        uint32_t maxConcurrentCalls;
        uint32_t maxWaitQueueSize;
        std::chrono::milliseconds maxWaitDuration;
        bool fairQueue;
    };
    
    struct Metrics {
        uint64_t callsExecuted;
        uint64_t callsRejected;
        uint64_t callsQueued;
        uint64_t callsTimedOut;
        uint32_t availableSlots;
        uint32_t queueSize;
    };
    
    explicit Bulkhead(const Config& config);
    ~Bulkhead();
    
    // Execution
    template<typename T>
    T Execute(std::function<T()> action);
    
    template<typename T>
    std::optional<T> Execute(std::function<T()> action,
                               std::chrono::milliseconds timeout);
    
    // Async execution
    template<typename T>
    std::future<T> ExecuteAsync(std::function<T()> action);
    
    // Slot management
    bool TryAcquireSlot(std::chrono::milliseconds timeout);
    void ReleaseSlot();
    uint32_t GetAvailableSlots() const;
    uint32_t GetQueueSize() const;
    
    // Metrics
    Metrics GetMetrics() const;
    void ResetMetrics();
    
private:
    Config config_;
    std::atomic<uint32_t> availableSlots_;
    std::queue<std::condition_variable*> waitQueue_;
    mutable std::mutex mutex_;
    
    Metrics metrics_;
    mutable std::mutex metricsMutex_;
};

// ============================================================================
// Timeout
// ============================================================================

/**
 * Timeout pattern implementation.
 */
class Timeout {
public:
    struct Config {
        std::string name;
        std::chrono::milliseconds duration;
        bool cancelOnTimeout;
    };
    
    struct Metrics {
        uint64_t callsExecuted;
        uint64_t callsTimedOut;
        double averageExecutionTimeMs;
    };
    
    explicit Timeout(const Config& config);
    
    // Execution
    template<typename T>
    T Execute(std::function<T()> action);
    
    template<typename T>
    std::optional<T> Execute(std::function<T()> action,
                               std::function<T()> fallback);
    
    // Async execution
    template<typename T>
    std::future<T> ExecuteAsync(std::function<T()> action);
    
    // Duration
    std::chrono::milliseconds GetDuration() const { return config_.duration; }
    void SetDuration(std::chrono::milliseconds duration);
    
    // Metrics
    Metrics GetMetrics() const;
    void ResetMetrics();
    
private:
    Config config_;
    Metrics metrics_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Cache Aside
// ============================================================================

/**
 * Cache-aside pattern implementation.
 */
class CacheAside {
public:
    struct Config {
        std::string name;
        std::chrono::milliseconds ttl;
        std::optional<uint64_t> maxSize;
        bool cacheNullValues;
    };
    
    template<typename T>
    using CacheLoader = std::function<T(const std::string&)>;
    
    explicit CacheAside(const Config& config);
    
    // Cache operations
    template<typename T>
    std::optional<T> Get(const std::string& key);
    
    template<typename T>
    T GetOrLoad(const std::string& key, CacheLoader<T> loader);
    
    template<typename T>
    void Put(const std::string& key, const T& value);
    
    void Invalidate(const std::string& key);
    void InvalidatePattern(const std::string& pattern);
    void InvalidateAll();
    
    // Statistics
    struct CacheMetrics {
        uint64_t hits;
        uint64_t misses;
        uint64_t loads;
        uint64_t evictions;
        double hitRate;
        size_t size;
    };
    CacheMetrics GetMetrics() const;
    void ResetMetrics();
    
private:
    Config config_;
    
    struct CacheEntry {
        std::vector<uint8_t> data;
        std::chrono::system_clock::time_point expiresAt;
    };
    std::map<std::string, CacheEntry> cache_;
    mutable std::mutex mutex_;
    
    CacheMetrics metrics_;
    mutable std::mutex metricsMutex_;
    
    void EvictIfNeeded();
    void CleanupExpired();
};

// ============================================================================
// Fallback
// ============================================================================

/**
 * Fallback pattern implementation.
 */
class Fallback {
public:
    struct Config {
        std::string name;
        bool propagateExceptions;
        std::optional<uint32_t> maxFallbackCalls;
    };
    
    explicit Fallback(const Config& config);
    
    // Execution
    template<typename T>
    T Execute(std::function<T()> action, std::function<T()> fallback);
    
    template<typename T>
    std::optional<T> ExecuteOptional(std::function<std::optional<T>()> action,
                                        std::function<T()> fallback);
    
    // Async execution
    template<typename T>
    std::future<T> ExecuteAsync(std::function<T()> action,
                                   std::function<T()> fallback);
    
    // Metrics
    struct FallbackMetrics {
        uint64_t callsSucceeded;
        uint64_t callsFailed;
        uint64_t fallbackCalls;
        uint64_t fallbackSuccesses;
    };
    FallbackMetrics GetMetrics() const;
    void ResetMetrics();
    
private:
    Config config_;
    FallbackMetrics metrics_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Resilience Pipeline
// ============================================================================

/**
 * Pipeline combining multiple resilience patterns.
 */
class ResiliencePipeline {
public:
    struct Config {
        std::optional<CircuitBreaker::Config> circuitBreaker;
        std::optional<RetryPolicy::Config> retryPolicy;
        std::optional<Bulkhead::Config> bulkhead;
        std::optional<Timeout::Config> timeout;
        std::optional<CacheAside::Config> cache;
        std::optional<Fallback::Config> fallback;
    };
    
    explicit ResiliencePipeline(const Config& config);
    
    // Execution
    template<typename T>
    T Execute(std::function<T()> action);
    
    template<typename T>
    T Execute(std::function<T()> action, std::function<T()> fallback);
    
    template<typename T>
    std::future<T> ExecuteAsync(std::function<T()> action);
    
    // Component access
    std::optional<CircuitBreaker&> GetCircuitBreaker();
    std::optional<RetryPolicy&> GetRetryPolicy();
    std::optional<Bulkhead&> GetBulkhead();
    std::optional<Timeout&> GetTimeout();
    std::optional<CacheAside&> GetCache();
    std::optional<Fallback&> GetFallback();
    
    // Metrics
    struct PipelineMetrics {
        CircuitBreaker::Metrics circuitBreakerMetrics;
        RetryPolicy::RetryMetrics retryMetrics;
        Bulkhead::Metrics bulkheadMetrics;
        Timeout::Metrics timeoutMetrics;
        CacheAside::CacheMetrics cacheMetrics;
        Fallback::FallbackMetrics fallbackMetrics;
        uint64_t totalCalls;
        uint64_t successfulCalls;
        uint64_t failedCalls;
    };
    PipelineMetrics GetMetrics() const;
    void ResetMetrics();
    
private:
    Config config_;
    
    std::optional<CircuitBreaker> circuitBreaker_;
    std::optional<RetryPolicy> retryPolicy_;
    std::optional<Bulkhead> bulkhead_;
    std::optional<Timeout> timeout_;
    std::optional<CacheAside> cache_;
    std::optional<Fallback> fallback_;
    
    template<typename T>
    T ExecuteInternal(std::function<T()> action, std::optional<std::function<T()>> fallback);
};

// ============================================================================
// Resilience Middleware
// ============================================================================

/**
 * Resilience middleware for API gateway.
 */
class ResilienceMiddleware : public Middleware {
public:
    struct Config {
        std::map<std::string, ResiliencePipeline::Config> routePipelines;
        ResiliencePipeline::Config defaultPipeline;
        bool enableMetrics;
    };
    
    explicit ResilienceMiddleware(const Config& config);
    
    std::string GetName() const override { return "Resilience"; }
    int GetPriority() const override { return 5; }
    
    HTTPResponse Process(const HTTPRequest& request,
                         std::function<HTTPResponse(const HTTPRequest&)> next) override;
    
    // Pipeline management
    void SetPipeline(const std::string& routePattern, const ResiliencePipeline::Config& config);
    void RemovePipeline(const std::string& routePattern);
    
    // Metrics
    ResiliencePipeline::PipelineMetrics GetMetrics() const;
    void ResetMetrics();
    
private:
    Config config_;
    std::map<std::string, ResiliencePipeline> pipelines_;
    ResiliencePipeline defaultPipeline_;
    mutable std::mutex mutex_;
    
    ResiliencePipeline& GetPipelineForRoute(const std::string& path);
};

// ============================================================================
// Chaos Engineering
// ============================================================================

/**
 * Chaos engineering for resilience testing.
 */
class ChaosMonkey {
public:
    struct Config {
        bool enabled;
        double failureRate;
        double latencyRate;
        std::chrono::milliseconds minLatency;
        std::chrono::milliseconds maxLatency;
        std::vector<std::string> targetServices;
        std::optional<std::function<bool(const HTTPRequest&)>> shouldInject;
    };
    
    explicit ChaosMonkey(const Config& config);
    
    // Lifecycle
    void Enable();
    void Disable();
    bool IsEnabled() const;
    
    // Injection
    bool ShouldInjectFailure(const HTTPRequest& request);
    bool ShouldInjectLatency(const HTTPRequest& request);
    std::chrono::milliseconds GetLatency();
    
    // Execution wrapper
    template<typename T>
    T Execute(std::function<T()> action, const HTTPRequest& request);
    
    // Statistics
    struct ChaosMetrics {
        uint64_t failuresInjected;
        uint64_t latenciesInjected;
        uint64_t callsAffected;
    };
    ChaosMetrics GetMetrics() const;
    void ResetMetrics();
    
private:
    Config config_;
    std::atomic<bool> enabled_;
    ChaosMetrics metrics_;
    mutable std::mutex mutex_;
    
    bool ShouldInject(const HTTPRequest& request);
};

} // namespace Gateway
