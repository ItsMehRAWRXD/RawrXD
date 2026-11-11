// Phase D.10 Batch 3/5: Reliability & Fault Tolerance
// Production-grade reliability engineering and fault tolerance
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <optional>

namespace Sovereign {
namespace Production {

// ============================================================================
// Circuit Breaker Pattern
// ============================================================================

enum class CircuitState {
    CLOSED = 0,      // Normal operation
    OPEN = 1,        // Failing, reject requests
    HALF_OPEN = 2    // Testing if service recovered
};

struct CircuitBreakerConfig {
    int failure_threshold = 5;
    std::chrono::seconds timeout{30};
    int success_threshold = 3;
    std::chrono::milliseconds slow_call_duration{1000};
    float slow_call_rate_threshold = 0.5f;
    bool automatic_transition = true;
};

class CircuitBreaker {
public:
    explicit CircuitBreaker(const std::string& name, const CircuitBreakerConfig& config);
    
    bool AllowRequest();
    void RecordSuccess();
    void RecordFailure();
    void RecordSlowCall();
    void RecordTimeout();
    
    CircuitState GetState() const;
    std::string GetName() const { return name_; }
    
    // Metrics
    struct Metrics {
        uint64_t success_count = 0;
        uint64_t failure_count = 0;
        uint64_t slow_call_count = 0;
        uint64_t rejected_count = 0;
        CircuitState state = CircuitState::CLOSED;
        float failure_rate = 0.0f;
        float slow_call_rate = 0.0f;
    };
    
    Metrics GetMetrics() const;
    void Reset();
    
private:
    std::string name_;
    CircuitBreakerConfig config_;
    
    std::atomic<CircuitState> state_{CircuitState::CLOSED};
    std::atomic<int> failure_count_{0};
    std::atomic<int> success_count_{0};
    std::atomic<int> slow_call_count_{0};
    std::atomic<int> total_calls_{0};
    std::atomic<uint64_t> rejected_count_{0};
    
    std::chrono::steady_clock::time_point last_failure_time_;
    std::chrono::steady_clock::time_point last_state_change_;
    mutable std::mutex state_mutex_;
    
    void TransitionTo(CircuitState new_state);
    bool ShouldTransitionToOpen();
    bool ShouldTransitionToHalfOpen();
    bool ShouldTransitionToClosed();
};

// ============================================================================
// Bulkhead Pattern
// ============================================================================

class Bulkhead {
public:
    struct Config {
        int max_concurrent_calls = 10;
        int max_wait_queue_size = 100;
        std::chrono::milliseconds max_wait_duration{1000};
    };
    
    explicit Bulkhead(const std::string& name, const Config& config);
    
    // Execution
    template<typename Func>
    auto Execute(Func&& func) -> std::optional<decltype(func())> {
        if (!AcquireSlot()) {
            return std::nullopt;
        }
        
        try {
            auto result = func();
            ReleaseSlot();
            return result;
        } catch (...) {
            ReleaseSlot();
            throw;
        }
    }
    
    bool TryExecute(std::function<void()> func);
    
    // Stats
    struct Stats {
        int available_slots = 0;
        int active_calls = 0;
        int queued_calls = 0;
        uint64_t total_calls = 0;
        uint64_t rejected_calls = 0;
    };
    
    Stats GetStats() const;
    
private:
    std::string name_;
    Config config_;
    
    std::atomic<int> active_calls_{0};
    std::atomic<int> queued_calls_{0};
    std::atomic<uint64_t> total_calls_{0};
    std::atomic<uint64_t> rejected_calls_{0};
    
    std::mutex slots_mutex_;
    std::condition_variable slots_cv_;
    
    bool AcquireSlot();
    void ReleaseSlot();
};

// ============================================================================
// Retry Policy
// ============================================================================

enum class RetryBackoffStrategy {
    FIXED = 0,
    LINEAR = 1,
    EXPONENTIAL = 2,
    EXPONENTIAL_WITH_JITTER = 3
};

struct RetryPolicy {
    int max_attempts = 3;
    std::chrono::milliseconds base_delay{100};
    std::chrono::milliseconds max_delay{5000};
    RetryBackoffStrategy backoff_strategy = RetryBackoffStrategy::EXPONENTIAL_WITH_JITTER;
    std::vector<int> retryable_status_codes = {408, 429, 500, 502, 503, 504};
    std::vector<std::string> retryable_exceptions;
};

class RetryExecutor {
public:
    explicit RetryExecutor(const RetryPolicy& policy);
    
    template<typename Func>
    auto Execute(Func&& func) -> decltype(func()) {
        int attempt = 0;
        std::exception_ptr last_exception;
        
        while (attempt < policy_.max_attempts) {
            try {
                return func();
            } catch (...) {
                last_exception = std::current_exception();
                
                if (!ShouldRetry(++attempt)) {
                    std::rethrow_exception(last_exception);
                }
                
                auto delay = CalculateDelay(attempt);
                std::this_thread::sleep_for(delay);
            }
        }
        
        std::rethrow_exception(last_exception);
    }
    
    // Async execution
    template<typename Func, typename Callback>
    void ExecuteAsync(Func&& func, Callback&& callback) {
        std::thread([this, func = std::forward<Func>(func), 
                     callback = std::forward<Callback>(callback)]() mutable {
            try {
                auto result = Execute(std::move(func));
                callback(true, result, "");
            } catch (const std::exception& e) {
                callback(false, {}, e.what());
            }
        }).detach();
    }
    
private:
    RetryPolicy policy_;
    
    bool ShouldRetry(int attempt);
    std::chrono::milliseconds CalculateDelay(int attempt);
};

// ============================================================================
// Timeout Manager
// ============================================================================

class TimeoutManager {
public:
    struct Config {
        std::chrono::milliseconds default_timeout{30000};
        bool enable_cancellation = true;
    };
    
    explicit TimeoutManager(const Config& config);
    
    // Synchronous timeout
    template<typename Func>
    auto ExecuteWithTimeout(Func&& func, std::chrono::milliseconds timeout) 
        -> std::optional<decltype(func())> {
        std::optional<decltype(func())> result;
        std::atomic<bool> completed{false};
        
        std::thread worker([&]() {
            result = func();
            completed = true;
        });
        
        worker.join();
        
        if (!completed) {
            // Timeout occurred
            return std::nullopt;
        }
        
        return result;
    }
    
    // Async timeout
    template<typename Func, typename TimeoutCallback>
    void ExecuteAsyncWithTimeout(Func&& func, std::chrono::milliseconds timeout,
                                  Func&& on_success, TimeoutCallback&& on_timeout);
    
    // Cancellation token
    class CancellationToken {
    public:
        bool IsCancelled() const { return cancelled_.load(); }
        void Cancel() { cancelled_ = true; }
        void ThrowIfCancelled() const {
            if (cancelled_) {
                throw std::runtime_error("Operation cancelled");
            }
        }
    private:
        std::atomic<bool> cancelled_{false};
    };
    
    std::shared_ptr<CancellationToken> CreateToken();
    
private:
    Config config_;
    std::vector<std::shared_ptr<CancellationToken>> tokens_;
    std::mutex tokens_mutex_;
};

// ============================================================================
// Graceful Degradation
// ============================================================================

class GracefulDegradation {
public:
    struct FallbackConfig {
        std::string service_name;
        std::function<std::any(const std::any&)> fallback;
        std::chrono::milliseconds timeout{1000};
        bool cache_result = false;
        std::chrono::seconds cache_ttl{60};
    };
    
    void RegisterFallback(const FallbackConfig& config);
    
    template<typename ResultType>
    ResultType ExecuteWithFallback(const std::string& service_name,
                                    std::function<ResultType()> primary,
                                    const ResultType& default_value) {
        try {
            return primary();
        } catch (...) {
            auto fallback = GetFallback(service_name);
            if (fallback) {
                try {
                    return std::any_cast<ResultType>(fallback({}));
                } catch (...) {
                    return default_value;
                }
            }
            return default_value;
        }
    }
    
    // Static fallback values
    void SetStaticFallback(const std::string& service_name, const std::any& value);
    
    // Cache management
    void InvalidateCache(const std::string& service_name);
    void InvalidateAllCache();
    
private:
    std::map<std::string, FallbackConfig> fallbacks_;
    std::map<std::string, std::pair<std::any, std::chrono::steady_clock::time_point>> cache_;
    mutable std::mutex mutex_;
    
    std::function<std::any(const std::any&)> GetFallback(const std::string& service_name);
};

// ============================================================================
// Chaos Engineering
// ============================================================================

enum class FaultType {
    LATENCY = 0,
    ERROR = 1,
    TIMEOUT = 2,
    MEMORY_PRESSURE = 3,
    CPU_PRESSURE = 4,
    NETWORK_PARTITION = 5,
    DISK_FAILURE = 6
};

struct FaultInjection {
    FaultType type;
    std::string target;
    double probability = 0.01;  // 1% default
    std::map<std::string, std::string> parameters;
    std::chrono::seconds duration{60};
    std::vector<std::string> excluded_services;
};

class ChaosEngineering {
public:
    struct Config {
        bool enabled = false;
        std::string environment = "staging";
        std::vector<std::string> allowed_environments;
        bool auto_stop_on_alert = true;
        int max_concurrent_faults = 3;
    };
    
    explicit ChaosEngineering(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Experiment management
    std::string StartExperiment(const std::string& name, 
                                   const std::vector<FaultInjection>& faults);
    bool StopExperiment(const std::string& experiment_id);
    bool IsExperimentRunning(const std::string& experiment_id) const;
    
    // Fault injection
    void InjectLatency(const std::string& service, std::chrono::milliseconds delay);
    void InjectError(const std::string& service, int error_rate_percent);
    void InjectTimeout(const std::string& service, std::chrono::milliseconds timeout);
    void InjectMemoryPressure(const std::string& service, int percent);
    void InjectCPUPressure(const std::string& service, int percent);
    
    // Safety
    bool IsSafeToProceed() const;
    void EmergencyStop();
    
    // Results
    struct ExperimentResult {
        std::string experiment_id;
        bool completed = false;
        bool successful = false;
        std::vector<std::string> events;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point ended_at;
    };
    
    ExperimentResult GetResult(const std::string& experiment_id) const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct Experiment {
        std::string id;
        std::string name;
        std::vector<FaultInjection> faults;
        std::chrono::steady_clock::time_point started_at;
        std::atomic<bool> active{false};
    };
    
    std::map<std::string, Experiment> experiments_;
    mutable std::mutex experiments_mutex_;
};

// ============================================================================
// Reliability Runtime
// ============================================================================

class ReliabilityRuntime {
public:
    struct Config {
        bool enable_circuit_breaker = true;
        bool enable_bulkhead = true;
        bool enable_retry = true;
        bool enable_timeout = true;
        bool enable_degradation = true;
        bool enable_chaos = false;  // Disabled by default in production
        
        CircuitBreakerConfig default_circuit_breaker;
        Bulkhead::Config default_bulkhead;
        RetryPolicy default_retry;
        TimeoutManager::Config timeout;
        ChaosEngineering::Config chaos;
    };
    
    explicit ReliabilityRuntime(const Config& config);
    ~ReliabilityRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Circuit breakers
    CircuitBreaker* GetCircuitBreaker(const std::string& name);
    CircuitBreaker* CreateCircuitBreaker(const std::string& name, 
                                          const CircuitBreakerConfig& config);
    
    // Bulkheads
    Bulkhead* GetBulkhead(const std::string& name);
    Bulkhead* CreateBulkhead(const std::string& name, const Bulkhead::Config& config);
    
    // Retry executor
    RetryExecutor* GetRetryExecutor();
    
    // Timeout manager
    TimeoutManager* GetTimeoutManager();
    
    // Degradation
    GracefulDegradation* GetDegradationManager();
    
    // Chaos engineering
    ChaosEngineering* GetChaosEngineering();
    
    // Health
    bool IsHealthy() const;
    std::map<std::string, bool> GetComponentHealth() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::map<std::string, std::unique_ptr<CircuitBreaker>> circuit_breakers_;
    std::map<std::string, std::unique_ptr<Bulkhead>> bulkheads_;
    std::unique_ptr<RetryExecutor> retry_executor_;
    std::unique_ptr<TimeoutManager> timeout_manager_;
    std::unique_ptr<GracefulDegradation> degradation_;
    std::unique_ptr<ChaosEngineering> chaos_;
    
    mutable std::mutex components_mutex_;
};

} // namespace Production
} // namespace Sovereign
