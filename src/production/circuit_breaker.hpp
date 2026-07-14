#pragma once

#include "../core/common.hpp"
#include <chrono>
#include <functional>

namespace rawrxd::production {

// Circuit breaker states
enum class CircuitState {
    CLOSED,     // Normal operation
    OPEN,       // Failing, reject requests
    HALF_OPEN   // Testing if service recovered
};

// Circuit breaker configuration
struct CircuitBreakerConfig {
    int failure_threshold = 5;              // Failures before opening
    int success_threshold = 3;              // Successes before closing
    std::chrono::seconds timeout{30};       // Time before half-open
    std::chrono::seconds half_open_max{5};  // Max time in half-open
    float error_rate_threshold = 0.5f;     // Error rate to trigger open
};

// Circuit breaker for fault tolerance
class CircuitBreaker {
public:
    explicit CircuitBreaker(const std::string& name,
                           const CircuitBreakerConfig& config);

    // Execute operation with circuit breaker
    template<typename Func>
    auto execute(Func&& operation) -> std::optional<std::invoke_result_t<Func>> {
        if (!allowRequest()) {
            return std::nullopt;
        }

        try {
            auto result = operation();
            recordSuccess();
            return result;
        } catch (...) {
            recordFailure();
            throw;
        }
    }

    // Check if request allowed
    bool allowRequest();

    // Manual control
    void trip();        // Force open
    void reset();       // Force closed
    void halfOpen();    // Force half-open

    // State
    CircuitState getState() const { return state_; }
    std::string getStateString() const;

    // Statistics
    struct Stats {
        uint64_t successes = 0;
        uint64_t failures = 0;
        uint64_t rejected = 0;
        uint64_t state_transitions = 0;
        float success_rate = 0.0f;
        std::chrono::steady_clock::time_point last_failure;
        std::chrono::steady_clock::time_point last_success;
    };

    Stats getStats() const;
    std::string getName() const { return name_; }

private:
    std::string name_;
    CircuitBreakerConfig config_;
    std::atomic<CircuitState> state_{CircuitState::CLOSED};

    std::atomic<int> failure_count_{0};
    std::atomic<int> success_count_{0};
    std::atomic<uint64_t> total_successes_{0};
    std::atomic<uint64_t> total_failures_{0};
    std::atomic<uint64_t> total_rejected_{0};
    std::atomic<uint64_t> state_transitions_{0};

    std::chrono::steady_clock::time_point last_failure_time_;
    std::chrono::steady_clock::time_point last_success_time_;
    std::chrono::steady_clock::time_point state_change_time_;

    mutable std::mutex mutex_;

    void recordSuccess();
    void recordFailure();
    void transitionTo(CircuitState new_state);
    bool shouldAttemptReset();
};

// Circuit breaker registry
class CircuitBreakerRegistry {
public:
    static CircuitBreakerRegistry& getInstance();

    // Create or get circuit breaker
    std::shared_ptr<CircuitBreaker> getOrCreate(
        const std::string& name,
        const CircuitBreakerConfig& config);

    // Get existing circuit breaker
    std::shared_ptr<CircuitBreaker> get(const std::string& name);

    // Remove circuit breaker
    void remove(const std::string& name);

    // List all circuit breakers
    std::vector<std::string> list() const;

    // Get all statistics
    std::unordered_map<std::string, CircuitBreaker::Stats> getAllStats() const;

private:
    CircuitBreakerRegistry() = default;

    std::unordered_map<std::string, std::shared_ptr<CircuitBreaker>> breakers_;
    mutable std::shared_mutex mutex_;
};

// Decorator for adding circuit breaker to any function
class CircuitBreakerDecorator {
public:
    CircuitBreakerDecorator(std::shared_ptr<CircuitBreaker> breaker,
                            std::function<void()> fallback);

    template<typename Func>
    auto operator()(Func&& operation) -> std::optional<std::invoke_result_t<Func>> {
        return breaker_>execute([&]() {
            return operation();
        });
    }

private:
    std::shared_ptr<CircuitBreaker> breaker_;
    std::function<void()> fallback_;
};

// Bulkhead pattern (resource isolation)
class Bulkhead {
public:
    explicit Bulkhead(const std::string& name, int max_concurrent);

    // Try to acquire slot
    bool tryAcquire(std::chrono::milliseconds timeout);

    // Release slot
    void release();

    // Current utilization
    int getAvailableSlots() const;
    int getMaxSlots() const { return max_concurrent_; }
    float getUtilization() const;

private:
    std::string name_;
    int max_concurrent_;
    std::atomic<int> current_{0};
    std::counting_semaphore<> semaphore_;
};

} // namespace rawrxd::production
