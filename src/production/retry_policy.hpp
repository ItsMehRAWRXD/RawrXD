#pragma once

#include "../core/common.hpp"
#include <chrono>
#include <random>

namespace rawrxd::production {

// Retry policy configuration
struct RetryPolicyConfig {
    int max_retries = 3;
    std::chrono::milliseconds base_delay{100};
    std::chrono::milliseconds max_delay{10000};
    float backoff_multiplier = 2.0f;
    float jitter_factor = 0.1f;  // Random jitter 0-10%
    std::vector<int> retryable_errors;  // Error codes to retry
    bool retry_on_timeout = true;
};

// Retry policy with exponential backoff
class RetryPolicy {
public:
    explicit RetryPolicy(const RetryPolicyConfig& config);

    // Execute with retry
    template<typename Func>
    auto execute(Func&& operation) -> std::optional<std::invoke_result_t<Func>> {
        int attempt = 0;
        std::chrono::milliseconds delay = config_.base_delay;

        while (attempt <= config_.max_retries) {
            try {
                return operation();
            } catch (const std::exception& e) {
                if (attempt == config_.max_retries) {
                    throw;
                }

                if (!shouldRetry(e)) {
                    throw;
                }

                std::this_thread::sleep_for(calculateDelay(delay, attempt));
                delay = std::min(delay * config_.backoff_multiplier, config_.max_delay);
                attempt++;
            }
        }

        return std::nullopt;
    }

    // Check if should retry
    bool shouldRetry(const std::exception& e) const;
    bool shouldRetry(int error_code) const;

    // Calculate delay with jitter
    std::chrono::milliseconds calculateDelay(std::chrono::milliseconds base_delay,
                                                int attempt) const;

    // Statistics
    struct Stats {
        uint64_t total_attempts = 0;
        uint64_t successful_first_attempts = 0;
        uint64_t successful_retries = 0;
        uint64_t failed_retries = 0;
        float avg_attempts_per_operation = 0.0f;
    };

    Stats getStats() const { return stats_; }

private:
    RetryPolicyConfig config_;
    Stats stats_;
    mutable std::mutex stats_mutex_;

    std::mt19937 rng_;

    void recordAttempt(bool success, int num_attempts);
};

// Hedged request pattern (send multiple requests, use first response)
class HedgedRequest {
public:
    explicit HedgedRequest(std::chrono::milliseconds delay_between = std::chrono::milliseconds{10});

    template<typename Func>
    auto execute(const std::vector<Func>& operations)
        -> std::optional<std::invoke_result_t<Func>> {
        if (operations.empty()) {
            return std::nullopt;
        }

        std::vector<std::future<std::invoke_result_t<Func>>> futures;
        futures.reserve(operations.size());

        for (size_t i = 0; i < operations.size(); ++i) {
            if (i > 0) {
                std::this_thread::sleep_for(delay_between_);
            }

            futures.push_back(std::async(std::launch::async, operations[i]));

            // Check if any completed
            for (auto& f : futures) {
                if (f.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                    return f.get();
                }
            }
        }

        // Wait for first to complete
        while (true) {
            for (auto& f : futures) {
                if (f.wait_for(std::chrono::milliseconds(10)) == std::future_status::ready) {
                    return f.get();
                }
            }
        }
    }

private:
    std::chrono::milliseconds delay_between_;
};

// Timeout wrapper
class TimeoutPolicy {
public:
    explicit TimeoutPolicy(std::chrono::milliseconds timeout);

    template<typename Func>
    auto execute(Func&& operation)
        -> std::optional<std::invoke_result_t<Func>> {
        std::packaged_task<std::invoke_result_t<Func>()> task(std::forward<Func>(operation));
        auto future = task.get_future();

        std::thread thread(std::move(task));

        if (future.wait_for(timeout_) == std::future_status::timeout) {
            // Handle timeout
            thread.detach();  // Or join with cancellation
            return std::nullopt;
        }

        thread.join();
        return future.get();
    }

private:
    std::chrono::milliseconds timeout_;
};

// Combined resilience policy
class ResiliencePolicy {
public:
    ResiliencePolicy(std::shared_ptr<RetryPolicy> retry,
                     std::shared_ptr<CircuitBreaker> circuit_breaker,
                     std::chrono::milliseconds timeout);

    template<typename Func>
    auto execute(Func&& operation)
        -> std::optional<std::invoke_result_t<Func>> {
        // Check circuit breaker first
        if (!circuit_breaker_>allowRequest()) {
            return std::nullopt;
        }

        // Execute with retry and timeout
        return retry_>execute([&]() {
            TimeoutPolicy timeout(timeout_);
            return timeout.execute(operation);
        });
    }

private:
    std::shared_ptr<RetryPolicy> retry_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;
    std::chrono::milliseconds timeout_;
};

} // namespace rawrxd::production
