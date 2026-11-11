#pragma once

#include "../core/common.hpp"
#include <chrono>
#include <unordered_map>
#include <mutex>

namespace rawrxd::production {

// Token bucket rate limiter
class TokenBucketRateLimiter {
public:
    struct Config {
        double refill_rate_per_second = 10.0;  // Tokens added per second
        double bucket_capacity = 100.0;         // Maximum tokens
        double default_tokens = 1.0;            // Tokens consumed per request
    };
    
    explicit TokenBucketRateLimiter(const Config& config);
    
    // Check if request allowed
    bool allow(const std::string& key);
    bool allow(const std::string& key, double tokens);
    
    // Get current token count
    double getTokens(const std::string& key);
    
    // Get remaining capacity
    double getRemainingCapacity(const std::string& key);
    
    // Reset bucket
    void reset(const std::string& key);
    
    // Get wait time until next allowed
    std::chrono::milliseconds getWaitTime(const std::string& key, double tokens = 1.0);
    
private:
    Config config_;
    
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point last_update;
    };
    
    std::unordered_map<std::string, Bucket> buckets_;
    mutable std::mutex mutex_;
    
    void refill(Bucket& bucket);
};

// Sliding window rate limiter
class SlidingWindowRateLimiter {
public:
    struct Config {
        int max_requests = 100;           // Max requests in window
        std::chrono::seconds window{60};  // Window duration
    };
    
    explicit SlidingWindowRateLimiter(const Config& config);
    
    // Check if request allowed
    bool allow(const std::string& key);
    
    // Get remaining requests in current window
    int getRemaining(const std::string& key);
    
    // Get window reset time
    std::chrono::steady_clock::time_point getResetTime(const std::string& key);
    
    // Reset window
    void reset(const std::string& key);
    
private:
    Config config_;
    
    struct Window {
        std::vector<std::chrono::steady_clock::time_point> requests;
        std::chrono::steady_clock::time_point window_start;
    };
    
    std::unordered_map<std::string, Window> windows_;
    mutable std::mutex mutex_;
    
    void cleanupOldRequests(Window& window);
};

// Distributed rate limiter (for multi-instance deployments)
class DistributedRateLimiter {
public:
    struct Config {
        std::string redis_host = "localhost";
        int redis_port = 6379;
        int max_requests_per_minute = 100;
    };
    
    explicit DistributedRateLimiter(const Config& config);
    
    // Check if request allowed
    bool allow(const std::string& key);
    
    // Check with custom limit
    bool allow(const std::string& key, int limit, std::chrono::seconds window);
    
private:
    Config config_;
    
    // Redis client would be here
    // std::shared_ptr<RedisClient> redis_;
};

// Adaptive rate limiter (adjusts based on system load)
class AdaptiveRateLimiter {
public:
    struct Config {
        int min_rate = 10;
        int max_rate = 1000;
        float target_cpu = 0.7f;
        float target_memory = 0.8f;
        float adjustment_factor = 0.1f;
    };
    
    explicit AdaptiveRateLimiter(const Config& config);
    
    // Check if request allowed
    bool allow(const std::string& key);
    
    // Update system metrics
    void updateMetrics(float cpu_usage, float memory_usage, float latency_ms);
    
    // Get current rate limit
    int getCurrentRate() const { return current_rate_.load(); }
    
private:
    Config config_;
    std::atomic<int> current_rate_;
    TokenBucketRateLimiter limiter_;
    
    void adjustRate();
};

// Rate limiter factory
class RateLimiterFactory {
public:
    enum class Type {
        TOKEN_BUCKET,
        SLIDING_WINDOW,
        DISTRIBUTED,
        ADAPTIVE
    };
    
    static std::unique_ptr<TokenBucketRateLimiter> createTokenBucket(
        double refill_rate, double capacity);
    
    static std::unique_ptr<SlidingWindowRateLimiter> createSlidingWindow(
        int max_requests, std::chrono::seconds window);
    
    static std::unique_ptr<DistributedRateLimiter> createDistributed(
        const std::string& redis_host, int redis_port);
    
    static std::unique_ptr<AdaptiveRateLimiter> createAdaptive(
        int min_rate, int max_rate);
};

} // namespace rawrxd::production
