/**
 * RateLimiter.hpp
 *
 * Phase N Batch 2/5: Rate Limiting & Authentication
 *
 * Advanced rate limiting with multiple algorithms and distributed
 * authentication/authorization system.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <queue>

namespace Gateway {

// ============================================================================
// Forward Declarations
// ============================================================================

class RateLimiter;
class TokenBucket;
class SlidingWindow;
class LeakyBucket;
class FixedWindow;

// ============================================================================
// Rate Limit Result
// ============================================================================

struct RateLimitResult {
    bool allowed;
    uint64_t remaining;
    uint64_t limit;
    std::chrono::system_clock::time_point resetTime;
    std::optional<std::chrono::milliseconds> retryAfter;
    std::optional<std::string> errorMessage;
    
    // Headers
    std::map<std::string, std::string> GetHeaders() const;
};

// ============================================================================
// Rate Limit Key
// ============================================================================

/**
 * Key for rate limiting.
 */
class RateLimitKey {
public:
    enum class Type {
        IP_ADDRESS,
        API_KEY,
        USER_ID,
        SESSION_ID,
        ROUTE,
        CUSTOM
    };
    
    RateLimitKey(Type type, const std::string& value);
    RateLimitKey(const std::string& customType, const std::string& value);
    
    // Accessors
    Type GetType() const { return type_; }
    const std::string& GetValue() const { return value_; }
    const std::string& GetCustomType() const { return customType_; }
    
    // Comparison
    bool operator==(const RateLimitKey& other) const;
    bool operator<(const RateLimitKey& other) const;
    std::string ToString() const;
    
private:
    Type type_;
    std::string value_;
    std::string customType_;
};

// ============================================================================
// Rate Limit Rule
// ============================================================================

/**
 * Rate limit rule configuration.
 */
struct RateLimitRule {
    enum class Algorithm {
        TOKEN_BUCKET,
        SLIDING_WINDOW,
        LEAKY_BUCKET,
        FIXED_WINDOW
    };
    
    std::string name;
    RateLimitKey::Type keyType;
    std::optional<std::string> keyPattern;
    Algorithm algorithm;
    uint64_t limit;
    std::chrono::seconds window;
    
    // Token bucket specific
    std::optional<uint64_t> burstSize;
    std::optional<double> refillRate;
    
    // Leaky bucket specific
    std::optional<uint64_t> leakRate;
    std::optional<uint64_t> bucketCapacity;
    
    // Advanced options
    bool blockOnLimit;
    std::optional<std::chrono::seconds> blockDuration;
    std::optional<uint64_t> warningThreshold;
    std::map<std::string, std::string> metadata;
    
    // Static factory methods
    static RateLimitRule TokenBucket(const std::string& name,
                                      RateLimitKey::Type keyType,
                                      uint64_t limit,
                                      std::chrono::seconds window,
                                      uint64_t burstSize);
    static RateLimitRule SlidingWindow(const std::string& name,
                                        RateLimitKey::Type keyType,
                                        uint64_t limit,
                                        std::chrono::seconds window);
    static RateLimitRule LeakyBucket(const std::string& name,
                                      RateLimitKey::Type keyType,
                                      uint64_t leakRate,
                                      uint64_t capacity);
    static RateLimitRule FixedWindow(const std::string& name,
                                      RateLimitKey::Type keyType,
                                      uint64_t limit,
                                      std::chrono::seconds window);
};

// ============================================================================
// Rate Limit Store
// ============================================================================

/**
 * Storage backend for rate limit counters.
 */
class RateLimitStore {
public:
    virtual ~RateLimitStore() = default;
    
    // Counter operations
    virtual uint64_t Increment(const std::string& key, uint64_t delta = 1) = 0;
    virtual uint64_t IncrementWithTTL(const std::string& key, uint64_t delta,
                                       std::chrono::seconds ttl) = 0;
    virtual uint64_t Get(const std::string& key) = 0;
    virtual void Set(const std::string& key, uint64_t value) = 0;
    virtual void SetWithTTL(const std::string& key, uint64_t value, std::chrono::seconds ttl) = 0;
    virtual void Delete(const std::string& key) = 0;
    virtual std::optional<std::chrono::system_clock::time_point> GetExpiration(
        const std::string& key) = 0;
    
    // Sliding window operations
    virtual void AddToWindow(const std::string& key, std::chrono::system_clock::time_point timestamp) = 0;
    virtual uint64_t CountInWindow(const std::string& key, std::chrono::seconds window) = 0;
    virtual void TrimWindow(const std::string& key, std::chrono::seconds window) = 0;
    
    // Batch operations
    virtual std::map<std::string, uint64_t> GetBatch(const std::vector<std::string>& keys) = 0;
    virtual void SetBatch(const std::map<std::string, uint64_t>& values, std::chrono::seconds ttl) = 0;
};

/**
 * In-memory rate limit store.
 */
class MemoryRateLimitStore : public RateLimitStore {
public:
    struct Entry {
        uint64_t value;
        std::optional<std::chrono::system_clock::time_point> expiresAt;
        std::deque<std::chrono::system_clock::time_point> window;
    };
    
    uint64_t Increment(const std::string& key, uint64_t delta = 1) override;
    uint64_t IncrementWithTTL(const std::string& key, uint64_t delta,
                               std::chrono::seconds ttl) override;
    uint64_t Get(const std::string& key) override;
    void Set(const std::string& key, uint64_t value) override;
    void SetWithTTL(const std::string& key, uint64_t value, std::chrono::seconds ttl) override;
    void Delete(const std::string& key) override;
    std::optional<std::chrono::system_clock::time_point> GetExpiration(
        const std::string& key) override;
    
    void AddToWindow(const std::string& key, std::chrono::system_clock::time_point timestamp) override;
    uint64_t CountInWindow(const std::string& key, std::chrono::seconds window) override;
    void TrimWindow(const std::string& key, std::chrono::seconds window) override;
    
    std::map<std::string, uint64_t> GetBatch(const std::vector<std::string>& keys) override;
    void SetBatch(const std::map<std::string, uint64_t>& values, std::chrono::seconds ttl) override;
    
    // Cleanup
    void CleanupExpired();
    size_t GetSize() const;
    
private:
    std::map<std::string, Entry> entries_;
    mutable std::mutex mutex_;
};

/**
 * Redis rate limit store.
 */
class RedisRateLimitStore : public RateLimitStore {
public:
    struct Config {
        std::string host;
        uint16_t port;
        std::optional<std::string> password;
        int32_t database;
        std::chrono::seconds connectionTimeout;
    };
    
    explicit RedisRateLimitStore(const Config& config);
    
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    uint64_t Increment(const std::string& key, uint64_t delta = 1) override;
    uint64_t IncrementWithTTL(const std::string& key, uint64_t delta,
                               std::chrono::seconds ttl) override;
    uint64_t Get(const std::string& key) override;
    void Set(const std::string& key, uint64_t value) override;
    void SetWithTTL(const std::string& key, uint64_t value, std::chrono::seconds ttl) override;
    void Delete(const std::string& key) override;
    std::optional<std::chrono::system_clock::time_point> GetExpiration(
        const std::string& key) override;
    
    void AddToWindow(const std::string& key, std::chrono::system_clock::time_point timestamp) override;
    uint64_t CountInWindow(const std::string& key, std::chrono::seconds window) override;
    void TrimWindow(const std::string& key, std::chrono::seconds window) override;
    
    std::map<std::string, uint64_t> GetBatch(const std::vector<std::string>& keys) override;
    void SetBatch(const std::map<std::string, uint64_t>& values, std::chrono::seconds ttl) override;
    
private:
    Config config_;
    void* redisContext_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Rate Limit Algorithm
// ============================================================================

/**
 * Rate limiting algorithm interface.
 */
class RateLimitAlgorithm {
public:
    virtual ~RateLimitAlgorithm() = default;
    
    virtual RateLimitResult CheckLimit(const RateLimitKey& key,
                                        const RateLimitRule& rule) = 0;
    virtual void Reset(const RateLimitKey& key) = 0;
    virtual std::string GetName() const = 0;
};

/**
 * Token bucket algorithm.
 */
class TokenBucket : public RateLimitAlgorithm {
public:
    explicit TokenBucket(std::shared_ptr<RateLimitStore> store);
    
    RateLimitResult CheckLimit(const RateLimitKey& key,
                                const RateLimitRule& rule) override;
    void Reset(const RateLimitKey& key) override;
    std::string GetName() const override { return "TokenBucket"; }
    
private:
    std::shared_ptr<RateLimitStore> store_;
    mutable std::mutex mutex_;
    
    std::string GetBucketKey(const RateLimitKey& key);
    std::string GetLastRefillKey(const RateLimitKey& key);
};

/**
 * Sliding window algorithm.
 */
class SlidingWindow : public RateLimitAlgorithm {
public:
    explicit SlidingWindow(std::shared_ptr<RateLimitStore> store);
    
    RateLimitResult CheckLimit(const RateLimitKey& key,
                                const RateLimitRule& rule) override;
    void Reset(const RateLimitKey& key) override;
    std::string GetName() const override { return "SlidingWindow"; }
    
private:
    std::shared_ptr<RateLimitStore> store_;
    mutable std::mutex mutex_;
    
    std::string GetWindowKey(const RateLimitKey& key);
};

/**
 * Leaky bucket algorithm.
 */
class LeakyBucket : public RateLimitAlgorithm {
public:
    explicit LeakyBucket(std::shared_ptr<RateLimitStore> store);
    
    RateLimitResult CheckLimit(const RateLimitKey& key,
                                const RateLimitRule& rule) override;
    void Reset(const RateLimitKey& key) override;
    std::string GetName() const override { return "LeakyBucket"; }
    
private:
    std::shared_ptr<RateLimitStore> store_;
    mutable std::mutex mutex_;
    
    std::string GetBucketKey(const RateLimitKey& key);
    std::string GetLastLeakKey(const RateLimitKey& key);
};

/**
 * Fixed window algorithm.
 */
class FixedWindow : public RateLimitAlgorithm {
public:
    explicit FixedWindow(std::shared_ptr<RateLimitStore> store);
    
    RateLimitResult CheckLimit(const RateLimitKey& key,
                                const RateLimitRule& rule) override;
    void Reset(const RateLimitKey& key) override;
    std::string GetName() const override { return "FixedWindow"; }
    
private:
    std::shared_ptr<RateLimitStore> store_;
    mutable std::mutex mutex_;
    
    std::string GetWindowKey(const RateLimitKey& key, std::chrono::seconds window);
};

// ============================================================================
// Rate Limiter
// ============================================================================

/**
 * Central rate limiter.
 */
class RateLimiter {
public:
    struct Config {
        std::shared_ptr<RateLimitStore> store;
        std::vector<RateLimitRule> defaultRules;
        bool enableDistributedSync;
        std::chrono::seconds syncInterval;
        bool enableMetrics;
    };
    
    explicit RateLimiter(const Config& config);
    ~RateLimiter();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Rule management
    void AddRule(const RateLimitRule& rule);
    void RemoveRule(const std::string& name);
    std::optional<RateLimitRule> GetRule(const std::string& name) const;
    std::vector<RateLimitRule> GetRules() const;
    std::vector<RateLimitRule> GetRulesForKey(const RateLimitKey& key) const;
    
    // Rate limiting
    RateLimitResult CheckLimit(const RateLimitKey& key);
    RateLimitResult CheckLimit(const RateLimitKey& key, const std::string& ruleName);
    RateLimitResult CheckLimit(const RateLimitKey& key, const RateLimitRule& rule);
    
    // Batch checking
    std::map<std::string, RateLimitResult> CheckLimits(const RateLimitKey& key);
    
    // Reset
    void Reset(const RateLimitKey& key);
    void Reset(const RateLimitKey& key, const std::string& ruleName);
    void ResetAll();
    
    // Blocking
    bool IsBlocked(const RateLimitKey& key);
    void Block(const RateLimitKey& key, std::chrono::seconds duration);
    void Unblock(const RateLimitKey& key);
    
    // Statistics
    struct LimiterStats {
        uint64_t totalRequests;
        uint64_t allowedRequests;
        uint64_t rejectedRequests;
        uint64_t blockedRequests;
        std::map<std::string, uint64_t> requestsPerRule;
        std::map<std::string, uint64_t> rejectionsPerRule;
    };
    LimiterStats GetStats() const;
    void ResetStats();
    
    // Health check
    bool HealthCheck() const;
    
private:
    Config config_;
    bool initialized_;
    std::vector<RateLimitRule> rules_;
    std::map<RateLimitRule::Algorithm, std::unique_ptr<RateLimitAlgorithm>> algorithms_;
    std::map<RateLimitKey, std::chrono::system_clock::time_point> blockedKeys_;
    mutable std::mutex mutex_;
    
    LimiterStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread syncThread_;
    std::atomic<bool> stopSync_;
    
    void SyncLoop();
    void CleanupBlockedKeys();
    std::unique_ptr<RateLimitAlgorithm> CreateAlgorithm(RateLimitRule::Algorithm algorithm);
};

// ============================================================================
// Adaptive Rate Limiter
// ============================================================================

/**
 * Adaptive rate limiter that adjusts limits based on system load.
 */
class AdaptiveRateLimiter {
public:
    struct Config {
        uint64_t baseLimit;
        uint64_t minLimit;
        uint64_t maxLimit;
        double cpuThreshold;
        double memoryThreshold;
        double latencyThreshold;
        double adjustmentFactor;
        std::chrono::seconds adjustmentInterval;
    };
    
    explicit AdaptiveRateLimiter(const Config& config,
                                  std::shared_ptr<RateLimiter> baseLimiter);
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Current limit
    uint64_t GetCurrentLimit() const;
    void SetCurrentLimit(uint64_t limit);
    
    // System metrics
    void UpdateSystemMetrics(double cpuUsage, double memoryUsage, double avgLatency);
    
    // Adjustment
    void AdjustLimit();
    void ForceAdjustment(uint64_t newLimit);
    
private:
    Config config_;
    std::shared_ptr<RateLimiter> baseLimiter_;
    std::atomic<uint64_t> currentLimit_;
    std::atomic<bool> running_;
    
    double currentCpuUsage_;
    double currentMemoryUsage_;
    double currentLatency_;
    mutable std::mutex mutex_;
    
    std::thread adjustmentThread_;
    
    void AdjustmentLoop();
    uint64_t CalculateNewLimit();
};

// ============================================================================
// Rate Limit Middleware
// ============================================================================

/**
 * Rate limiting middleware for API gateway.
 */
class RateLimitMiddleware : public Middleware {
public:
    explicit RateLimitMiddleware(std::shared_ptr<RateLimiter> limiter);
    
    std::string GetName() const override { return "RateLimit"; }
    int GetPriority() const override { return 10; }  // High priority
    
    HTTPResponse Process(const HTTPRequest& request,
                         std::function<HTTPResponse(const HTTPRequest&)> next) override;
    
    // Key extraction
    void SetKeyExtractor(std::function<RateLimitKey(const HTTPRequest&)> extractor);
    
    // Custom rules per route
    void SetRouteRule(const std::string& routePattern, const RateLimitRule& rule);
    void ClearRouteRule(const std::string& routePattern);
    
private:
    std::shared_ptr<RateLimiter> limiter_;
    std::function<RateLimitKey(const HTTPRequest&)> keyExtractor_;
    std::map<std::string, RateLimitRule> routeRules_;
    mutable std::mutex mutex_;
    
    RateLimitKey ExtractDefaultKey(const HTTPRequest& request);
    HTTPResponse CreateRateLimitResponse(const RateLimitResult& result);
};

} // namespace Gateway
