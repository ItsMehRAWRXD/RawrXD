// rate_limiter.cpp
// Batch 13: Rate Limiting and Throttling
//
// Prevents abuse through rate limiting
// Features: Token bucket, sliding window, IP-based limits

#include <string>
#include <map>
#include <mutex>
#include <chrono>
#include <atomic>
#include <queue>
#include <algorithm>

namespace Benchmark {
namespace Security {

// Rate limit result
struct RateLimitResult {
    bool allowed;
    int remaining;
    int64_t reset_time;
    int retry_after;
    std::string limit_type;
};

// Token bucket for burst handling
class TokenBucket {
public:
    TokenBucket(double rate_per_second, double capacity)
        : rate_(rate_per_second),
          capacity_(capacity),
          tokens_(capacity),
          last_update_(GetCurrentTime()) {}
    
    bool Consume(double tokens = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Add tokens based on time elapsed
        auto now = GetCurrentTime();
        double elapsed = std::chrono::duration<double>(now - last_update_).count();
        tokens_ = std::min(capacity_, tokens_ + elapsed * rate_);
        last_update_ = now;
        
        // Check if we have enough tokens
        if (tokens_ >= tokens) {
            tokens_ -= tokens;
            return true;
        }
        
        return false;
    }
    
    double GetTokens() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tokens_;
    }
    
    int GetRetryAfter() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tokens_ >= 1.0) return 0;
        return static_cast<int>(std::ceil((1.0 - tokens_) / rate_));
    }

private:
    double rate_;
    double capacity_;
    double tokens_;
    std::chrono::steady_clock::time_point last_update_;
    mutable std::mutex mutex_;
    
    static std::chrono::steady_clock::time_point GetCurrentTime() {
        return std::chrono::steady_clock::now();
    }
};

// Sliding window counter
class SlidingWindow {
public:
    SlidingWindow(int window_size_seconds, int max_requests)
        : window_size_(window_size_seconds),
          max_requests_(max_requests) {}
    
    bool AllowRequest() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = GetCurrentTime();
        
        // Remove old entries outside the window
        while (!requests_.empty() && 
               std::chrono::duration_cast<std::chrono::seconds>(
                   now - requests_.front()).count() >= window_size_) {
            requests_.pop();
        }
        
        // Check if we can add new request
        if (static_cast<int>(requests_.size()) < max_requests_) {
            requests_.push(now);
            return true;
        }
        
        return false;
    }
    
    int GetRemaining() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return max_requests_ - static_cast<int>(requests_.size());
    }
    
    int GetRetryAfter() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (requests_.size() < static_cast<size_t>(max_requests_)) return 0;
        
        auto oldest = requests_.front();
        auto now = GetCurrentTime();
        int elapsed = static_cast<int>(
            std::chrono::duration_cast<std::chrono::seconds>(now - oldest).count());
        
        return std::max(0, window_size_ - elapsed);
    }

private:
    int window_size_;
    int max_requests_;
    std::queue<std::chrono::steady_clock::time_point> requests_;
    mutable std::mutex mutex_;
    
    static std::chrono::steady_clock::time_point GetCurrentTime() {
        return std::chrono::steady_clock::now();
    }
};

// Rate limiter manager
class RateLimiter {
public:
    struct Config {
        // Global limits
        int global_requests_per_minute = 1000;
        int global_burst_size = 100;
        
        // Per-IP limits
        int ip_requests_per_minute = 60;
        int ip_burst_size = 10;
        
        // Per-user limits
        int user_requests_per_minute = 120;
        int user_burst_size = 20;
        
        // Endpoint-specific limits
        std::map<std::string, std::pair<int, int>> endpoint_limits;
    };
    
    explicit RateLimiter(const Config& config = Config()) : config_(config) {
        // Initialize global bucket
        global_bucket_ = std::make_unique<TokenBucket>(
            config.global_requests_per_minute / 60.0,
            config.global_burst_size);
    }
    
    // Check if request is allowed
    RateLimitResult CheckRequest(const std::string& client_id,
                                  const std::string& endpoint = "",
                                  const std::string& user_id = "") {
        RateLimitResult result;
        
        // Check global limit first
        if (!global_bucket_->Consume()) {
            result.allowed = false;
            result.remaining = 0;
            result.retry_after = global_bucket_->GetRetryAfter();
            result.limit_type = "global";
            return result;
        }
        
        // Check IP-based limit
        auto ip_result = CheckIPLimit(client_id);
        if (!ip_result.allowed) {
            // Refund global token
            result.allowed = false;
            result.remaining = ip_result.remaining;
            result.retry_after = ip_result.retry_after;
            result.limit_type = "ip";
            return result;
        }
        
        // Check user limit if authenticated
        if (!user_id.empty()) {
            auto user_result = CheckUserLimit(user_id);
            if (!user_result.allowed) {
                result.allowed = false;
                result.remaining = user_result.remaining;
                result.retry_after = user_result.retry_after;
                result.limit_type = "user";
                return result;
            }
        }
        
        // Check endpoint-specific limit
        if (!endpoint.empty()) {
            auto endpoint_result = CheckEndpointLimit(client_id, endpoint);
            if (!endpoint_result.allowed) {
                result.allowed = false;
                result.remaining = endpoint_result.remaining;
                result.retry_after = endpoint_result.retry_after;
                result.limit_type = "endpoint";
                return result;
            }
        }
        
        // All checks passed
        result.allowed = true;
        result.remaining = std::min({
            static_cast<int>(global_bucket_->GetTokens()),
            ip_result.remaining,
            user_id.empty() ? INT_MAX : CheckUserLimit(user_id).remaining
        });
        result.reset_time = GetResetTime();
        result.limit_type = "none";
        
        return result;
    }
    
    // Get current rate limit status
    RateLimitResult GetStatus(const std::string& client_id,
                              const std::string& user_id = "") {
        RateLimitResult result;
        result.allowed = true;
        result.remaining = static_cast<int>(global_bucket_->GetTokens());
        result.reset_time = GetResetTime();
        
        // Get IP limit status
        auto ip_window = GetOrCreateIPWindow(client_id);
        result.remaining = std::min(result.remaining, ip_window->GetRemaining());
        
        // Get user limit status
        if (!user_id.empty()) {
            auto user_window = GetOrCreateUserWindow(user_id);
            result.remaining = std::min(result.remaining, user_window->GetRemaining());
        }
        
        return result;
    }
    
    // Reset limits for a client
    void ResetClient(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(ip_mutex_);
        ip_windows_.erase(client_id);
    }
    
    // Reset all limits
    void ResetAll() {
        std::lock_guard<std::mutex> lock(ip_mutex_);
        ip_windows_.clear();
        
        std::lock_guard<std::mutex> user_lock(user_mutex_);
        user_windows_.clear();
        
        std::lock_guard<std::mutex> endpoint_lock(endpoint_mutex_);
        endpoint_windows_.clear();
    }
    
    // Cleanup expired entries
    void Cleanup() {
        // Remove old IP windows (older than 1 hour)
        std::lock_guard<std::mutex> lock(ip_mutex_);
        // In production: track last access time and remove stale entries
    }

private:
    Config config_;
    std::unique_ptr<TokenBucket> global_bucket_;
    
    std::map<std::string, std::unique_ptr<SlidingWindow>> ip_windows_;
    mutable std::mutex ip_mutex_;
    
    std::map<std::string, std::unique_ptr<SlidingWindow>> user_windows_;
    mutable std::mutex user_mutex_;
    
    std::map<std::string, std::unique_ptr<SlidingWindow>> endpoint_windows_;
    mutable std::mutex endpoint_mutex_;
    
    RateLimitResult CheckIPLimit(const std::string& client_id) {
        auto window = GetOrCreateIPWindow(client_id);
        
        RateLimitResult result;
        result.allowed = window->AllowRequest();
        result.remaining = window->GetRemaining();
        result.retry_after = window->GetRetryAfter();
        
        return result;
    }
    
    RateLimitResult CheckUserLimit(const std::string& user_id) {
        auto window = GetOrCreateUserWindow(user_id);
        
        RateLimitResult result;
        result.allowed = window->AllowRequest();
        result.remaining = window->GetRemaining();
        result.retry_after = window->GetRetryAfter();
        
        return result;
    }
    
    RateLimitResult CheckEndpointLimit(const std::string& client_id,
                                       const std::string& endpoint) {
        RateLimitResult result;
        result.allowed = true;
        result.remaining = INT_MAX;
        
        auto it = config_.endpoint_limits.find(endpoint);
        if (it == config_.endpoint_limits.end()) {
            return result;
        }
        
        // Create or get endpoint window for this client
        std::string key = client_id + ":" + endpoint;
        
        std::lock_guard<std::mutex> lock(endpoint_mutex_);
        auto window_it = endpoint_windows_.find(key);
        if (window_it == endpoint_windows_.end()) {
            endpoint_windows_[key] = std::make_unique<SlidingWindow>(
                60, it->second.first);  // requests per minute
            window_it = endpoint_windows_.find(key);
        }
        
        result.allowed = window_it->second->AllowRequest();
        result.remaining = window_it->second->GetRemaining();
        result.retry_after = window_it->second->GetRetryAfter();
        
        return result;
    }
    
    SlidingWindow* GetOrCreateIPWindow(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(ip_mutex_);
        
        auto it = ip_windows_.find(client_id);
        if (it == ip_windows_.end()) {
            ip_windows_[client_id] = std::make_unique<SlidingWindow>(
                60, config_.ip_requests_per_minute);
            it = ip_windows_.find(client_id);
        }
        
        return it->second.get();
    }
    
    SlidingWindow* GetOrCreateUserWindow(const std::string& user_id) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        
        auto it = user_windows_.find(user_id);
        if (it == user_windows_.end()) {
            user_windows_[user_id] = std::make_unique<SlidingWindow>(
                60, config_.user_requests_per_minute);
            it = user_windows_.find(user_id);
        }
        
        return it->second.get();
    }
    
    int64_t GetResetTime() const {
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::seconds>(epoch).count() + 60;
    }
};

// Throttling for resource-intensive operations
class Throttler {
public:
    struct Config {
        int max_concurrent = 10;
        int queue_size = 100;
        int timeout_ms = 30000;
    };
    
    explicit Throttler(const Config& config = Config()) 
        : config_(config), current_(0) {}
    
    // Try to acquire slot
    bool TryAcquire(int timeout_ms = -1) {
        int timeout = (timeout_ms < 0) ? config_.timeout_ms : timeout_ms;
        auto deadline = std::chrono::steady_clock::now() + 
                       std::chrono::milliseconds(timeout);
        
        std::unique_lock<std::mutex> lock(mutex_);
        
        while (current_ >= config_.max_concurrent) {
            if (cv_.wait_until(lock, deadline) == std::cv_status::timeout) {
                return false;
            }
        }
        
        ++current_;
        return true;
    }
    
    // Release slot
    void Release() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (current_ > 0) {
            --current_;
            cv_.notify_one();
        }
    }
    
    // Get current utilization
    double GetUtilization() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<double>(current_) / config_.max_concurrent;
    }
    
    // Get available slots
    int GetAvailable() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return config_.max_concurrent - current_;
    }

private:
    Config config_;
    int current_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

// Rate limit headers for HTTP responses
struct RateLimitHeaders {
    int limit;
    int remaining;
    int reset;
    int retry_after;
    std::string policy;
    
    std::map<std::string, std::string> ToMap() const {
        return {
            {"X-RateLimit-Limit", std::to_string(limit)},
            {"X-RateLimit-Remaining", std::to_string(remaining)},
            {"X-RateLimit-Reset", std::to_string(reset)},
            {"X-RateLimit-Policy", policy}
        };
    }
};

} // namespace Security
} // namespace Benchmark
