// RawrXD Rate Limiter
// Phase 9 - Task 9: Rate Limiting

#include <windows.h>
#include <map>
#include <string>
#include <chrono>
#include <mutex>
#include <queue>

// Rate limiting algorithms
enum RateLimitAlgorithm {
    RL_TOKEN_BUCKET,
    RL_SLIDING_WINDOW,
    RL_FIXED_WINDOW,
    RL_LEAKY_BUCKET
};

// Rate limit configuration
struct RateLimitConfig {
    RateLimitAlgorithm algorithm;
    int requestsPerSecond;
    int burstSize;
    int cooldownMs;
};

// Token bucket state
struct TokenBucket {
    double tokens;
    double capacity;
    double refillRate;
    std::chrono::steady_clock::time_point lastRefill;
    std::mutex mutex;
};

// Sliding window state
struct SlidingWindow {
    std::queue<std::chrono::steady_clock::time_point> requests;
    int windowSize;
    int maxRequests;
    std::mutex mutex;
};

// Rate limiter entry
struct RateLimiterEntry {
    std::string key;
    TokenBucket bucket;
    SlidingWindow window;
    uint64_t totalRequests;
    uint64_t rejectedRequests;
    std::chrono::steady_clock::time_point lastAccess;
};

// Rate limiter
class RateLimiter {
private:
    std::map<std::string, RateLimiterEntry> entries;
    std::mutex entriesMutex;
    RateLimitConfig defaultConfig;
    std::thread cleanupThread;
    std::atomic<bool> running;
    
public:
    RateLimiter() : running(false) {}
    
    ~RateLimiter() {
        Shutdown();
    }
    
    bool Initialize(const RateLimitConfig& config) {
        defaultConfig = config;
        running = true;
        
        // Start cleanup thread
        cleanupThread = std::thread(&RateLimiter::CleanupLoop, this);
        
        printf("Rate limiter initialized:\n");
        printf("  Algorithm: %d\n", config.algorithm);
        printf("  Requests/sec: %d\n", config.requestsPerSecond);
        printf("  Burst size: %d\n", config.burstSize);
        
        return true;
    }
    
    // Check if request is allowed
    bool AllowRequest(const std::string& key) {
        std::lock_guard<std::mutex> lock(entriesMutex);
        
        auto it = entries.find(key);
        if (it == entries.end()) {
            // Create new entry
            RateLimiterEntry entry;
            entry.key = key;
            entry.totalRequests = 0;
            entry.rejectedRequests = 0;
            entry.lastAccess = std::chrono::steady_clock::now();
            
            // Initialize based on algorithm
            switch (defaultConfig.algorithm) {
                case RL_TOKEN_BUCKET:
                    entry.bucket.tokens = defaultConfig.burstSize;
                    entry.bucket.capacity = defaultConfig.burstSize;
                    entry.bucket.refillRate = defaultConfig.requestsPerSecond;
                    entry.bucket.lastRefill = std::chrono::steady_clock::now();
                    break;
                    
                case RL_SLIDING_WINDOW:
                    entry.window.windowSize = 1000; // 1 second in ms
                    entry.window.maxRequests = defaultConfig.requestsPerSecond;
                    break;
            }
            
            entries[key] = entry;
            it = entries.find(key);
        }
        
        it->second.lastAccess = std::chrono::steady_clock::now();
        it->second.totalRequests++;
        
        bool allowed = false;
        
        switch (defaultConfig.algorithm) {
            case RL_TOKEN_BUCKET:
                allowed = CheckTokenBucket(it->second.bucket);
                break;
                
            case RL_SLIDING_WINDOW:
                allowed = CheckSlidingWindow(it->second.window);
                break;
                
            case RL_FIXED_WINDOW:
                allowed = CheckFixedWindow(key);
                break;
                
            case RL_LEAKY_BUCKET:
                allowed = CheckLeakyBucket(it->second.bucket);
                break;
        }
        
        if (!allowed) {
            it->second.rejectedRequests++;
        }
        
        return allowed;
    }
    
    // Check token bucket
    bool CheckTokenBucket(TokenBucket& bucket) {
        std::lock_guard<std::mutex> lock(bucket.mutex);
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - bucket.lastRefill).count() / 1000.0;
        
        // Refill tokens
        bucket.tokens += elapsed * bucket.refillRate;
        if (bucket.tokens > bucket.capacity) {
            bucket.tokens = bucket.capacity;
        }
        bucket.lastRefill = now;
        
        // Check if we can consume a token
        if (bucket.tokens >= 1.0) {
            bucket.tokens -= 1.0;
            return true;
        }
        
        return false;
    }
    
    // Check sliding window
    bool CheckSlidingWindow(SlidingWindow& window) {
        std::lock_guard<std::mutex> lock(window.mutex);
        
        auto now = std::chrono::steady_clock::now();
        auto windowStart = now - std::chrono::milliseconds(window.windowSize);
        
        // Remove old requests
        while (!window.requests.empty() && window.requests.front() < windowStart) {
            window.requests.pop();
        }
        
        // Check if we can add new request
        if ((int)window.requests.size() < window.maxRequests) {
            window.requests.push(now);
            return true;
        }
        
        return false;
    }
    
    // Check fixed window (simplified)
    bool CheckFixedWindow(const std::string& key) {
        // Simplified - would track per-second buckets
        return true;
    }
    
    // Check leaky bucket
    bool CheckLeakyBucket(TokenBucket& bucket) {
        std::lock_guard<std::mutex> lock(bucket.mutex);
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - bucket.lastRefill).count() / 1000.0;
        
        // Leak tokens
        bucket.tokens -= elapsed * bucket.refillRate;
        if (bucket.tokens < 0) {
            bucket.tokens = 0;
        }
        bucket.lastRefill = now;
        
        // Check if we can add new request
        if (bucket.tokens < bucket.capacity) {
            bucket.tokens += 1.0;
            return true;
        }
        
        return false;
    }
    
    // Get rate limit status
    void GetStatus(const std::string& key, double& currentRate, int& remaining, int& resetTime) {
        std::lock_guard<std::mutex> lock(entriesMutex);
        
        auto it = entries.find(key);
        if (it == entries.end()) {
            currentRate = 0;
            remaining = defaultConfig.burstSize;
            resetTime = 0;
            return;
        }
        
        switch (defaultConfig.algorithm) {
            case RL_TOKEN_BUCKET:
                currentRate = it->second.bucket.tokens;
                remaining = (int)it->second.bucket.tokens;
                resetTime = (int)((it->second.bucket.capacity - it->second.bucket.tokens) / 
                                 it->second.bucket.refillRate * 1000);
                break;
                
            case RL_SLIDING_WINDOW:
                currentRate = it->second.window.requests.size();
                remaining = it->second.window.maxRequests - (int)it->second.window.requests.size();
                resetTime = it->second.window.windowSize;
                break;
                
            default:
                currentRate = 0;
                remaining = defaultConfig.burstSize;
                resetTime = 0;
        }
    }
    
    // Get statistics
    void GetStats(const std::string& key, uint64_t& total, uint64_t& rejected) {
        std::lock_guard<std::mutex> lock(entriesMutex);
        
        auto it = entries.find(key);
        if (it != entries.end()) {
            total = it->second.totalRequests;
            rejected = it->second.rejectedRequests;
        } else {
            total = 0;
            rejected = 0;
        }
    }
    
    // Reset rate limit for key
    bool Reset(const std::string& key) {
        std::lock_guard<std::mutex> lock(entriesMutex);
        
        auto it = entries.find(key);
        if (it != entries.end()) {
            entries.erase(it);
            return true;
        }
        
        return false;
    }
    
    void Shutdown() {
        running = false;
        
        if (cleanupThread.joinable()) {
            cleanupThread.join();
        }
    }
    
private:
    void CleanupLoop() {
        while (running) {
            Sleep(60000); // Cleanup every minute
            
            std::lock_guard<std::mutex> lock(entriesMutex);
            
            auto now = std::chrono::steady_clock::now();
            auto it = entries.begin();
            
            while (it != entries.end()) {
                // Remove entries inactive for 1 hour
                auto inactive = std::chrono::duration_cast<std::chrono::minutes>(
                    now - it->second.lastAccess).count();
                
                if (inactive > 60) {
                    it = entries.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
};

// Global instance
static RateLimiter g_RateLimiter;

// C API
extern "C" {

bool RateLimiter_Init(int algorithm, int requestsPerSecond, int burstSize) {
    RateLimitConfig config;
    config.algorithm = (RateLimitAlgorithm)algorithm;
    config.requestsPerSecond = requestsPerSecond;
    config.burstSize = burstSize;
    config.cooldownMs = 0;
    
    return g_RateLimiter.Initialize(config);
}

bool RateLimiter_Allow(const char* key) {
    return g_RateLimiter.AllowRequest(key);
}

void RateLimiter_GetStatus(const char* key, double* currentRate, int* remaining, int* resetTime) {
    g_RateLimiter.GetStatus(key, *currentRate, *remaining, *resetTime);
}

void RateLimiter_GetStats(const char* key, uint64_t* total, uint64_t* rejected) {
    g_RateLimiter.GetStats(key, *total, *rejected);
}

bool RateLimiter_Reset(const char* key) {
    return g_RateLimiter.Reset(key);
}

void RateLimiter_Shutdown() {
    g_RateLimiter.Shutdown();
}

} // extern "C"
