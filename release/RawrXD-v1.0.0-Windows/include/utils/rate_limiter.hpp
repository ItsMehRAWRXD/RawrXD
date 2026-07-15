// rate_limiter.hpp — Thread-Safe Rate Limiter for RAG Pipeline
// Production-ready rate limiting with token bucket algorithm
// ============================================================================

#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <string>
#include <optional>

namespace rawrxd {
namespace utils {

// ============================================================================
// Rate Limit Result
// ============================================================================

struct RateLimitResult {
    bool allowed;
    uint64_t retry_after_ms;
    uint32_t remaining;
    uint32_t limit;
    std::string reason;
    
    static RateLimitResult allow(uint32_t remaining, uint32_t limit) {
        return {true, 0, remaining, limit, ""};
    }
    
    static RateLimitResult deny(uint64_t retry_after_ms, const std::string& reason) {
        return {false, retry_after_ms, 0, 0, reason};
    }
};

// ============================================================================
// Token Bucket Rate Limiter
// ============================================================================

class TokenBucket {
public:
    TokenBucket(uint32_t max_tokens, uint32_t refill_rate_per_sec)
        : max_tokens_(max_tokens)
        , refill_rate_per_sec_(refill_rate_per_sec)
        , tokens_(max_tokens)
        , last_refill_(std::chrono::steady_clock::now()) {}
    
    RateLimitResult try_consume(uint32_t tokens = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        refill_tokens();
        
        if (tokens_ >= tokens) {
            tokens_ -= tokens;
            return RateLimitResult::allow(tokens_, max_tokens_);
        }
        
        // Calculate retry after time
        uint64_t needed = tokens - tokens_;
        uint64_t retry_ms = (needed * 1000) / refill_rate_per_sec_;
        
        return RateLimitResult::deny(retry_ms, "Rate limit exceeded");
    }
    
    uint32_t get_remaining_tokens() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tokens_;
    }
    
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        tokens_ = max_tokens_;
        last_refill_ = std::chrono::steady_clock::now();
    }

private:
    void refill_tokens() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_refill_).count();
        
        if (elapsed > 0) {
            tokens_ = std::min(max_tokens_, tokens_ + static_cast<uint32_t>(
                elapsed * refill_rate_per_sec_));
            last_refill_ = now;
        }
    }
    
    uint32_t max_tokens_;
    uint32_t refill_rate_per_sec_;
    uint32_t tokens_;
    std::chrono::steady_clock::time_point last_refill_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Per-Client Rate Limiter
// ============================================================================

class PerClientRateLimiter {
private:
    struct ClientBucket {
        std::unique_ptr<TokenBucket> bucket;
        std::chrono::steady_clock::time_point last_access;
        
        ClientBucket() = default;
        
        ClientBucket(uint32_t max_tokens, uint32_t refill_rate, std::chrono::steady_clock::time_point access)
            : bucket(std::make_unique<TokenBucket>(max_tokens, refill_rate))
            , last_access(access) {}
            
        // Move constructor and move assignment (required for unordered_map)
        ClientBucket(ClientBucket&&) = default;
        ClientBucket& operator=(ClientBucket&&) = default;
        
        // Delete copy constructor and copy assignment
        ClientBucket(const ClientBucket&) = delete;
        ClientBucket& operator=(const ClientBucket&) = delete;
    };

public:
    PerClientRateLimiter(uint32_t max_tokens, uint32_t refill_rate_per_sec,
                         std::chrono::minutes client_ttl = std::chrono::minutes(60))
        : max_tokens_(max_tokens)
        , refill_rate_per_sec_(refill_rate_per_sec)
        , client_ttl_(client_ttl) {}
    
    RateLimitResult check_client(const std::string& client_id, uint32_t tokens = 1) {
        std::unique_lock<std::shared_mutex> lock(buckets_mutex_);
        
        cleanup_expired_clients();
        
        auto it = buckets_.find(client_id);
        if (it == buckets_.end()) {
            // Create new bucket for this client
            ClientBucket new_bucket(max_tokens_, refill_rate_per_sec_, std::chrono::steady_clock::now());
            auto [new_it, inserted] = buckets_.emplace(client_id, std::move(new_bucket));
            it = new_it;
        }
        
        // Update last access time
        it->second.last_access = std::chrono::steady_clock::now();
        
        // Release shared lock and acquire exclusive lock on bucket
        lock.unlock();
        
        return it->second.bucket->try_consume(tokens);
    }
    
    void reset_client(const std::string& client_id) {
        std::unique_lock<std::shared_mutex> lock(buckets_mutex_);
        
        auto it = buckets_.find(client_id);
        if (it != buckets_.end()) {
            it->second.bucket->reset();
        }
    }
    
    void remove_client(const std::string& client_id) {
        std::unique_lock<std::shared_mutex> lock(buckets_mutex_);
        buckets_.erase(client_id);
    }
    
    size_t get_client_count() const {
        std::shared_lock<std::shared_mutex> lock(buckets_mutex_);
        return buckets_.size();
    }
    
    void cleanup_expired_clients() {
        auto now = std::chrono::steady_clock::now();
        
        for (auto it = buckets_.begin(); it != buckets_.end();) {
            auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
                now - it->second.last_access);
            
            if (elapsed > client_ttl_) {
                it = buckets_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    uint32_t max_tokens_;
    uint32_t refill_rate_per_sec_;
    std::chrono::minutes client_ttl_;
    
    mutable std::shared_mutex buckets_mutex_;
    std::unordered_map<std::string, ClientBucket> buckets_;
};

// ============================================================================
// RAG Pipeline Rate Limiter (Global Instance)
// ============================================================================

class RAGRateLimiter {
public:
    // Default: 10 requests per second burst, 100 per minute sustained
    static RAGRateLimiter& instance() {
        static RAGRateLimiter instance;
        return instance;
    }
    
    void configure(uint32_t burst_limit, uint32_t sustained_per_minute) {
        global_limiter_.emplace(burst_limit, sustained_per_minute / 60);
    }
    
    RateLimitResult check_global() {
        if (!global_limiter_.has_value()) {
            return RateLimitResult::allow(1, 1); // No limit configured
        }
        return global_limiter_->try_consume(1);
    }
    
    RateLimitResult check_client(const std::string& client_id) {
        if (!client_limiter_.has_value()) {
            return check_global();
        }
        return client_limiter_->check_client(client_id);
    }
    
    void enable_client_limiting(uint32_t burst_limit, uint32_t sustained_per_minute,
                                std::chrono::minutes client_ttl = std::chrono::minutes(60)) {
        client_limiter_.emplace(burst_limit, sustained_per_minute / 60, client_ttl);
    }
    
    void reset() {
        if (global_limiter_.has_value()) {
            global_limiter_->reset();
        }
        if (client_limiter_.has_value()) {
            // Can't easily reset all clients, but they can be reset individually
        }
    }

private:
    RAGRateLimiter() = default;
    
    std::optional<TokenBucket> global_limiter_;
    std::optional<PerClientRateLimiter> client_limiter_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

inline RateLimitResult check_rag_rate_limit(const std::string& client_id = "") {
    if (client_id.empty()) {
        return RAGRateLimiter::instance().check_global();
    }
    return RAGRateLimiter::instance().check_client(client_id);
}

inline void configure_rag_rate_limit(uint32_t burst_limit, uint32_t sustained_per_minute) {
    RAGRateLimiter::instance().configure(burst_limit, sustained_per_minute);
}

} // namespace utils
} // namespace rawrxd
