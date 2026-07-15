#include "security/IntrusionPrevention.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct RateLimitData {
    int requestCount;
    int64_t windowStart;
    int blockedCount;
};

static std::map<std::string, RateLimitData> s_rateLimits;
static std::map<std::string, int64_t> s_blockedSources;
static std::map<std::string, nlohmann::json> s_policies;
static size_t s_blockedRequestCount = 0;
static size_t s_allowedRequestCount = 0;

void IntrusionPrevention::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_rateLimits.clear();
        s_blockedSources.clear();
        s_policies.clear();
        s_blockedRequestCount = 0;
        s_allowedRequestCount = 0;
        
        // Initialize default policies
        s_policies["default"] = {
            {"max_requests_per_minute", 100},
            {"block_duration_seconds", 300},
            {"enable_rate_limiting", true},
            {"enable_blocking", true}
        };
        
        s_initialized = true;
    }
}

void IntrusionPrevention::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    
    // Reset rate limit windows
    for (auto& [source, data] : s_rateLimits) {
        if ((now - data.windowStart) > 60000000) { // 1 minute
            data.requestCount = 0;
            data.windowStart = now;
        }
    }
    
    // Unblock expired blocks
    std::vector<std::string> toUnblock;
    for (const auto& [source, blockedAt] : s_blockedSources) {
        if ((now - blockedAt) > 300000000) { // 5 minutes
            toUnblock.push_back(source);
        }
    }
    for (const auto& source : toUnblock) {
        s_blockedSources.erase(source);
    }
}

bool IntrusionPrevention::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json IntrusionPrevention::CheckIntrusion(const nlohmann::json& request) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    std::string source = request.value("source", "unknown");
    
    // Check if blocked
    if (IsBlocked(source)) {
        s_blockedRequestCount++;
        return {
            {"allowed", false},
            {"reason", "source_blocked"},
            {"source", source}
        };
    }
    
    // Check rate limit
    if (!CheckRateLimit(source)) {
        s_blockedRequestCount++;
        BlockSource(source);
        return {
            {"allowed", false},
            {"reason", "rate_limit_exceeded"},
            {"source", source}
        };
    }
    
    s_allowedRequestCount++;
    return {
        {"allowed", true},
        {"source", source}
    };
}

bool IntrusionPrevention::ValidateRequest(const nlohmann::json& request) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return false;
    
    // Basic validation
    if (!request.contains("source")) return false;
    if (!request.contains("timestamp")) return false;
    
    // Check for suspicious patterns
    std::string source = request.value("source", "");
    if (source.empty() || source.length() > 256) return false;
    
    return true;
}

void IntrusionPrevention::BlockSource(const std::string& source) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_blockedSources[source] = std::chrono::system_clock::now().time_since_epoch().count();
}

void IntrusionPrevention::UnblockSource(const std::string& source) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_blockedSources.erase(source);
}

bool IntrusionPrevention::IsBlocked(const std::string& source) {
    return s_blockedSources.find(source) != s_blockedSources.end();
}

bool IntrusionPrevention::CheckRateLimit(const std::string& source) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return true;
    
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    auto& data = s_rateLimits[source];
    
    // Reset window if needed
    if ((now - data.windowStart) > 60000000) {
        data.requestCount = 0;
        data.windowStart = now;
    }
    
    // Check limit (100 requests per minute)
    if (data.requestCount >= 100) {
        data.blockedCount++;
        return false;
    }
    
    data.requestCount++;
    return true;
}

nlohmann::json IntrusionPrevention::GetRateLimitStatus(const std::string& source) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_rateLimits.find(source);
    if (it != s_rateLimits.end()) {
        return {
            {"source", source},
            {"request_count", it->second.requestCount},
            {"blocked_count", it->second.blockedCount},
            {"window_start", it->second.windowStart}
        };
    }
    
    return {
        {"source", source},
        {"request_count", 0},
        {"blocked_count", 0}
    };
}

void IntrusionPrevention::SetPolicy(const std::string& policyName, const nlohmann::json& policy) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_policies[policyName] = policy;
}

nlohmann::json IntrusionPrevention::GetPolicy(const std::string& policyName) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_policies.find(policyName);
    if (it != s_policies.end()) {
        return it->second;
    }
    return nlohmann::json{};
}

nlohmann::json IntrusionPrevention::GetAllPolicies() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_policies;
}

nlohmann::json IntrusionPrevention::GetPreventionMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    return {
        {"blocked_sources", s_blockedSources.size()},
        {"rate_limited_sources", s_rateLimits.size()},
        {"blocked_requests", s_blockedRequestCount},
        {"allowed_requests", s_allowedRequestCount},
        {"policies_defined", s_policies.size()}
    };
}
