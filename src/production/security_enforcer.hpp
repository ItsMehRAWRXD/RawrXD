#pragma once

#include "../core/common.hpp"
#include <string>
#include <vector>
#include <unordered_set>

namespace rawrxd::production {

// Security policy configuration
struct SecurityPolicy {
    // Input validation
    bool validate_inputs = true;
    int max_prompt_length = 8192;
    int max_tokens_per_request = 4096;
    int max_requests_per_minute = 60;
    
    // Content filtering
    bool enable_content_filter = true;
    std::vector<std::string> blocked_patterns;
    std::vector<std::string> allowed_domains;
    
    // Authentication
    bool require_auth = true;
    std::string auth_method = "token";  // token, oauth, mtls
    int token_expiry_seconds = 3600;
    
    // Encryption
    bool require_tls = true;
    int min_tls_version = 12;  // 1.2 or 1.3
    bool encrypt_model_files = false;
    
    // Audit logging
    bool audit_all_requests = true;
    bool log_prompts = false;  // Privacy concern
    bool log_responses = false;
    int log_retention_days = 30;
    
    // Resource limits
    int max_concurrent_requests = 100;
    int max_memory_mb = 8192;
    int max_compute_time_seconds = 60;
};

// Security enforcer
class SecurityEnforcer {
public:
    explicit SecurityEnforcer(const SecurityPolicy& policy);
    
    // Validate request
    struct ValidationResult {
        bool allowed;
        std::string reason;
        std::string request_id;
    };
    
    ValidationResult validateRequest(const std::string& user_id,
                                      const std::string& request_path,
                                      const std::vector<int>& prompt_tokens);
    
    // Check content
    bool checkContent(const std::string& content);
    bool checkContent(const std::vector<int>& tokens);
    
    // Rate limiting
    bool checkRateLimit(const std::string& user_id);
    bool checkRateLimit(const std::string& user_id, int tokens);
    
    // Authentication
    bool authenticate(const std::string& token);
    bool authenticate(const std::string& api_key, const std::string& secret);
    
    // Authorization
    bool authorize(const std::string& user_id, const std::string& action);
    bool authorize(const std::string& user_id, const std::string& resource, 
                   const std::string& action);
    
    // Audit logging
    void logRequest(const std::string& request_id,
                    const std::string& user_id,
                    const std::string& action,
                    bool success,
                    const std::string& details = "");
    
    // Get security metrics
    struct SecurityMetrics {
        uint64_t total_requests = 0;
        uint64_t blocked_requests = 0;
        uint64_t rate_limited_requests = 0;
        uint64_t auth_failures = 0;
        uint64_t content_violations = 0;
    };
    
    SecurityMetrics getMetrics() const;
    
private:
    SecurityPolicy policy_;
    SecurityMetrics metrics_;
    mutable std::mutex metrics_mutex_;
    
    // Rate limit tracking
    std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>> rate_limits_;
    mutable std::mutex rate_limit_mutex_;
    
    // Blocked token cache
    std::unordered_set<std::string> blocked_token_cache_;
    mutable std::shared_mutex token_cache_mutex_;
    
    bool validateTokenCount(int count);
    bool validatePromptLength(size_t length);
    bool checkBlockedPatterns(const std::string& content);
};

// Input validator
class InputValidator {
public:
    // Validation rules
    struct ValidationRules {
        size_t max_length = 8192;
        size_t min_length = 1;
        bool allow_empty = false;
        bool sanitize_html = true;
        bool check_encoding = true;
        std::vector<std::string> required_fields;
        std::vector<std::string> forbidden_patterns;
    };
    
    explicit InputValidator(const ValidationRules& rules);
    
    // Validate string input
    bool validate(const std::string& input, std::string& error);
    
    // Validate JSON input
    bool validateJson(const std::string& json_str, std::string& error);
    
    // Sanitize input
    std::string sanitize(const std::string& input);
    
    // Check for injection attacks
    bool detectInjection(const std::string& input);
    bool detectSQLInjection(const std::string& input);
    bool detectXSS(const std::string& input);
    
private:
    ValidationRules rules_;
};

// Rate limiter
class RateLimiter {
public:
    enum class Strategy {
        TOKEN_BUCKET,      // Smooth rate limiting
        SLIDING_WINDOW,    // Precise window-based
        FIXED_WINDOW,      // Simple window-based
        LEAKY_BUCKET       // Traffic shaping
    };
    
    struct Config {
        int requests_per_second = 10;
        int burst_size = 20;
        Strategy strategy = Strategy::TOKEN_BUCKET;
    };
    
    explicit RateLimiter(const Config& config);
    
    // Check if request allowed
    bool allow(const std::string& key);
    bool allow(const std::string& key, int tokens);
    
    // Get remaining quota
    int getRemaining(const std::string& key);
    
    // Reset limit for key
    void reset(const std::string& key);
    
private:
    Config config_;
    
    struct RateLimitState {
        double tokens = 0;
        std::chrono::steady_clock::time_point last_update;
        int window_count = 0;
        std::chrono::steady_clock::time_point window_start;
    };
    
    std::unordered_map<std::string, RateLimitState> states_;
    mutable std::mutex mutex_;
    
    bool tokenBucketAllow(RateLimitState& state);
    bool slidingWindowAllow(RateLimitState& state);
};

// Audit logger
class AuditLogger {
public:
    struct AuditEntry {
        std::string timestamp;
        std::string request_id;
        std::string user_id;
        std::string action;
        std::string resource;
        bool success;
        std::string details;
        std::string ip_address;
        std::string user_agent;
    };
    
    explicit AuditLogger(const std::string& log_path);
    
    // Log entry
    void log(const AuditEntry& entry);
    
    // Query logs
    std::vector<AuditEntry> query(const std::string& user_id,
                                   const std::chrono::system_clock::time_point& start,
                                   const std::chrono::system_clock::time_point& end);
    
    // Export logs
    void exportToFile(const std::string& path, 
                      const std::chrono::system_clock::time_point& start,
                      const std::chrono::system_clock::time_point& end);
    
private:
    std::string log_path_;
    std::mutex mutex_;
    
    std::string formatEntry(const AuditEntry& entry);
};

} // namespace rawrxd::production
