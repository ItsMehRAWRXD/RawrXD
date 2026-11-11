// RawrXD Security Manager
// Phase AG: Security Hardening

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <chrono>

namespace rawrxd {
namespace security {

// Security levels
enum class SecurityLevel {
    NONE = 0,
    BASIC = 1,
    STANDARD = 2,
    HIGH = 3,
    MAXIMUM = 4
};

// Audit event types
enum class AuditEventType {
    AUTHENTICATION,
    AUTHORIZATION,
    DATA_ACCESS,
    CONFIG_CHANGE,
    MODEL_LOAD,
    INFERENCE_REQUEST,
    API_CALL,
    SECURITY_VIOLATION,
    SYSTEM_EVENT
};

// Audit event severity
enum class AuditSeverity {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

// Audit event structure
struct AuditEvent {
    std::string id;
    AuditEventType type;
    AuditSeverity severity;
    std::string user;
    std::string action;
    std::string resource;
    std::string details;
    std::string ip_address;
    std::chrono::system_clock::time_point timestamp;
    bool success;
    
    AuditEvent();
    std::string toJson() const;
};

// Rate limiting configuration
struct RateLimitConfig {
    int max_requests_per_minute;
    int max_tokens_per_day;
    int max_concurrent_requests;
    std::chrono::seconds window_duration;
};

// Security policy
struct SecurityPolicy {
    SecurityLevel level;
    bool require_authentication;
    bool require_encryption;
    bool audit_all_requests;
    bool enable_rate_limiting;
    bool enable_input_validation;
    bool enable_output_filtering;
    RateLimitConfig rate_limits;
    std::vector<std::string> allowed_origins;
    std::vector<std::string> blocked_ips;
};

// Forward declarations
class AuditLogger;
class RateLimiter;
class InputValidator;
class EncryptionManager;

/**
 * Security Manager - Central security coordinator
 * 
 * Manages authentication, authorization, audit logging,
 * rate limiting, and input validation.
 */
class SecurityManager {
public:
    SecurityManager();
    ~SecurityManager();
    
    // Initialize with security policy
    bool initialize(const SecurityPolicy& policy);
    
    // Authentication
    bool authenticate(const std::string& api_key);
    bool authenticateUser(const std::string& username, const std::string& password);
    std::string generateApiKey(const std::string& user_id);
    void revokeApiKey(const std::string& api_key);
    
    // Authorization
    bool authorize(const std::string& user, const std::string& resource, const std::string& action);
    bool checkPermission(const std::string& user, const std::string& permission);
    
    // Audit logging
    void logEvent(const AuditEvent& event);
    void logEvent(AuditEventType type, AuditSeverity severity, const std::string& user,
                  const std::string& action, const std::string& resource,
                  const std::string& details, bool success);
    std::vector<AuditEvent> getAuditLog(const std::chrono::system_clock::time_point& start,
                                        const std::chrono::system_clock::time_point& end);
    
    // Rate limiting
    bool checkRateLimit(const std::string& client_id);
    bool checkTokenQuota(const std::string& user_id, int tokens_requested);
    void recordRequest(const std::string& client_id);
    
    // Input validation
    bool validateInput(const std::string& input, std::string& error);
    bool sanitizeOutput(std::string& output);
    
    // Encryption
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);
    
    // Security checks
    bool isIpBlocked(const std::string& ip);
    bool isOriginAllowed(const std::string& origin);
    
    // Policy management
    void setPolicy(const SecurityPolicy& policy);
    SecurityPolicy getPolicy() const;
    
    // Getters
    AuditLogger* getAuditLogger() { return audit_logger_.get(); }
    RateLimiter* getRateLimiter() { return rate_limiter_.get(); }
    
private:
    std::unique_ptr<AuditLogger> audit_logger_;
    std::unique_ptr<RateLimiter> rate_limiter_;
    std::unique_ptr<InputValidator> input_validator_;
    std::unique_ptr<EncryptionManager> encryption_manager_;
    
    SecurityPolicy policy_;
    mutable std::mutex policy_mutex_;
    
    std::unordered_map<std::string, std::string> api_keys_;
    std::unordered_map<std::string, std::vector<std::string>> user_permissions_;
    mutable std::mutex auth_mutex_;
    
    bool initialized_;
};

/**
 * Audit Logger - Persistent audit trail
 */
class AuditLogger {
public:
    AuditLogger();
    ~AuditLogger();
    
    bool initialize(const std::string& log_file);
    void log(const AuditEvent& event);
    std::vector<AuditEvent> query(const std::chrono::system_clock::time_point& start,
                                    const std::chrono::system_clock::time_point& end);
    void rotateLogs();
    
private:
    std::string log_file_;
    std::mutex log_mutex_;
    bool initialized_;
};

/**
 * Rate Limiter - Request throttling
 */
class RateLimiter {
public:
    RateLimiter();
    
    void configure(const RateLimitConfig& config);
    bool checkLimit(const std::string& client_id);
    bool checkQuota(const std::string& user_id, int tokens);
    void record(const std::string& client_id);
    void reset(const std::string& client_id);
    
private:
    struct ClientStats {
        int request_count;
        std::chrono::system_clock::time_point window_start;
        int token_count;
        std::chrono::system_clock::time_point day_start;
    };
    
    RateLimitConfig config_;
    std::unordered_map<std::string, ClientStats> stats_;
    std::mutex stats_mutex_;
};

/**
 * Input Validator - Sanitization and validation
 */
class InputValidator {
public:
    InputValidator();
    
    bool validatePrompt(const std::string& prompt, std::string& error);
    bool validateModelName(const std::string& name, std::string& error);
    bool validateApiKey(const std::string& key, std::string& error);
    bool sanitize(std::string& text);
    
    void addForbiddenPattern(const std::string& pattern);
    void clearForbiddenPatterns();
    
private:
    std::vector<std::string> forbidden_patterns_;
    std::mutex patterns_mutex_;
};

/**
 * Encryption Manager - Data encryption utilities
 */
class EncryptionManager {
public:
    EncryptionManager();
    
    bool initialize(const std::string& key_file);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);
    std::string hash(const std::string& data);
    bool verifyHash(const std::string& data, const std::string& hash);
    
private:
    std::string master_key_;
    bool initialized_;
};

// Global security manager accessor
SecurityManager* getSecurityManager();
void setSecurityManager(std::unique_ptr<SecurityManager> manager);

} // namespace security
} // namespace rawrxd
