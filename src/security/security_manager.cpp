// RawrXD Security Manager Implementation
// Phase AG: Security Hardening

#include "security_manager.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <regex>

// For SHA256 hashing (simplified - use proper crypto library in production)
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace rawrxd {
namespace security {

// Global security manager instance
static std::unique_ptr<SecurityManager> g_security_manager;

SecurityManager* getSecurityManager() {
    return g_security_manager.get();
}

void setSecurityManager(std::unique_ptr<SecurityManager> manager) {
    g_security_manager = std::move(manager);
}

// AuditEvent implementation
AuditEvent::AuditEvent()
    : type(AuditEventType::SYSTEM_EVENT)
    , severity(AuditSeverity::INFO)
    , success(true)
    , timestamp(std::chrono::system_clock::now()) {
    // Generate unique ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 16; ++i) {
        ss << dis(gen);
    }
    id = ss.str();
}

std::string AuditEvent::toJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"id\":\"" << id << "\",";
    ss << "\"type\":" << static_cast<int>(type) << ",";
    ss << "\"severity\":" << static_cast<int>(severity) << ",";
    ss << "\"user\":\"" << user << "\",";
    ss << "\"action\":\"" << action << "\",";
    ss << "\"resource\":\"" << resource << "\",";
    ss << "\"details\":\"" << details << "\",";
    ss << "\"ip\":\"" << ip_address << "\",";
    ss << "\"success\":" << (success ? "true" : "false") << ",";
    
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    ss << "\"timestamp\":\"" << std::put_time(std::localtime(&time_t), "%Y-%m-%dT%H:%M:%S") << "\"";
    ss << "}";
    return ss.str();
}

// SecurityManager implementation
SecurityManager::SecurityManager()
    : audit_logger_(std::make_unique<AuditLogger>())
    , rate_limiter_(std::make_unique<RateLimiter>())
    , input_validator_(std::make_unique<InputValidator>())
    , encryption_manager_(std::make_unique<EncryptionManager>())
    , initialized_(false) {
}

SecurityManager::~SecurityManager() = default;

bool SecurityManager::initialize(const SecurityPolicy& policy) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    
    policy_ = policy;
    
    // Initialize audit logger
    if (policy.audit_all_requests) {
        if (!audit_logger_->initialize("logs/audit.log")) {
            std::cerr << "Failed to initialize audit logger" << std::endl;
            return false;
        }
    }
    
    // Initialize rate limiter
    if (policy.enable_rate_limiting) {
        rate_limiter_->configure(policy.rate_limits);
    }
    
    // Initialize encryption
    if (policy.require_encryption) {
        if (!encryption_manager_->initialize("config/master.key")) {
            std::cerr << "Failed to initialize encryption manager" << std::endl;
            return false;
        }
    }
    
    initialized_ = true;
    
    logEvent(AuditEventType::SYSTEM_EVENT, AuditSeverity::INFO, "system",
             "security_init", "security_manager", "Security manager initialized", true);
    
    return true;
}

bool SecurityManager::authenticate(const std::string& api_key) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    if (!policy_.require_authentication) {
        return true;
    }
    
    auto it = api_keys_.find(api_key);
    if (it == api_keys_.end()) {
        logEvent(AuditEventType::AUTHENTICATION, AuditSeverity::WARNING, "unknown",
                 "api_auth", "api", "Invalid API key", false);
        return false;
    }
    
    logEvent(AuditEventType::AUTHENTICATION, AuditSeverity::INFO, it->second,
             "api_auth", "api", "API key authentication successful", true);
    return true;
}

bool SecurityManager::authenticateUser(const std::string& username, const std::string& password) {
    // Simplified - use proper password hashing in production
    logEvent(AuditEventType::AUTHENTICATION, AuditSeverity::INFO, username,
             "user_auth", "user", "User authentication attempted", true);
    return true;
}

std::string SecurityManager::generateApiKey(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    // Generate random API key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    ss << "rxd_";
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    
    std::string api_key = ss.str();
    api_keys_[api_key] = user_id;
    
    logEvent(AuditEventType::SYSTEM_EVENT, AuditSeverity::INFO, user_id,
             "api_key_gen", "api", "API key generated", true);
    
    return api_key;
}

void SecurityManager::revokeApiKey(const std::string& api_key) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    auto it = api_keys_.find(api_key);
    if (it != api_keys_.end()) {
        std::string user_id = it->second;
        api_keys_.erase(it);
        
        logEvent(AuditEventType::SYSTEM_EVENT, AuditSeverity::INFO, user_id,
                 "api_key_revoke", "api", "API key revoked", true);
    }
}

bool SecurityManager::authorize(const std::string& user, const std::string& resource, const std::string& action) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    auto it = user_permissions_.find(user);
    if (it == user_permissions_.end()) {
        logEvent(AuditEventType::AUTHORIZATION, AuditSeverity::WARNING, user,
                 action, resource, "User has no permissions", false);
        return false;
    }
    
    const auto& permissions = it->second;
    std::string required_perm = resource + ":" + action;
    
    if (std::find(permissions.begin(), permissions.end(), required_perm) == permissions.end()) {
        logEvent(AuditEventType::AUTHORIZATION, AuditSeverity::WARNING, user,
                 action, resource, "Permission denied", false);
        return false;
    }
    
    return true;
}

bool SecurityManager::checkPermission(const std::string& user, const std::string& permission) {
    return authorize(user, permission, "execute");
}

void SecurityManager::logEvent(const AuditEvent& event) {
    if (policy_.audit_all_requests && audit_logger_) {
        audit_logger_->log(event);
    }
}

void SecurityManager::logEvent(AuditEventType type, AuditSeverity severity, const std::string& user,
                               const std::string& action, const std::string& resource,
                               const std::string& details, bool success) {
    AuditEvent event;
    event.type = type;
    event.severity = severity;
    event.user = user;
    event.action = action;
    event.resource = resource;
    event.details = details;
    event.success = success;
    event.timestamp = std::chrono::system_clock::now();
    
    logEvent(event);
}

std::vector<AuditEvent> SecurityManager::getAuditLog(const std::chrono::system_clock::time_point& start,
                                                      const std::chrono::system_clock::time_point& end) {
    if (audit_logger_) {
        return audit_logger_->query(start, end);
    }
    return {};
}

bool SecurityManager::checkRateLimit(const std::string& client_id) {
    if (!policy_.enable_rate_limiting) {
        return true;
    }
    return rate_limiter_->checkLimit(client_id);
}

bool SecurityManager::checkTokenQuota(const std::string& user_id, int tokens_requested) {
    if (!policy_.enable_rate_limiting) {
        return true;
    }
    return rate_limiter_->checkQuota(user_id, tokens_requested);
}

void SecurityManager::recordRequest(const std::string& client_id) {
    if (policy_.enable_rate_limiting) {
        rate_limiter_->record(client_id);
    }
}

bool SecurityManager::validateInput(const std::string& input, std::string& error) {
    if (!policy_.enable_input_validation) {
        return true;
    }
    return input_validator_->validatePrompt(input, error);
}

bool SecurityManager::sanitizeOutput(std::string& output) {
    if (!policy_.enable_output_filtering) {
        return true;
    }
    return input_validator_->sanitize(output);
}

std::string SecurityManager::encrypt(const std::string& plaintext) {
    if (policy_.require_encryption) {
        return encryption_manager_->encrypt(plaintext);
    }
    return plaintext;
}

std::string SecurityManager::decrypt(const std::string& ciphertext) {
    if (policy_.require_encryption) {
        return encryption_manager_->decrypt(ciphertext);
    }
    return ciphertext;
}

bool SecurityManager::isIpBlocked(const std::string& ip) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    return std::find(policy_.blocked_ips.begin(), policy_.blocked_ips.end(), ip) != policy_.blocked_ips.end();
}

bool SecurityManager::isOriginAllowed(const std::string& origin) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    if (policy_.allowed_origins.empty()) {
        return true;
    }
    return std::find(policy_.allowed_origins.begin(), policy_.allowed_origins.end(), origin) != policy_.allowed_origins.end();
}

void SecurityManager::setPolicy(const SecurityPolicy& policy) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    policy_ = policy;
    
    if (policy.enable_rate_limiting) {
        rate_limiter_->configure(policy.rate_limits);
    }
}

SecurityPolicy SecurityManager::getPolicy() const {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    return policy_;
}

// AuditLogger implementation
AuditLogger::AuditLogger() : initialized_(false) {}

AuditLogger::~AuditLogger() = default;

bool AuditLogger::initialize(const std::string& log_file) {
    log_file_ = log_file;
    initialized_ = true;
    return true;
}

void AuditLogger::log(const AuditEvent& event) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    std::ofstream file(log_file_, std::ios::app);
    if (file.is_open()) {
        file << event.toJson() << std::endl;
    }
}

std::vector<AuditEvent> AuditLogger::query(const std::chrono::system_clock::time_point& start,
                                           const std::chrono::system_clock::time_point& end) {
    std::vector<AuditEvent> results;
    // Implementation would parse log file and filter by time range
    return results;
}

void AuditLogger::rotateLogs() {
    std::lock_guard<std::mutex> lock(log_mutex_);
    // Implementation would rotate log files
}

// RateLimiter implementation
RateLimiter::RateLimiter() = default;

void RateLimiter::configure(const RateLimitConfig& config) {
    config_ = config;
}

bool RateLimiter::checkLimit(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto& stats = stats_[client_id];
    
    // Check if window has expired
    if (now - stats.window_start > config_.window_duration) {
        stats.request_count = 0;
        stats.window_start = now;
    }
    
    // Check concurrent requests
    // Note: This is simplified - would need proper tracking
    
    return stats.request_count < config_.max_requests_per_minute;
}

bool RateLimiter::checkQuota(const std::string& user_id, int tokens) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto& stats = stats_[user_id];
    
    // Check if day has passed
    auto day_duration = std::chrono::hours(24);
    if (now - stats.day_start > day_duration) {
        stats.token_count = 0;
        stats.day_start = now;
    }
    
    return (stats.token_count + tokens) <= config_.max_tokens_per_day;
}

void RateLimiter::record(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_[client_id].request_count++;
}

void RateLimiter::reset(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.erase(client_id);
}

// InputValidator implementation
InputValidator::InputValidator() = default;

bool InputValidator::validatePrompt(const std::string& prompt, std::string& error) {
    // Check length
    if (prompt.length() > 100000) {
        error = "Prompt exceeds maximum length";
        return false;
    }
    
    // Check for forbidden patterns
    std::lock_guard<std::mutex> lock(patterns_mutex_);
    for (const auto& pattern : forbidden_patterns_) {
        if (prompt.find(pattern) != std::string::npos) {
            error = "Prompt contains forbidden content";
            return false;
        }
    }
    
    return true;
}

bool InputValidator::validateModelName(const std::string& name, std::string& error) {
    // Allow alphanumeric, hyphens, and underscores
    std::regex valid_name("^[a-zA-Z0-9_-]+$");
    if (!std::regex_match(name, valid_name)) {
        error = "Invalid model name format";
        return false;
    }
    return true;
}

bool InputValidator::validateApiKey(const std::string& key, std::string& error) {
    if (key.length() < 32) {
        error = "API key too short";
        return false;
    }
    return true;
}

bool InputValidator::sanitize(std::string& text) {
    // Remove potentially dangerous content
    // This is a simplified implementation
    text.erase(std::remove_if(text.begin(), text.end(), [](char c) {
        return c < 32 && c != '\n' && c != '\r' && c != '\t';
    }), text.end());
    return true;
}

void InputValidator::addForbiddenPattern(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(patterns_mutex_);
    forbidden_patterns_.push_back(pattern);
}

void InputValidator::clearForbiddenPatterns() {
    std::lock_guard<std::mutex> lock(patterns_mutex_);
    forbidden_patterns_.clear();
}

// EncryptionManager implementation
EncryptionManager::EncryptionManager() : initialized_(false) {}

bool EncryptionManager::initialize(const std::string& key_file) {
    // In production, load key from secure storage
    // This is a simplified implementation
    master_key_ = "placeholder_key_32_bytes_long!!";
    initialized_ = true;
    return true;
}

std::string EncryptionManager::encrypt(const std::string& plaintext) {
    // Simplified - use proper encryption in production
    // This is just a placeholder
    return "encrypted:" + plaintext;
}

std::string EncryptionManager::decrypt(const std::string& ciphertext) {
    // Simplified - use proper decryption in production
    if (ciphertext.substr(0, 10) == "encrypted:") {
        return ciphertext.substr(10);
    }
    return ciphertext;
}

std::string EncryptionManager::hash(const std::string& data) {
    // Use OpenSSL for SHA256
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.c_str(), data.length());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool EncryptionManager::verifyHash(const std::string& data, const std::string& hash) {
    return hash == EncryptionManager::hash(data);
}

} // namespace security
} // namespace rawrxd
