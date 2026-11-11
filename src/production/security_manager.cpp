/**
 * @file security_manager.cpp
 * @brief Security manager implementation
 * @version 14.7.3
 * @date 2026-07-14
 */

#include "security_manager.hpp"
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace rawrxd {
namespace production {

// ============================================================================
// SecurityManager Implementation
// ============================================================================

class SecurityManager::Impl {
public:
    SecurityLevel level_;
    std::map<std::string, RateLimitBucket> rate_buckets_;
    std::map<std::string, Credentials> users_;
    std::map<std::string, std::string> api_keys_;
    std::map<std::string, std::vector<std::string>> user_roles_;
    std::vector<AuditLogEntry> audit_log_;
    mutable std::shared_mutex mutex_;
    
    int max_tokens_ = 100;
    int refill_rate_ = 10;

    bool initialize(SecurityLevel level) {
        level_ = level;
        
        // Configure based on security level
        switch (level) {
            case SecurityLevel::LOW:
                max_tokens_ = 1000;
                refill_rate_ = 100;
                break;
            case SecurityLevel::MEDIUM:
                max_tokens_ = 100;
                refill_rate_ = 10;
                break;
            case SecurityLevel::HIGH:
                max_tokens_ = 50;
                refill_rate_ = 5;
                break;
            case SecurityLevel::MAXIMUM:
                max_tokens_ = 10;
                refill_rate_ = 1;
                break;
        }
        
        return true;
    }

    std::optional<std::string> validateInput(const std::string& input, size_t max_length) {
        // Check length
        if (input.length() > max_length) {
            return std::nullopt;
        }

        // Check for null bytes
        if (input.find('\0') != std::string::npos) {
            return std::nullopt;
        }

        // Basic sanitization
        std::string sanitized = input;
        
        // Remove control characters except common whitespace
        sanitized.erase(
            std::remove_if(sanitized.begin(), sanitized.end(),
                [](unsigned char c) {
                    return c < 32 && c != '\t' && c != '\n' && c != '\r';
                }),
            sanitized.end()
        );

        return sanitized;
    }

    bool detectSqlInjection(const std::string& input) {
        std::vector<std::string> patterns = {
            "'", "--", "/*", "*/", ";", "DROP", "DELETE", "INSERT",
            "UPDATE", "SELECT", "UNION", "EXEC", "EXECUTE"
        };
        
        std::string upper_input = input;
        std::transform(upper_input.begin(), upper_input.end(), upper_input.begin(), ::toupper);
        
        for (const auto& pattern : patterns) {
            if (upper_input.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool detectXss(const std::string& input) {
        std::vector<std::string> patterns = {
            "<script", "javascript:", "onerror=", "onload=",
            "eval(", "expression(", "<iframe", "<object"
        };
        
        std::string lower_input = input;
        std::transform(lower_input.begin(), lower_input.end(), lower_input.begin(), ::tolower);
        
        for (const auto& pattern : patterns) {
            if (lower_input.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool checkRateLimit(const std::string& client_id, int cost) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto& bucket = rate_buckets_[client_id];
        
        // Initialize if new
        if (bucket.max_tokens == 0) {
            bucket.max_tokens = max_tokens_;
            bucket.tokens = max_tokens_;
            bucket.refill_rate = std::chrono::seconds(1);
            bucket.last_update = now;
        }

        // Calculate tokens to add
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - bucket.last_update);
        int tokens_to_add = elapsed.count() * refill_rate_;
        bucket.tokens = std::min(bucket.max_tokens, bucket.tokens + tokens_to_add);
        bucket.last_update = now;

        // Check if request can be processed
        if (bucket.tokens >= cost) {
            bucket.tokens -= cost;
            return true;
        }
        
        return false;
    }

    bool authenticate(const Credentials& credentials) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        
        auto it = users_.find(credentials.username);
        if (it == users_.end()) {
            return false;
        }

        return verifyPassword(credentials.password_hash, it->second.password_hash);
    }

    std::string authenticateApiKey(const std::string& api_key) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        
        for (const auto& [user, key] : api_keys_) {
            if (key == api_key) {
                return user;
            }
        }
        return "";
    }

    bool authorize(const std::string& user, const std::string& resource, const std::string& action) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        
        auto it = user_roles_.find(user);
        if (it == user_roles_.end()) {
            return false;
        }

        // Check if user has required role
        for (const auto& role : it->second) {
            if (role == "admin") return true;
            if (role == "user" && action != "delete") return true;
            if (role == "readonly" && action == "read") return true;
        }

        return false;
    }

    bool hasRole(const std::string& user, const std::string& role) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        
        auto it = user_roles_.find(user);
        if (it == user_roles_.end()) {
            return false;
        }

        return std::find(it->second.begin(), it->second.end(), role) != it->second.end();
    }

    void auditLog(const AuditLogEntry& entry) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        audit_log_.push_back(entry);
        
        // Keep only last 10000 entries
        if (audit_log_.size() > 10000) {
            audit_log_.erase(audit_log_.begin(), audit_log_.begin() + (audit_log_.size() - 10000));
        }
    }

    std::vector<AuditLogEntry> getAuditLog(size_t count) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        
        size_t start = audit_log_.size() > count ? audit_log_.size() - count : 0;
        return std::vector<AuditLogEntry>(audit_log_.begin() + start, audit_log_.end());
    }
};

// Public interface
SecurityManager::SecurityManager() : impl_(std::make_unique<Impl>()) {}
SecurityManager::~SecurityManager() = default;

bool SecurityManager::initialize(SecurityLevel level) {
    return impl_->initialize(level);
}

std::optional<std::string> SecurityManager::validateInput(const std::string& input, size_t max_length) {
    return impl_->validateInput(input, max_length);
}

bool SecurityManager::detectSqlInjection(const std::string& input) {
    return impl_->detectSqlInjection(input);
}

bool SecurityManager::detectXss(const std::string& input) {
    return impl_->detectXss(input);
}

bool SecurityManager::checkRateLimit(const std::string& client_id, int cost) {
    return impl_->checkRateLimit(client_id, cost);
}

void SecurityManager::configureRateLimit(int max_tokens, int refill_rate) {
    impl_->max_tokens_ = max_tokens;
    impl_->refill_rate_ = refill_rate;
}

bool SecurityManager::authenticate(const Credentials& credentials) {
    return impl_->authenticate(credentials);
}

std::string SecurityManager::authenticateApiKey(const std::string& api_key) {
    return impl_->authenticateApiKey(api_key);
}

bool SecurityManager::authorize(const std::string& user, const std::string& resource, const std::string& action) {
    return impl_->authorize(user, resource, action);
}

bool SecurityManager::hasRole(const std::string& user, const std::string& role) {
    return impl_->hasRole(user, role);
}

void SecurityManager::auditLog(const AuditLogEntry& entry) {
    impl_->auditLog(entry);
}

void SecurityManager::auditLog(const std::string& action, const std::string& user, 
                                  const std::string& resource, const std::string& result) {
    AuditLogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.action = action;
    entry.user = user;
    entry.resource = resource;
    entry.result = result;
    impl_->auditLog(entry);
}

std::vector<AuditLogEntry> SecurityManager::getAuditLog(size_t count) {
    return impl_->getAuditLog(count);
}

std::string SecurityManager::hashPassword(const std::string& password) {
    // Simple hash for demonstration - use bcrypt/Argon2 in production
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, password.c_str(), password.length());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool SecurityManager::verifyPassword(const std::string& password, const std::string& hash) {
    return hashPassword(password) == hash;
}

std::string SecurityManager::generateApiKey() {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));
    
    std::stringstream ss;
    ss << "rxd_";
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]);
    }
    return ss.str();
}

std::string SecurityManager::sanitizeHtml(const std::string& html) {
    std::string sanitized = html;
    // Replace < and >
    size_t pos = 0;
    while ((pos = sanitized.find('<', pos)) != std::string::npos) {
        sanitized.replace(pos, 1, "&lt;");
        pos += 4;
    }
    pos = 0;
    while ((pos = sanitized.find('>', pos)) != std::string::npos) {
        sanitized.replace(pos, 1, "&gt;");
        pos += 4;
    }
    return sanitized;
}

std::string SecurityManager::escapeJson(const std::string& input) {
    std::string escaped;
    for (char c : input) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c >= 0x20 && c < 0x7F) {
                    escaped += c;
                } else {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    escaped += buf;
                }
        }
    }
    return escaped;
}

SecurityLevel SecurityManager::getSecurityLevel() const {
    return impl_->level_;
}

void SecurityManager::setSecurityLevel(SecurityLevel level) {
    impl_->level_ = level;
}

} // namespace production
} // namespace rawrxd
