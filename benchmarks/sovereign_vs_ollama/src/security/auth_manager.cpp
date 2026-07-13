// auth_manager.cpp
// Batch 13: Authentication and Authorization
//
// Manages API keys, tokens, and access control
// Features: JWT validation, role-based access, API key management

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <optional>
#include <functional>
#include <algorithm>

namespace Benchmark {
namespace Security {

// Authentication result
struct AuthResult {
    bool success;
    std::string user_id;
    std::string role;
    std::vector<std::string> permissions;
    int64_t expires_at;
    std::string error_message;
    
    static AuthResult Success(const std::string& uid, const std::string& r) {
        AuthResult result;
        result.success = true;
        result.user_id = uid;
        result.role = r;
        result.expires_at = GetExpiryTime(3600);  // 1 hour
        return result;
    }
    
    static AuthResult Failure(const std::string& message) {
        AuthResult result;
        result.success = false;
        result.error_message = message;
        return result;
    }
    
private:
    static int64_t GetExpiryTime(int seconds) {
        auto now = std::chrono::system_clock::now();
        auto expiry = now + std::chrono::seconds(seconds);
        return std::chrono::duration_cast<std::chrono::seconds>(
            expiry.time_since_epoch()).count();
    }
};

// API Key structure
struct APIKey {
    std::string key_id;
    std::string key_hash;
    std::string user_id;
    std::string role;
    std::vector<std::string> permissions;
    int64_t created_at;
    int64_t expires_at;
    int64_t last_used;
    int use_count;
    bool active;
    std::string description;
};

// API Key manager
class APIKeyManager {
public:
    struct Config {
        int key_length = 32;
        int max_keys_per_user = 10;
        int default_expiry_days = 365;
        bool require_rotation = true;
        int rotation_warning_days = 30;
    };
    
    explicit APIKeyManager(const Config& config = Config()) : config_(config) {}
    
    // Generate new API key
    std::pair<std::string, APIKey> GenerateKey(
        const std::string& user_id,
        const std::string& role,
        const std::vector<std::string>& permissions,
        const std::string& description = "",
        int expiry_days = -1) {
        
        // Check key limit
        if (CountUserKeys(user_id) >= config_.max_keys_per_user) {
            return {"", {}};
        }
        
        // Generate key
        std::string key = GenerateRandomKey(config_.key_length);
        std::string key_id = "key_" + std::to_string(GetTimestamp());
        
        APIKey api_key;
        api_key.key_id = key_id;
        api_key.key_hash = HashKey(key);
        api_key.user_id = user_id;
        api_key.role = role;
        api_key.permissions = permissions;
        api_key.created_at = GetTimestamp();
        api_key.expires_at = GetTimestamp() + 
            (expiry_days > 0 ? expiry_days : config_.default_expiry_days) * 86400;
        api_key.last_used = 0;
        api_key.use_count = 0;
        api_key.active = true;
        api_key.description = description;
        
        // Store key
        {
            std::lock_guard<std::mutex> lock(keys_mutex_);
            keys_[key_id] = api_key;
            key_lookup_[api_key.key_hash] = key_id;
        }
        
        return {key, api_key};
    }
    
    // Validate API key
    AuthResult ValidateKey(const std::string& key) {
        std::string key_hash = HashKey(key);
        
        std::lock_guard<std::mutex> lock(keys_mutex_);
        
        auto it = key_lookup_.find(key_hash);
        if (it == key_lookup_.end()) {
            return AuthResult::Failure("Invalid API key");
        }
        
        auto key_it = keys_.find(it->second);
        if (key_it == keys_.end()) {
            return AuthResult::Failure("Key not found");
        }
        
        APIKey& api_key = key_it->second;
        
        // Check if active
        if (!api_key.active) {
            return AuthResult::Failure("API key is deactivated");
        }
        
        // Check expiry
        if (api_key.expires_at < GetTimestamp()) {
            return AuthResult::Failure("API key has expired");
        }
        
        // Update usage
        api_key.last_used = GetTimestamp();
        api_key.use_count++;
        
        return AuthResult::Success(api_key.user_id, api_key.role);
    }
    
    // Revoke API key
    bool RevokeKey(const std::string& key_id) {
        std::lock_guard<std::mutex> lock(keys_mutex_);
        
        auto it = keys_.find(key_id);
        if (it == keys_.end()) {
            return false;
        }
        
        it->second.active = false;
        return true;
    }
    
    // Get key info
    std::optional<APIKey> GetKeyInfo(const std::string& key_id) {
        std::lock_guard<std::mutex> lock(keys_mutex_);
        
        auto it = keys_.find(key_id);
        if (it != keys_.end()) {
            return it->second;
        }
        
        return std::nullopt;
    }
    
    // List user keys
    std::vector<APIKey> ListUserKeys(const std::string& user_id) {
        std::vector<APIKey> result;
        
        std::lock_guard<std::mutex> lock(keys_mutex_);
        
        for (const auto& [key_id, key] : keys_) {
            if (key.user_id == user_id) {
                result.push_back(key);
            }
        }
        
        return result;
    }
    
    // Check if key needs rotation
    bool NeedsRotation(const std::string& key_id) {
        auto key_opt = GetKeyInfo(key_id);
        if (!key_opt.has_value()) return false;
        
        const APIKey& key = key_opt.value();
        int64_t time_to_expiry = key.expires_at - GetTimestamp();
        
        return time_to_expiry < config_.rotation_warning_days * 86400;
    }
    
    // Cleanup expired keys
    int CleanupExpiredKeys() {
        std::lock_guard<std::mutex> lock(keys_mutex_);
        
        int removed = 0;
        auto now = GetTimestamp();
        
        for (auto it = keys_.begin(); it != keys_.end();) {
            if (it->second.expires_at < now && !it->second.active) {
                key_lookup_.erase(it->second.key_hash);
                it = keys_.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        
        return removed;
    }

private:
    Config config_;
    std::map<std::string, APIKey> keys_;
    std::map<std::string, std::string> key_lookup_;
    mutable std::mutex keys_mutex_;
    
    std::string GenerateRandomKey(int length) {
        const char charset[] = 
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string result;
        result.reserve(length);
        
        for (int i = 0; i < length; ++i) {
            result += charset[rand() % (sizeof(charset) - 1)];
        }
        
        return result;
    }
    
    std::string HashKey(const std::string& key) {
        // Simple hash - in production use bcrypt or Argon2
        std::hash<std::string> hasher;
        return std::to_string(hasher(key));
    }
    
    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    int CountUserKeys(const std::string& user_id) {
        int count = 0;
        for (const auto& [key_id, key] : keys_) {
            if (key.user_id == user_id && key.active) {
                ++count;
            }
        }
        return count;
    }
};

// Role-based access control
class RBACManager {
public:
    // Permission definitions
    static constexpr const char* PERM_BENCHMARK_READ = "benchmark:read";
    static constexpr const char* PERM_BENCHMARK_RUN = "benchmark:run";
    static constexpr const char* PERM_BENCHMARK_DELETE = "benchmark:delete";
    static constexpr const char* PERM_RESULTS_READ = "results:read";
    static constexpr const char* PERM_RESULTS_EXPORT = "results:export";
    static constexpr const char* PERM_ADMIN = "admin:*";
    static constexpr const char* PERM_CONFIG_READ = "config:read";
    static constexpr const char* PERM_CONFIG_WRITE = "config:write";
    
    // Role definitions
    struct Role {
        std::string name;
        std::vector<std::string> permissions;
        std::vector<std::string> inherits;
    };
    
    RBACManager() {
        // Define default roles
        roles_["viewer"] = {
            "viewer",
            {PERM_BENCHMARK_READ, PERM_RESULTS_READ},
            {}
        };
        
        roles_["operator"] = {
            "operator",
            {PERM_BENCHMARK_READ, PERM_BENCHMARK_RUN, PERM_RESULTS_READ, 
             PERM_RESULTS_EXPORT, PERM_CONFIG_READ},
            {"viewer"}
        };
        
        roles_["admin"] = {
            "admin",
            {PERM_BENCHMARK_READ, PERM_BENCHMARK_RUN, PERM_BENCHMARK_DELETE,
             PERM_RESULTS_READ, PERM_RESULTS_EXPORT, PERM_CONFIG_READ, 
             PERM_CONFIG_WRITE, PERM_ADMIN},
            {"operator"}
        };
    }
    
    // Check if role has permission
    bool HasPermission(const std::string& role_name, 
                      const std::string& permission) {
        auto perms = GetRolePermissions(role_name);
        
        // Check exact match
        if (std::find(perms.begin(), perms.end(), permission) != perms.end()) {
            return true;
        }
        
        // Check wildcard
        std::string wildcard = permission.substr(0, permission.find(':')) + ":*";
        if (std::find(perms.begin(), perms.end(), wildcard) != perms.end()) {
            return true;
        }
        
        // Check admin wildcard
        if (std::find(perms.begin(), perms.end(), PERM_ADMIN) != perms.end()) {
            return true;
        }
        
        return false;
    }
    
    // Check if role has all permissions
    bool HasPermissions(const std::string& role_name,
                        const std::vector<std::string>& permissions) {
        for (const auto& perm : permissions) {
            if (!HasPermission(role_name, perm)) {
                return false;
            }
        }
        return true;
    }
    
    // Get role permissions (including inherited)
    std::vector<std::string> GetRolePermissions(const std::string& role_name) {
        std::vector<std::string> result;
        std::set<std::string> visited;
        
        CollectPermissions(role_name, result, visited);
        
        return result;
    }
    
    // Add custom role
    void AddRole(const Role& role) {
        roles_[role.name] = role;
    }
    
    // Check resource access
    bool CheckResourceAccess(const std::string& role_name,
                             const std::string& resource,
                             const std::string& action) {
        std::string permission = resource + ":" + action;
        return HasPermission(role_name, permission);
    }

private:
    std::map<std::string, Role> roles_;
    
    void CollectPermissions(const std::string& role_name,
                           std::vector<std::string>& result,
                           std::set<std::string>& visited) {
        if (visited.count(role_name)) return;
        visited.insert(role_name);
        
        auto it = roles_.find(role_name);
        if (it == roles_.end()) return;
        
        // Add direct permissions
        for (const auto& perm : it->second.permissions) {
            if (std::find(result.begin(), result.end(), perm) == result.end()) {
                result.push_back(perm);
            }
        }
        
        // Recursively add inherited permissions
        for (const auto& parent : it->second.inherits) {
            CollectPermissions(parent, result, visited);
        }
    }
};

// Session manager
class SessionManager {
public:
    struct Session {
        std::string session_id;
        std::string user_id;
        std::string role;
        int64_t created_at;
        int64_t expires_at;
        int64_t last_activity;
        std::string ip_address;
        std::string user_agent;
    };
    
    struct Config {
        int session_timeout_minutes = 60;
        int max_sessions_per_user = 5;
        bool bind_to_ip = false;
    };
    
    explicit SessionManager(const Config& config = Config()) 
        : config_(config) {}
    
    // Create new session
    std::optional<Session> CreateSession(const std::string& user_id,
                                          const std::string& role,
                                          const std::string& ip = "",
                                          const std::string& user_agent = "") {
        // Check session limit
        if (CountUserSessions(user_id) >= config_.max_sessions_per_user) {
            // Remove oldest session
            RemoveOldestSession(user_id);
        }
        
        Session session;
        session.session_id = GenerateSessionID();
        session.user_id = user_id;
        session.role = role;
        session.created_at = GetTimestamp();
        session.expires_at = session.created_at + config_.session_timeout_minutes * 60;
        session.last_activity = session.created_at;
        session.ip_address = ip;
        session.user_agent = user_agent;
        
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_[session.session_id] = session;
        }
        
        return session;
    }
    
    // Validate session
    std::optional<Session> ValidateSession(const std::string& session_id) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return std::nullopt;
        }
        
        // Check expiry
        if (it->second.expires_at < GetTimestamp()) {
            sessions_.erase(it);
            return std::nullopt;
        }
        
        // Update activity
        it->second.last_activity = GetTimestamp();
        
        return it->second;
    }
    
    // Destroy session
    bool DestroySession(const std::string& session_id) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        return sessions_.erase(session_id) > 0;
    }
    
    // Destroy all user sessions
    int DestroyUserSessions(const std::string& user_id) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        
        int removed = 0;
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (it->second.user_id == user_id) {
                it = sessions_.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        
        return removed;
    }
    
    // Cleanup expired sessions
    int CleanupSessions() {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        
        int removed = 0;
        auto now = GetTimestamp();
        
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (it->second.expires_at < now) {
                it = sessions_.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        
        return removed;
    }

private:
    Config config_;
    std::map<std::string, Session> sessions_;
    mutable std::mutex sessions_mutex_;
    
    std::string GenerateSessionID() {
        return "sess_" + std::to_string(GetTimestamp()) + "_" + 
               std::to_string(rand());
    }
    
    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    int CountUserSessions(const std::string& user_id) {
        int count = 0;
        for (const auto& [id, session] : sessions_) {
            if (session.user_id == user_id) ++count;
        }
        return count;
    }
    
    void RemoveOldestSession(const std::string& user_id) {
        std::string oldest_id;
        int64_t oldest_time = INT64_MAX;
        
        for (const auto& [id, session] : sessions_) {
            if (session.user_id == user_id && session.created_at < oldest_time) {
                oldest_time = session.created_at;
                oldest_id = id;
            }
        }
        
        if (!oldest_id.empty()) {
            sessions_.erase(oldest_id);
        }
    }
};

} // namespace Security
} // namespace Benchmark
