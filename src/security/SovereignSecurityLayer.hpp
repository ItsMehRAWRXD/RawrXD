// SovereignSecurityLayer.hpp
// Phase D.4 Batch 3/5 — Production Security Layer
// Authentication, authorization, and audit logging for sovereign runtime

#ifndef SOVEREIGN_SECURITY_LAYER_HPP
#define SOVEREIGN_SECURITY_LAYER_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <optional>

namespace Sovereign {

// ============================================================================
// Security Types
// ============================================================================

enum class SecurityLevel {
    NONE = 0,           // No authentication required
    BASIC = 1,          // Basic API key authentication
    STANDARD = 2,       // Token-based with permissions
    HIGH = 3,           // Multi-factor authentication
    MAXIMUM = 4         // Hardware-backed, audited
};

enum class Permission {
    // Inference permissions
    INFERENCE_READ = 0x0001,
    INFERENCE_WRITE = 0x0002,
    
    // Agent permissions
    AGENT_CREATE = 0x0004,
    AGENT_EXECUTE = 0x0008,
    AGENT_DELETE = 0x0010,
    
    // Swarm permissions
    SWARM_CREATE = 0x0020,
    SWARM_COORDINATE = 0x0040,
    
    // System permissions
    SYSTEM_CONFIG_READ = 0x0080,
    SYSTEM_CONFIG_WRITE = 0x0100,
    SYSTEM_MONITOR = 0x0200,
    SYSTEM_ADMIN = 0x0400,
    
    // Audit permissions
    AUDIT_READ = 0x0800,
    AUDIT_EXPORT = 0x1000,
    
    // All permissions
    ALL = 0xFFFF
};

enum class AuthMethod {
    NONE,
    API_KEY,
    JWT_TOKEN,
    CERTIFICATE,
    HARDWARE_TOKEN
};

// ============================================================================
// API Key Management
// ============================================================================

struct APIKey {
    std::string key_id;
    std::string hashed_key;
    std::string name;
    std::string owner;
    uint32_t permissions;
    SecurityLevel level;
    
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    std::chrono::system_clock::time_point last_used;
    uint32_t use_count;
    
    bool is_active;
    std::vector<std::string> allowed_ips;
    std::vector<std::string> allowed_origins;
    
    APIKey()
        : permissions(0)
        , level(SecurityLevel::BASIC)
        , use_count(0)
        , is_active(true)
    {}
};

class APIKeyManager {
public:
    APIKeyManager();
    ~APIKeyManager();
    
    // Key generation
    std::pair<std::string, APIKey> GenerateKey(
        const std::string& name,
        const std::string& owner,
        uint32_t permissions,
        SecurityLevel level,
        std::chrono::hours validity
    );
    
    // Key validation
    bool ValidateKey(const std::string& key);
    std::optional<APIKey> GetKeyInfo(const std::string& key_id);
    
    // Key management
    bool RevokeKey(const std::string& key_id);
    bool ActivateKey(const std::string& key_id);
    bool DeactivateKey(const std::string& key_id);
    bool UpdateKeyPermissions(const std::string& key_id, uint32_t permissions);
    
    // Key rotation
    std::pair<std::string, APIKey> RotateKey(const std::string& key_id);
    
    // Listing
    std::vector<APIKey> ListKeys(const std::string& owner = "");
    std::vector<APIKey> ListExpiredKeys();
    
    // Cleanup
    size_t CleanupExpiredKeys();
    
    // Persistence
    bool SaveToFile(const std::string& path);
    bool LoadFromFile(const std::string& path);
    
private:
    std::map<std::string, APIKey> keys_;
    mutable std::mutex keys_mutex_;
    
    std::string GenerateSecureKey();
    std::string HashKey(const std::string& key);
    bool IsKeyExpired(const APIKey& key) const;
};

// ============================================================================
// Permission System
// ============================================================================

class PermissionManager {
public:
    PermissionManager();
    ~PermissionManager();
    
    // Permission checking
    static bool HasPermission(uint32_t granted, Permission required);
    static bool HasAnyPermission(uint32_t granted, uint32_t required);
    static bool HasAllPermissions(uint32_t granted, uint32_t required);
    
    // Permission manipulation
    static uint32_t GrantPermission(uint32_t current, Permission permission);
    static uint32_t RevokePermission(uint32_t current, Permission permission);
    static uint32_t GrantAll();
    static uint32_t RevokeAll();
    
    // Permission strings
    static std::string PermissionToString(Permission perm);
    static std::optional<Permission> StringToPermission(const std::string& str);
    static std::vector<std::string> PermissionsToStrings(uint32_t perms);
    static uint32_t StringsToPermissions(const std::vector<std::string>& strs);
    
    // Role-based permissions
    static uint32_t GetRolePermissions(const std::string& role);
    static std::vector<std::string> GetAvailableRoles();
    
    // Validation
    static bool ValidatePermissionCombination(uint32_t perms);
};

// ============================================================================
// Authentication
// ============================================================================

struct AuthContext {
    std::string principal;           // User/API key ID
    uint32_t permissions;
    SecurityLevel level;
    AuthMethod method;
    std::string session_id;
    std::chrono::system_clock::time_point authenticated_at;
    std::chrono::system_clock::time_point expires_at;
    std::map<std::string, std::string> claims;
    
    AuthContext()
        : permissions(0)
        , level(SecurityLevel::NONE)
        , method(AuthMethod::NONE)
    {}
    
    bool IsExpired() const {
        return std::chrono::system_clock::now() > expires_at;
    }
    
    bool HasPermission(Permission perm) const {
        return PermissionManager::HasPermission(permissions, perm);
    }
};

class Authenticator {
public:
    Authenticator();
    ~Authenticator();
    
    // Initialize with API key manager
    void Initialize(std::shared_ptr<APIKeyManager> key_manager);
    
    // Authentication methods
    std::optional<AuthContext> AuthenticateAPIKey(const std::string& key);
    std::optional<AuthContext> AuthenticateJWT(const std::string& token);
    std::optional<AuthContext> AuthenticateCertificate(const std::string& cert);
    
    // Session management
    std::string CreateSession(const AuthContext& ctx);
    std::optional<AuthContext> ValidateSession(const std::string& session_id);
    bool TerminateSession(const std::string& session_id);
    void TerminateAllSessions();
    
    // Token generation
    std::string GenerateJWT(const AuthContext& ctx, std::chrono::hours validity);
    
    // Rate limiting
    bool CheckRateLimit(const std::string& principal, uint32_t max_requests_per_minute);
    void ResetRateLimit(const std::string& principal);
    
private:
    std::shared_ptr<APIKeyManager> key_manager_;
    std::map<std::string, AuthContext> sessions_;
    mutable std::mutex sessions_mutex_;
    
    struct RateLimitInfo {
        uint32_t request_count;
        std::chrono::system_clock::time_point window_start;
    };
    std::map<std::string, RateLimitInfo> rate_limits_;
    mutable std::mutex rate_limits_mutex_;
    
    std::string GenerateSessionID();
};

// ============================================================================
// Audit Logging
// ============================================================================

enum class AuditEventType {
    AUTHENTICATION_SUCCESS,
    AUTHENTICATION_FAILURE,
    AUTHORIZATION_DENIED,
    KEY_CREATED,
    KEY_REVOKED,
    KEY_ROTATED,
    PERMISSION_CHANGED,
    SESSION_CREATED,
    SESSION_TERMINATED,
    CONFIG_CHANGED,
    SYSTEM_STARTUP,
    SYSTEM_SHUTDOWN,
    SECURITY_ALERT
};

struct AuditEvent {
    std::string event_id;
    AuditEventType type;
    std::string principal;
    std::string action;
    std::string resource;
    std::string details;
    std::string ip_address;
    std::string user_agent;
    std::chrono::system_clock::time_point timestamp;
    uint32_t severity;
    bool success;
    
    AuditEvent()
        : severity(0)
        , success(true)
    {}
};

class AuditLogger {
public:
    AuditLogger();
    ~AuditLogger();
    
    // Initialization
    void Initialize(const std::string& log_path, size_t max_file_size_mb = 100);
    void SetMinSeverity(uint32_t severity);
    
    // Logging
    void Log(const AuditEvent& event);
    void LogAuthSuccess(const std::string& principal, const std::string& method);
    void LogAuthFailure(const std::string& principal, const std::string& reason);
    void LogAuthorizationDenied(const std::string& principal, 
                                 const std::string& action,
                                 const std::string& resource);
    void LogKeyEvent(const std::string& principal, 
                     const std::string& key_id,
                     AuditEventType type);
    void LogSecurityAlert(const std::string& description, uint32_t severity);
    
    // Querying
    std::vector<AuditEvent> Query(
        std::optional<AuditEventType> type = std::nullopt,
        std::optional<std::string> principal = std::nullopt,
        std::optional<std::chrono::system_clock::time_point> start = std::nullopt,
        std::optional<std::chrono::system_clock::time_point> end = std::nullopt,
        size_t limit = 1000
    );
    
    // Export
    bool ExportToFile(const std::string& path, 
                      std::optional<std::chrono::system_clock::time_point> start = std::nullopt,
                      std::optional<std::chrono::system_clock::time_point> end = std::nullopt);
    
    // Maintenance
    bool RotateLog();
    size_t CleanupOldEntries(std::chrono::days retention);
    
    // Statistics
    struct AuditStats {
        size_t total_events;
        size_t auth_success;
        size_t auth_failures;
        size_t auth_denials;
        size_t security_alerts;
        std::chrono::system_clock::time_point oldest_entry;
        std::chrono::system_clock::time_point newest_entry;
    };
    AuditStats GetStatistics() const;
    
private:
    std::string log_path_;
    size_t max_file_size_mb_;
    uint32_t min_severity_;
    mutable std::mutex log_mutex_;
    
    std::vector<AuditEvent> events_;
    
    std::string EventTypeToString(AuditEventType type) const;
    std::string FormatEvent(const AuditEvent& event) const;
    void WriteToFile(const AuditEvent& event);
};

// ============================================================================
// Security Policy
// ============================================================================

struct SecurityPolicy {
    SecurityLevel minimum_level;
    bool require_https;
    bool require_mfa_for_admin;
    uint32_t max_failed_attempts;
    std::chrono::minutes lockout_duration;
    std::chrono::hours session_timeout;
    std::chrono::hours key_rotation_interval;
    bool audit_all_requests;
    bool ip_whitelist_enabled;
    std::vector<std::string> allowed_ips;
    
    SecurityPolicy()
        : minimum_level(SecurityLevel::BASIC)
        , require_https(true)
        , require_mfa_for_admin(false)
        , max_failed_attempts(5)
        , lockout_duration(std::chrono::minutes(30))
        , session_timeout(std::chrono::hours(8))
        , key_rotation_interval(std::chrono::hours(720)) // 30 days
        , audit_all_requests(true)
        , ip_whitelist_enabled(false)
    {}
};

class SecurityPolicyManager {
public:
    SecurityPolicyManager();
    ~SecurityPolicyManager();
    
    // Policy management
    void SetPolicy(const SecurityPolicy& policy);
    SecurityPolicy GetPolicy() const;
    
    // Policy enforcement helpers
    bool CheckSecurityLevel(SecurityLevel level) const;
    bool CheckIPAllowed(const std::string& ip) const;
    bool ShouldRotateKey(const APIKey& key) const;
    
    // Persistence
    bool SaveToFile(const std::string& path);
    bool LoadFromFile(const std::string& path);
    
private:
    SecurityPolicy policy_;
    mutable std::mutex policy_mutex_;
};

// ============================================================================
// Main Security Layer
// ============================================================================

class SovereignSecurityLayer {
public:
    static SovereignSecurityLayer& GetInstance();
    
    // Initialization
    void Initialize(const std::string& config_path = "");
    void Shutdown();
    bool IsInitialized() const;
    
    // Component access
    APIKeyManager& GetKeyManager();
    Authenticator& GetAuthenticator();
    AuditLogger& GetAuditLogger();
    PermissionManager& GetPermissionManager();
    SecurityPolicyManager& GetPolicyManager();
    
    // High-level operations
    std::optional<AuthContext> Authenticate(const std::string& credential, 
                                            AuthMethod method);
    bool Authorize(const AuthContext& ctx, Permission permission);
    bool AuthorizeResource(const AuthContext& ctx, 
                           Permission permission,
                           const std::string& resource);
    
    // Security checks
    bool ValidateRequest(const std::string& credential,
                         const std::string& ip_address,
                         const std::string& user_agent);
    
    // Convenience methods
    bool IsAuthenticated(const std::string& session_id);
    std::optional<AuthContext> GetSessionContext(const std::string& session_id);
    
    // Status
    struct SecurityStatus {
        bool initialized;
        size_t active_keys;
        size_t active_sessions;
        size_t total_audit_events;
        SecurityLevel current_level;
        std::chrono::system_clock::time_point last_audit_time;
    };
    SecurityStatus GetStatus() const;
    
private:
    SovereignSecurityLayer();
    ~SovereignSecurityLayer();
    
    SovereignSecurityLayer(const SovereignSecurityLayer&) = delete;
    SovereignSecurityLayer& operator=(const SovereignSecurityLayer&) = delete;
    
    std::unique_ptr<APIKeyManager> key_manager_;
    std::unique_ptr<Authenticator> authenticator_;
    std::unique_ptr<AuditLogger> audit_logger_;
    std::unique_ptr<PermissionManager> permission_manager_;
    std::unique_ptr<SecurityPolicyManager> policy_manager_;
    
    bool initialized_;
    mutable std::mutex init_mutex_;
};

// ============================================================================
// Security Exceptions
// ============================================================================

class SecurityException : public std::exception {
public:
    explicit SecurityException(const std::string& message);
    const char* what() const noexcept override;
    
private:
    std::string message_;
};

class AuthenticationException : public SecurityException {
public:
    explicit AuthenticationException(const std::string& message);
};

class AuthorizationException : public SecurityException {
public:
    explicit AuthorizationException(const std::string& message);
};

class RateLimitException : public SecurityException {
public:
    explicit RateLimitException(const std::string& message);
};

} // namespace Sovereign

#endif // SOVEREIGN_SECURITY_LAYER_HPP
