#pragma once
/**
 * @file security_manager.hpp
 * @brief Security management for RawrXD Benchmark Suite
 * @copyright 2026 RawrXD Team
 */

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <map>

namespace rawrxd {
namespace security {

/**
 * @brief Security levels
 */
enum class SecurityLevel {
    NONE = 0,       ///< No security
    BASIC = 1,      ///< Basic authentication
    STANDARD = 2,   ///< Standard encryption + auth
    HIGH = 3,       ///< High security with MFA
    MAXIMUM = 4     ///< Maximum security with full audit
};

/**
 * @brief Authentication methods
 */
enum class AuthMethod {
    NONE,
    API_KEY,
    JWT,
    OAUTH2,
    CERTIFICATE,
    MFA
};

/**
 * @brief User roles
 */
enum class UserRole {
    VIEWER,         ///< Read-only access
    OPERATOR,       ///< Can run benchmarks
    ADMIN,          ///< Full administrative access
    AUDITOR         ///< Audit and compliance access
};

/**
 * @brief User information
 */
struct User {
    std::string id;
    std::string username;
    std::string email;
    UserRole role;
    std::vector<std::string> permissions;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_login;
    bool active;
    std::map<std::string, std::string> metadata;
};

/**
 * @brief Authentication token
 */
struct AuthToken {
    std::string token;
    std::string user_id;
    std::vector<std::string> scopes;
    std::chrono::system_clock::time_point issued_at;
    std::chrono::system_clock::time_point expires_at;
    std::string issuer;
    std::string audience;
};

/**
 * @brief Permission definition
 */
struct Permission {
    std::string resource;
    std::string action;
    std::string description;
};

/**
 * @brief Security policy
 */
struct SecurityPolicy {
    SecurityLevel level;
    bool require_encryption;
    bool require_authentication;
    bool require_audit_logging;
    int max_session_duration_minutes;
    int max_failed_login_attempts;
    int lockout_duration_minutes;
    std::vector<std::string> allowed_ips;
    std::vector<std::string> blocked_ips;
    std::map<std::string, std::string> custom_rules;
};

/**
 * @brief Authentication provider interface
 */
class IAuthProvider {
public:
    virtual ~IAuthProvider() = default;
    
    /**
     * @brief Authenticate user with credentials
     */
    virtual bool Authenticate(
        const std::string& username,
        const std::string& credential,
        AuthToken& out_token
    ) = 0;
    
    /**
     * @brief Validate authentication token
     */
    virtual bool ValidateToken(const AuthToken& token) = 0;
    
    /**
     * @brief Refresh authentication token
     */
    virtual bool RefreshToken(AuthToken& token) = 0;
    
    /**
     * @brief Revoke authentication token
     */
    virtual void RevokeToken(const std::string& token) = 0;
    
    /**
     * @brief Get user by ID
     */
    virtual std::optional<User> GetUser(const std::string& user_id) = 0;
    
    /**
     * @brief Check if user has permission
     */
    virtual bool HasPermission(
        const User& user,
        const std::string& resource,
        const std::string& action
    ) = 0;
};

/**
 * @brief API Key authentication provider
 */
class ApiKeyAuthProvider : public IAuthProvider {
public:
    ApiKeyAuthProvider();
    ~ApiKeyAuthProvider() override;
    
    void AddApiKey(
        const std::string& api_key,
        const User& user,
        const std::vector<std::string>& scopes
    );
    
    void RemoveApiKey(const std::string& api_key);
    
    bool Authenticate(
        const std::string& username,
        const std::string& credential,
        AuthToken& out_token
    ) override;
    
    bool ValidateToken(const AuthToken& token) override;
    bool RefreshToken(AuthToken& token) override;
    void RevokeToken(const std::string& token) override;
    std::optional<User> GetUser(const std::string& user_id) override;
    bool HasPermission(
        const User& user,
        const std::string& resource,
        const std::string& action
    ) override;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief JWT authentication provider
 */
class JwtAuthProvider : public IAuthProvider {
public:
    JwtAuthProvider(const std::string& secret_key);
    ~JwtAuthProvider() override;
    
    bool Authenticate(
        const std::string& username,
        const std::string& credential,
        AuthToken& out_token
    ) override;
    
    bool ValidateToken(const AuthToken& token) override;
    bool RefreshToken(AuthToken& token) override;
    void RevokeToken(const std::string& token) override;
    std::optional<User> GetUser(const std::string& user_id) override;
    bool HasPermission(
        const User& user,
        const std::string& resource,
        const std::string& action
    ) override;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief Security manager
 */
class SecurityManager {
public:
    SecurityManager();
    ~SecurityManager();
    
    /**
     * @brief Initialize security manager
     */
    bool Initialize(const SecurityPolicy& policy);
    
    /**
     * @brief Shutdown security manager
     */
    void Shutdown();
    
    /**
     * @brief Set authentication provider
     */
    void SetAuthProvider(std::shared_ptr<IAuthProvider> provider);
    
    /**
     * @brief Authenticate request
     */
    bool Authenticate(
        const std::string& auth_header,
        AuthToken& out_token
    );
    
    /**
     * @brief Authorize request
     */
    bool Authorize(
        const AuthToken& token,
        const std::string& resource,
        const std::string& action
    );
    
    /**
     * @brief Check if IP is allowed
     */
    bool IsIpAllowed(const std::string& ip_address);
    
    /**
     * @brief Record failed login attempt
     */
    void RecordFailedLogin(const std::string& username, const std::string& ip);
    
    /**
     * @brief Check if account is locked
     */
    bool IsAccountLocked(const std::string& username);
    
    /**
     * @brief Get current security policy
     */
    SecurityPolicy GetPolicy() const;
    
    /**
     * @brief Update security policy
     */
    void UpdatePolicy(const SecurityPolicy& policy);
    
    /**
     * @brief Get security level
     */
    SecurityLevel GetSecurityLevel() const;
    
    /**
     * @brief Generate secure random token
     */
    static std::string GenerateSecureToken(size_t length = 32);
    
    /**
     * @brief Hash password securely
     */
    static std::string HashPassword(const std::string& password);
    
    /**
     * @brief Verify password hash
     */
    static bool VerifyPassword(
        const std::string& password,
        const std::string& hash
    );
    
    /**
     * @brief Encrypt data
     */
    static std::string Encrypt(
        const std::string& data,
        const std::string& key
    );
    
    /**
     * @brief Decrypt data
     */
    static std::string Decrypt(
        const std::string& encrypted,
        const std::string& key
    );
    
    /**
     * @brief Get singleton instance
     */
    static SecurityManager& Instance();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief Security middleware for HTTP requests
 */
class SecurityMiddleware {
public:
    SecurityMiddleware();
    ~SecurityMiddleware();
    
    /**
     * @brief Process incoming request
     */
    bool ProcessRequest(
        const std::map<std::string, std::string>& headers,
        const std::string& client_ip,
        std::string& out_error
    );
    
    /**
     * @brief Add security headers to response
     */
    void AddSecurityHeaders(std::map<std::string, std::string>& headers);
    
    /**
     * @brief Validate request body
     */
    bool ValidateBody(
        const std::string& body,
        size_t max_size,
        std::string& out_error
    );
    
    /**
     * @brief Rate limit check
     */
    bool CheckRateLimit(
        const std::string& client_id,
        int max_requests,
        int window_seconds
    );

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief Permission constants
 */
namespace Permissions {
    constexpr const char* BENCHMARK_RUN = "benchmark:run";
    constexpr const char* BENCHMARK_VIEW = "benchmark:view";
    constexpr const char* BENCHMARK_DELETE = "benchmark:delete";
    constexpr const char* CONFIG_READ = "config:read";
    constexpr const char* CONFIG_WRITE = "config:write";
    constexpr const char* ADMIN_USERS = "admin:users";
    constexpr const char* ADMIN_AUDIT = "admin:audit";
    constexpr const char* ADMIN_SYSTEM = "admin:system";
}

} // namespace security
} // namespace rawrxd
