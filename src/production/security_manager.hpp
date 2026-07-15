#pragma once

/**
 * @file security_manager.hpp
 * @brief Production security manager
 * @details Input validation, rate limiting, authentication, and audit logging
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <cstring>
#include <vector>
#include <memory>
#include <chrono>
#include <optional>

namespace rawrxd {
namespace production {

/**
 * @brief Security level
 */
enum class SecurityLevel {
    LOW,        // Development/testing
    MEDIUM,     // Standard production
    HIGH,       // Enhanced security
    MAXIMUM     // Maximum security
};

/**
 * @brief User credentials
 */
struct Credentials {
    std::string username;
    std::string password_hash;
    std::string api_key;
    std::vector<std::string> roles;
};

/**
 * @brief Rate limit bucket
 */
struct RateLimitBucket {
    std::string client_id;
    int tokens;
    std::chrono::steady_clock::time_point last_update;
    int max_tokens;
    std::chrono::seconds refill_rate;
};

/**
 * @brief Audit log entry
 */
struct AuditLogEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string action;
    std::string user;
    std::string resource;
    std::string result;
    std::string ip_address;
    std::string user_agent;
    std::string request_id;
};

/**
 * @brief Security manager for production hardening
 *
 * Provides:
 * - Input validation and sanitization
 * - Rate limiting with token bucket
 * - Authentication and authorization
 * - Comprehensive audit logging
 * - TLS/SSL configuration
 */
class SecurityManager {
public:
    SecurityManager();
    ~SecurityManager();

    /**
     * @brief Initialize security manager
     * @param level Security level
     * @return true if initialization successful
     */
    bool initialize(SecurityLevel level);

    /**
     * @brief Validate and sanitize input
     * @param input Raw input string
     * @param max_length Maximum allowed length
     * @return Sanitized string or nullopt if invalid
     */
    std::optional<std::string> validateInput(
        const std::string& input,
        size_t max_length = 4096
    );

    /**
     * @brief Check if input contains SQL injection patterns
     * @param input Input to check
     * @return true if suspicious patterns found
     */
    bool detectSqlInjection(const std::string& input);

    /**
     * @brief Check if input contains XSS patterns
     * @param input Input to check
     * @return true if suspicious patterns found
     */
    bool detectXss(const std::string& input);

    /**
     * @brief Check rate limit for client
     * @param client_id Client identifier
     * @param cost Request cost in tokens
     * @return true if request allowed
     */
    bool checkRateLimit(const std::string& client_id, int cost = 1);

    /**
     * @brief Configure rate limiting
     * @param max_tokens Maximum tokens in bucket
     * @param refill_rate Tokens per second
     */
    void configureRateLimit(int max_tokens, int refill_rate);

    /**
     * @brief Authenticate user
     * @param credentials User credentials
     * @return true if authentication successful
     */
    bool authenticate(const Credentials& credentials);

    /**
     * @brief Authenticate with API key
     * @param api_key API key
     * @return User ID if valid, empty string otherwise
     */
    std::string authenticateApiKey(const std::string& api_key);

    /**
     * @brief Check authorization
     * @param user User ID
     * @param resource Resource being accessed
     * @param action Action being performed
     * @return true if authorized
     */
    bool authorize(
        const std::string& user,
        const std::string& resource,
        const std::string& action
    );

    /**
     * @brief Check if user has role
     * @param user User ID
     * @param role Role to check
     * @return true if user has role
     */
    bool hasRole(const std::string& user, const std::string& role);

    /**
     * @brief Write audit log entry
     * @param entry Audit log entry
     */
    void auditLog(const AuditLogEntry& entry);

    /**
     * @brief Quick audit log helper
     * @param action Action performed
     * @param user User ID
     * @param resource Resource accessed
     * @param result Result of action
     */
    void auditLog(
        const std::string& action,
        const std::string& user,
        const std::string& resource,
        const std::string& result
    );

    /**
     * @brief Get recent audit log entries
     * @param count Number of entries to retrieve
     * @return Vector of audit log entries
     */
    std::vector<AuditLogEntry> getAuditLog(size_t count = 100);

    /**
     * @brief Hash password
     * @param password Plain text password
     * @return Hashed password
     */
    static std::string hashPassword(const std::string& password);

    /**
     * @brief Verify password
     * @param password Plain text password
     * @param hash Stored hash
     * @return true if password matches
     */
    static bool verifyPassword(const std::string& password, const std::string& hash);

    /**
     * @brief Generate secure API key
     * @return New API key
     */
    static std::string generateApiKey();

    /**
     * @brief Sanitize HTML content
     * @param html Raw HTML
     * @return Sanitized HTML
     */
    static std::string sanitizeHtml(const std::string& html);

    /**
     * @brief Escape special characters for JSON
     * @param input Raw string
     * @return JSON-escaped string
     */
    static std::string escapeJson(const std::string& input);

    /**
     * @brief Get current security level
     */
    SecurityLevel getSecurityLevel() const;

    /**
     * @brief Set security level
     * @param level New security level
     */
    void setSecurityLevel(SecurityLevel level);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief TLS/SSL configuration
 */
struct TlsConfig {
    std::string certificate_path;
    std::string private_key_path;
    std::string ca_certificate_path;
    bool verify_peer = true;
    int min_version = 3;  // TLS 1.2
};

/**
 * @brief TLS manager
 */
class TlsManager {
public:
    bool initialize(const TlsConfig& config);
    bool loadCertificate(const std::string& path);
    bool loadPrivateKey(const std::string& path);
    bool verifyCertificate(const std::string& cert);
    
    static std::string getTlsVersion();
    static std::vector<std::string> getCipherSuites();
};

} // namespace production
} // namespace rawrxd
