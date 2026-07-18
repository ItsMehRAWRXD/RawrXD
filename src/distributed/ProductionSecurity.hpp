// Phase F: Production Security Hardening
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
namespace Sovereign {
namespace Distributed {
namespace Production {

// ============================================================================
// TLS Configuration
// ============================================================================

struct TLSConfig {
    std::string cert_path;
    std::string key_path;
    std::string ca_path;
    bool verify_peer = true;
    bool verify_hostname = true;
    std::string cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";
    int tls_version = 3; // TLS 1.3
    
    bool Validate() const {
        return !cert_path.empty() && !key_path.empty();
    }
};

// ============================================================================
// Authentication
// ============================================================================

struct NodeCredentials {
    std::string node_id;
    std::string certificate;
    std::string private_key;
    std::vector<std::string> roles;
    std::chrono::steady_clock::time_point issued_at;
    std::chrono::steady_clock::time_point expires_at;
    
    bool IsValid() const {
        auto now = std::chrono::steady_clock::now();
        return now >= issued_at && now < expires_at;
    }
};

class MutualTLSAuthenticator {
public:
    explicit MutualTLSAuthenticator(const TLSConfig& config);
    ~MutualTLSAuthenticator();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    
    // Authentication
    bool AuthenticateNode(const std::string& node_id, 
                          const std::vector<uint8_t>& certificate);
    bool VerifyCertificateChain(const std::vector<uint8_t>& cert_chain);
    
    // Certificate management
    bool LoadCertificate(const std::string& path);
    bool ReloadCertificates(); // Hot reload
    
    // Callbacks
    using AuthCallback = std::function<void(const std::string& node_id, bool success)>;
    void OnAuthentication(AuthCallback callback);
    
private:
    TLSConfig config_;
    std::unique_ptr<void, void(*)(void*)> ssl_ctx_; // SSL_CTX*
    std::mutex certs_mutex_;
    std::map<std::string, NodeCredentials> node_creds_;
    AuthCallback on_auth_;
};

// ============================================================================
// Authorization (RBAC)
// ============================================================================

enum class Permission {
    PROPOSE_CONSENSUS = 0,
    VOTE_CONSENSUS = 1,
    INITIATE_ROLLBACK = 2,
    PUBLISH_STATE = 3,
    READ_STATE = 4,
    ADMIN_CONFIG = 5,
    ADMIN_NODES = 6
};

struct Role {
    std::string name;
    std::vector<Permission> permissions;
    std::map<std::string, std::string> constraints; // Resource constraints
};

class RBACManager {
public:
    RBACManager();
    ~RBACManager();
    
    // Role management
    bool DefineRole(const Role& role);
    bool AssignRole(const std::string& node_id, const std::string& role_name);
    bool RevokeRole(const std::string& node_id, const std::string& role_name);
    
    // Permission checking
    bool HasPermission(const std::string& node_id, Permission perm);
    bool HasPermission(const std::string& node_id, Permission perm, 
                       const std::string& resource);
    
    // Query
    std::vector<std::string> GetNodeRoles(const std::string& node_id);
    std::vector<Permission> GetNodePermissions(const std::string& node_id);
    
private:
    mutable std::mutex roles_mutex_;
    std::map<std::string, Role> roles_;
    std::map<std::string, std::vector<std::string>> node_roles_;
};

// ============================================================================
// Audit Logging
// ============================================================================

enum class AuditEventType {
    AUTHENTICATION = 0,
    AUTHORIZATION = 1,
    CONSENSUS_PROPOSE = 2,
    CONSENSUS_VOTE = 3,
    CONSENSUS_COMMIT = 4,
    ROLLBACK_INITIATE = 5,
    ROLLBACK_COMPLETE = 6,
    STATE_PUBLISH = 7,
    STATE_REPLICATE = 8,
    CONFIG_CHANGE = 9,
    NODE_JOIN = 10,
    NODE_LEAVE = 11
};

struct AuditEvent {
    std::string event_id;
    AuditEventType type;
    std::string node_id;
    std::string user_id; // If applicable
    std::chrono::steady_clock::time_point timestamp;
    std::string action;
    std::string resource;
    bool success;
    std::string details; // JSON
    std::string source_ip;
    std::string session_id;
};

class AuditLogger {
public:
    struct Config {
        std::string log_path;
        size_t max_file_size_mb = 100;
        int max_files = 10;
        bool encrypt_logs = true;
        std::string encryption_key_path;
        bool async_write = true;
    };
    
    explicit AuditLogger(const Config& config);
    ~AuditLogger();
    
    bool Initialize();
    void Shutdown();
    
    // Logging
    void Log(const AuditEvent& event);
    void Log(AuditEventType type, const std::string& node_id,
             const std::string& action, bool success,
             const std::string& details = "");
    
    // Query
    std::vector<AuditEvent> Query(const std::chrono::steady_clock::time_point& start,
                                  const std::chrono::steady_clock::time_point& end);
    std::vector<AuditEvent> QueryByNode(const std::string& node_id, int count = 100);
    std::vector<AuditEvent> QueryByType(AuditEventType type, int count = 100);
    
    // Export
    bool ExportToJSON(const std::string& path, 
                      const std::chrono::steady_clock::time_point& start,
                      const std::chrono::steady_clock::time_point& end);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::unique_ptr<void, void(*)(void*)> log_file_; // File handle
    std::mutex log_mutex_;
    
    void WriteEvent(const AuditEvent& event);
    std::string SerializeEvent(const AuditEvent& event);
    void RotateLogIfNeeded();
};

// ============================================================================
// Secrets Management
// ============================================================================

class SecretsManager {
public:
    struct Config {
        std::string provider; // "vault", "aws", "azure", "gcp", "file"
        std::string address;
        std::string token_path;
        std::string role_id;
        std::string secret_id;
    };
    
    explicit SecretsManager(const Config& config);
    ~SecretsManager();
    
    bool Initialize();
    void Shutdown();
    
    // Secret operations
    std::string GetSecret(const std::string& path);
    bool SetSecret(const std::string& path, const std::string& value);
    bool DeleteSecret(const std::string& path);
    
    // Certificate operations
    std::pair<std::string, std::string> GetCertificate(const std::string& path);
    bool RotateCertificate(const std::string& path);
    
    // Encryption
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext,
                                   const std::string& key_path);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext,
                                   const std::string& key_path);
    
private:
    Config config_;
    std::unique_ptr<void, void(*)(void*)> provider_; // Provider-specific handle
    std::mutex secrets_mutex_;
    std::map<std::string, std::string> cache_;
};

// ============================================================================
// Security Manager (Facade)
// ============================================================================

class SecurityManager {
public:
    struct Config {
        TLSConfig tls;
        AuditLogger::Config audit;
        SecretsManager::Config secrets;
        bool enforce_mtls = true;
        bool audit_all_operations = true;
    };
    
    explicit SecurityManager(const Config& config);
    ~SecurityManager();
    
    bool Initialize();
    void Shutdown();
    
    // Access to subsystems
    MutualTLSAuthenticator* GetAuthenticator() { return authenticator_.get(); }
    RBACManager* GetRBAC() { return rbac_.get(); }
    AuditLogger* GetAuditLogger() { return audit_logger_.get(); }
    SecretsManager* GetSecretsManager() { return secrets_manager_.get(); }
    
    // Convenience methods
    bool AuthenticateAndAuthorize(const std::string& node_id,
                                   const std::vector<uint8_t>& certificate,
                                   Permission perm);
    void LogAuditEvent(AuditEventType type, const std::string& node_id,
                      const std::string& action, bool success,
                      const std::string& details = "");
    
private:
    Config config_;
    std::unique_ptr<MutualTLSAuthenticator> authenticator_;
    std::unique_ptr<RBACManager> rbac_;
    std::unique_ptr<AuditLogger> audit_logger_;
    std::unique_ptr<SecretsManager> secrets_manager_;
};

} // namespace Production
} // namespace Distributed
} // namespace Sovereign
