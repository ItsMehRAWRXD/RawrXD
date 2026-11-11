// Phase D.7 Batch 2/5: Secrets Management
// Vault Integration and Dynamic Secrets
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>

namespace Sovereign {
namespace Security {

// ============================================================================
// Secret Types
// ============================================================================

enum class SecretType {
    STATIC = 0,
    DYNAMIC = 1,
    ROTATING = 2,
    ENCRYPTED = 3,
    CERTIFICATE = 4
};

enum class SecretEngine {
    KV = 0,
    DATABASE = 1,
    AWS = 2,
    AZURE = 3,
    GCP = 4,
    PKI = 5,
    SSH = 6,
    TRANSIT = 7
};

struct SecretMetadata {
    std::string secret_id;
    std::string path;
    SecretType type;
    SecretEngine engine;
    int version = 1;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::chrono::steady_clock::time_point expires_at;
    std::string created_by;
    std::vector<std::string> tags;
    std::map<std::string, std::string> custom_metadata;
    bool deletion_allowed = false;
};

struct SecretValue {
    std::map<std::string, std::string> data;
    SecretMetadata metadata;
    std::string lease_id;
    std::chrono::seconds lease_duration{0};
    bool renewable = false;
};

// ============================================================================
// Vault Client
// ============================================================================

class VaultClient {
public:
    struct Config {
        std::string vault_address;
        std::string vault_namespace;
        std::string auth_method;  // "token", "kubernetes", "aws", "approle"
        std::string credentials_path;
        int retry_attempts = 3;
        int retry_delay_ms = 1000;
        bool verify_ssl = true;
        std::string ca_cert_path;
    };
    
    explicit VaultClient(const Config& config);
    ~VaultClient();
    
    bool Initialize();
    void Shutdown();
    
    // Authentication
    bool Authenticate();
    bool RenewToken();
    bool IsAuthenticated() const;
    std::chrono::steady_clock::time_point GetTokenExpiry() const;
    
    // KV Secrets
    SecretValue GetSecret(const std::string& path, int version = 0);
    bool PutSecret(const std::string& path, const std::map<std::string, std::string>& data);
    bool DeleteSecret(const std::string& path);
    bool UndeleteSecret(const std::string& path, const std::vector<int>& versions);
    bool DestroySecret(const std::string& path, const std::vector<int>& versions);
    std::vector<int> ListVersions(const std::string& path);
    
    // Dynamic Secrets
    SecretValue GenerateDynamicCredentials(const std::string& role);
    bool RevokeLease(const std::string& lease_id);
    bool RenewLease(const std::string& lease_id);
    
    // Transit Encryption
    std::string Encrypt(const std::string& key_name, const std::string& plaintext);
    std::string Decrypt(const std::string& key_name, const std::string& ciphertext);
    std::string Sign(const std::string& key_name, const std::string& data);
    bool Verify(const std::string& key_name, const std::string& data, const std::string& signature);
    
    // PKI
    struct CertificateRequest {
        std::string common_name;
        std::vector<std::string> alt_names;
        std::string ip_sans;
        std::string ttl;
    };
    
    struct CertificateResponse {
        std::string certificate;
        std::string issuing_ca;
        std::string ca_chain;
        std::string private_key;
        std::string serial_number;
    };
    
    CertificateResponse IssueCertificate(const std::string& role, const CertificateRequest& request);
    bool RevokeCertificate(const std::string& serial_number);
    
private:
    Config config_;
    std::string token_;
    std::chrono::steady_clock::time_point token_expiry_;
    
    bool AuthenticateWithToken();
    bool AuthenticateWithKubernetes();
    bool AuthenticateWithAWS();
    bool AuthenticateWithAppRole();
    
    std::string MakeRequest(const std::string& method, const std::string& path, const std::string& body = "");
};

// ============================================================================
// Secret Cache
// ============================================================================

class SecretCache {
public:
    struct Config {
        int max_size = 1000;
        int default_ttl_seconds = 300;
        bool encrypt_cache = true;
        std::string encryption_key_path;
    };
    
    explicit SecretCache(const Config& config);
    
    bool Initialize();
    
    // Cache operations
    bool Put(const std::string& key, const SecretValue& secret);
    std::optional<SecretValue> Get(const std::string& key);
    bool Invalidate(const std::string& key);
    bool InvalidatePrefix(const std::string& prefix);
    void Clear();
    
    // Statistics
    struct Stats {
        int hits = 0;
        int misses = 0;
        int evictions = 0;
        int size = 0;
        double hit_ratio = 0.0;
    };
    
    Stats GetStats() const;
    
private:
    Config config_;
    
    struct CacheEntry {
        SecretValue secret;
        std::chrono::steady_clock::time_point expires_at;
    };
    
    mutable std::mutex cache_mutex_;
    std::map<std::string, CacheEntry> cache_;
    
    std::atomic<int> hits_{0};
    std::atomic<int> misses_{0};
    std::atomic<int> evictions_{0};
    
    void EvictIfNeeded();
    void CleanupExpired();
};

// ============================================================================
// Rotation Manager
// ============================================================================

class RotationManager {
public:
    struct Config {
        int check_interval_minutes = 60;
        int rotation_buffer_hours = 24;
        bool auto_rotate = true;
        int max_rotation_attempts = 3;
    };
    
    struct RotationPolicy {
        std::string policy_id;
        std::string secret_path;
        int rotation_interval_days = 90;
        std::string rotation_strategy;  // "automatic", "manual", "on_demand"
        std::vector<std::string> notification_channels;
        bool require_approval = false;
        std::string custom_rotation_script;
    };
    
    struct RotationEvent {
        std::string event_id;
        std::string policy_id;
        std::string secret_path;
        int old_version = 0;
        int new_version = 0;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
        bool successful = false;
        std::string error_message;
    };
    
    explicit RotationManager(const Config& config);
    ~RotationManager();
    
    bool Initialize(VaultClient* vault);
    void Shutdown();
    
    // Policy management
    bool CreatePolicy(const RotationPolicy& policy);
    bool UpdatePolicy(const std::string& policy_id, const RotationPolicy& policy);
    bool DeletePolicy(const std::string& policy_id);
    RotationPolicy GetPolicy(const std::string& policy_id) const;
    std::vector<RotationPolicy> GetPolicies() const;
    
    // Rotation operations
    std::string TriggerRotation(const std::string& policy_id);
    bool CancelRotation(const std::string& event_id);
    bool ApproveRotation(const std::string& event_id, const std::string& approved_by);
    RotationEvent GetRotationStatus(const std::string& event_id) const;
    
    // History
    std::vector<RotationEvent> GetRotationHistory(const std::string& secret_path, int limit = 100) const;
    
    // Manual rotation
    bool RotateDatabaseCredentials(const std::string& role);
    bool RotateAPIKey(const std::string& path);
    bool RotateCertificate(const std::string& role);
    
private:
    Config config_;
    VaultClient* vault_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread rotation_thread_;
    
    mutable std::mutex policies_mutex_;
    std::map<std::string, RotationPolicy> policies_;
    
    mutable std::mutex events_mutex_;
    std::map<std::string, RotationEvent> events_;
    
    void RotationLoop();
    bool ExecuteRotation(const RotationPolicy& policy, RotationEvent& event);
    bool RotateViaVault(const RotationPolicy& policy);
    bool RotateViaScript(const RotationPolicy& policy);
    std::vector<std::string> GetSecretsNeedingRotation();
};

// ============================================================================
// Secret Watcher
// ============================================================================

class SecretWatcher {
public:
    struct Config {
        int poll_interval_seconds = 30;
        bool enable_events = true;
    };
    
    using SecretChangeCallback = std::function<void(const std::string& path, const SecretValue& new_value)>;
    
    explicit SecretWatcher(const Config& config);
    ~SecretWatcher();
    
    bool Initialize(VaultClient* vault);
    void Shutdown();
    
    // Watch operations
    bool Watch(const std::string& path, SecretChangeCallback callback);
    bool Unwatch(const std::string& path);
    bool IsWatching(const std::string& path) const;
    std::vector<std::string> GetWatchedPaths() const;
    
private:
    Config config_;
    VaultClient* vault_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread watch_thread_;
    
    mutable std::mutex watches_mutex_;
    std::map<std::string, SecretChangeCallback> watches_;
    std::map<std::string, SecretValue> last_known_values_;
    
    void WatchLoop();
    void CheckForChanges();
};

// ============================================================================
// Secrets Runtime
// ============================================================================

class SecretsRuntime {
public:
    struct Config {
        VaultClient::Config vault;
        SecretCache::Config cache;
        RotationManager::Config rotation;
        SecretWatcher::Config watcher;
    };
    
    explicit SecretsRuntime(const Config& config);
    ~SecretsRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // High-level API
    std::string GetSecretValue(const std::string& path, const std::string& key);
    std::map<std::string, std::string> GetSecretData(const std::string& path);
    bool PutSecret(const std::string& path, const std::map<std::string, std::string>& data);
    
    // Dynamic secrets
    std::map<std::string, std::string> GetDatabaseCredentials(const std::string& role);
    std::map<std::string, std::string> GetCloudCredentials(const std::string& role);
    
    // Encryption
    std::string Encrypt(const std::string& key_name, const std::string& plaintext);
    std::string Decrypt(const std::string& key_name, const std::string& ciphertext);
    
    // Certificate management
    std::string GetCertificate(const std::string& role, const std::string& common_name);
    
    // Watch for changes
    bool WatchSecret(const std::string& path, std::function<void()> callback);
    bool UnwatchSecret(const std::string& path);
    
    // Access subsystems
    VaultClient* GetVaultClient();
    SecretCache* GetCache();
    RotationManager* GetRotationManager();
    SecretWatcher* GetWatcher();
    
private:
    Config config_;
    std::unique_ptr<VaultClient> vault_;
    std::unique_ptr<SecretCache> cache_;
    std::unique_ptr<RotationManager> rotation_;
    std::unique_ptr<SecretWatcher> watcher_;
};

} // namespace Security
} // namespace Sovereign
