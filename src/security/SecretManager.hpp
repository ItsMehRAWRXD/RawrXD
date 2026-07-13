// RawrXD Secret Manager
// Phase Q.4: Secure credential and secret management
// HashiCorp Vault-compatible API with automatic rotation

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Security {

// Forward declarations
class EncryptionManager;
class AuditLogger;

// Secret types
enum class SecretType {
    GENERIC,        // Generic key-value
    API_KEY,        // API key
    PASSWORD,       // Password
    CERTIFICATE,    // TLS certificate
    SSH_KEY,        // SSH key pair
    DATABASE,       // Database credentials
    OAUTH_TOKEN,    // OAuth token
    JWT_SIGNING,    // JWT signing key
    ENCRYPTION_KEY, // Encryption key
    HMAC_KEY        // HMAC key
};

// Secret metadata
struct SecretMetadata {
    std::string path;           // Path like "secret/api/production"
    SecretType type;
    std::string description;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    std::chrono::system_clock::time_point expiresAt;
    std::chrono::system_clock::time_point lastRotatedAt;
    uint32_t version;
    uint32_t rotationCount;
    bool isActive;
    
    // Access control
    std::vector<std::string> allowedRoles;
    std::vector<std::string> allowedEntities;
    
    // Tags
    std::map<std::string, std::string> tags;
    
    // Custom metadata
    std::map<std::string, std::string> customData;
};

// Secret data
struct Secret {
    SecretMetadata metadata;
    std::map<std::string, std::string> data;  // Key-value pairs
    std::vector<uint8_t> binaryData;          // For binary secrets
};

// Secret version
struct SecretVersion {
    uint32_t version;
    std::chrono::system_clock::time_point createdAt;
    bool isDestroyed;
    std::map<std::string, std::string> data;
};

// Rotation policy
struct RotationPolicy {
    bool enabled = false;
    uint32_t rotationIntervalDays = 90;  // Default 90 days
    uint32_t autoRotateBeforeExpiryDays = 7;
    bool notifyBeforeRotation = true;
    uint32_t notifyDaysBefore = 7;
    
    // Custom rotation logic
    std::function<std::map<std::string, std::string>(const std::map<std::string, std::string>&)> rotationFunction;
};

// Lease/ttl for dynamic secrets
struct Lease {
    std::string id;
    std::string secretPath;
    std::string entityId;
    std::chrono::system_clock::time_point issuedAt;
    std::chrono::system_clock::time_point expiresAt;
    bool isRenewable;
    uint32_t ttlSeconds;
    uint32_t maxTtlSeconds;
    
    // Lease-specific data
    std::map<std::string, std::string> data;
};

// Secret engine configuration
struct SecretEngineConfig {
    std::string type;  // "kv", "database", "aws", "pki", "transit"
    std::string path;  // Mount path like "secret/" or "database/"
    std::map<std::string, std::string> config;
    bool isActive;
};

// Secret manager configuration
struct SecretManagerConfig {
    // Storage
    std::string storageBackend = "file";  // file, database, consul, etcd
    std::string storagePath = "/var/lib/rawrxd/secrets";
    
    // Encryption
    bool sealOnStartup = true;
    uint32_t unsealThreshold = 3;  // Shamir secret sharing threshold
    uint32_t unsealShares = 5;     // Total unseal shares
    
    // High availability
    bool enableHA = false;
    std::string leaderAddress;
    
    // Performance
    uint32_t cacheSize = 10000;
    uint32_t cacheTTLSeconds = 300;
    
    // Audit
    bool auditAllOperations = true;
};

// Secret manager
class SecretManager {
public:
    SecretManager(EncryptionManager* encryption, AuditLogger* audit);
    ~SecretManager();
    
    // Lifecycle
    bool initialize(const SecretManagerConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    bool isSealed() const { return sealed_; }
    
    // Seal/Unseal (Shamir secret sharing)
    std::vector<std::string> generateUnsealKeys();
    bool unseal(const std::vector<std::string>& keys);
    bool seal();
    
    // Secret CRUD
    bool createSecret(const std::string& path, const Secret& secret);
    bool updateSecret(const std::string& path, const Secret& secret);
    Secret readSecret(const std::string& path);
    Secret readSecretVersion(const std::string& path, uint32_t version);
    bool deleteSecret(const std::string& path);
    bool destroySecretVersion(const std::string& path, uint32_t version);
    bool undeleteSecretVersion(const std::string& path, uint32_t version);
    
    // Secret metadata
    SecretMetadata getSecretMetadata(const std::string& path);
    std::vector<SecretVersion> listSecretVersions(const std::string& path);
    std::vector<std::string> listSecrets(const std::string& path);
    
    // Patch operations
    bool patchSecret(const std::string& path, const std::map<std::string, std::string>& updates);
    
    // Rotation
    bool setRotationPolicy(const std::string& path, const RotationPolicy& policy);
    RotationPolicy getRotationPolicy(const std::string& path);
    bool rotateSecret(const std::string& path);
    bool rotateSecretNow(const std::string& path);
    std::vector<std::string> getSecretsNeedingRotation(uint32_t days = 7) const;
    
    // Leases (for dynamic secrets)
    Lease createLease(const std::string& secretPath, const std::string& entityId,
                      uint32_t ttlSeconds);
    Lease renewLease(const std::string& leaseId, uint32_t incrementSeconds);
    bool revokeLease(const std::string& leaseId);
    bool revokePrefix(const std::string& prefix);
    Lease getLease(const std::string& leaseId);
    std::vector<Lease> listLeases(const std::string& prefix);
    
    // Secret engines
    bool mountEngine(const std::string& path, const SecretEngineConfig& config);
    bool unmountEngine(const std::string& path);
    std::vector<SecretEngineConfig> listEngines();
    
    // Database secrets (dynamic credentials)
    Secret generateDatabaseCredentials(const std::string& role,
                                        const std::string& database);
    bool revokeDatabaseCredentials(const std::string& leaseId);
    
    // PKI secrets
    struct CertificateRequest {
        std::string commonName;
        std::vector<std::string> altNames;
        std::vector<std::string> ipSans;
        uint32_t ttlDays;
    };
    struct CertificateResponse {
        std::string certificate;
        std::string privateKey;
        std::string caChain;
        std::string serialNumber;
    };
    CertificateResponse generateCertificate(const std::string& role,
                                               const CertificateRequest& request);
    bool revokeCertificate(const std::string& serialNumber);
    
    // Transit encryption (encryption as a service)
    std::vector<uint8_t> encryptTransit(const std::string& keyName,
                                           const std::vector<uint8_t>& plaintext,
                                           const std::string& context);
    std::vector<uint8_t> decryptTransit(const std::string& keyName,
                                           const std::vector<uint8_t>& ciphertext,
                                           const std::string& context);
    std::string signTransit(const std::string& keyName,
                           const std::vector<uint8_t>& data);
    bool verifyTransit(const std::string& keyName,
                      const std::vector<uint8_t>& data,
                      const std::string& signature);
    bool rotateTransitKey(const std::string& keyName);
    
    // AWS secrets (dynamic credentials)
    Secret generateAWSCredentials(const std::string& role,
                                 const std::string& iamPolicy);
    bool revokeAWSCredentials(const std::string& leaseId);
    
    // Statistics
    struct SecretStats {
        uint64_t totalSecrets;
        uint64_t activeSecrets;
        uint64_t destroyedSecrets;
        uint64_t totalVersions;
        uint64_t activeLeases;
        uint64_t totalRotations;
        uint64_t encryptionOperations;
        uint64_t decryptionOperations;
        uint64_t storageUsed;
    };
    SecretStats getStats() const;
    
    // Health
    bool isHealthy() const;
    std::map<std::string, std::string> getHealthStatus() const;
    
    // Configuration
    SecretManagerConfig getConfig() const { return config_; }
    bool updateConfig(const SecretManagerConfig& config);

private:
    void rotationLoop();
    void leaseCleanupLoop();
    std::string generateSecretId();
    std::string generateLeaseId();
    bool checkAccess(const std::string& path, const std::string& entityId);
    void persistSecret(const std::string& path, const Secret& secret);
    Secret loadSecret(const std::string& path);
    
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::atomic<bool> sealed_;
    std::thread rotationThread_;
    std::thread leaseThread_;
    mutable std::mutex mutex_;
    
    SecretManagerConfig config_;
    EncryptionManager* encryption_;
    AuditLogger* audit_;
    
    // Data stores
    std::map<std::string, Secret> secrets_;
    std::map<std::string, RotationPolicy> rotationPolicies_;
    std::map<std::string, Lease> leases_;
    std::map<std::string, SecretEngineConfig> engines_;
    
    // Cache
    struct CacheEntry {
        Secret secret;
        std::chrono::steady_clock::time_point expiry;
    };
    std::map<std::string, CacheEntry> cache_;
    
    // Statistics
    std::atomic<uint64_t> totalRotations_{0};
    std::atomic<uint64_t> encryptionOps_{0};
    std::atomic<uint64_t> decryptionOps_{0};
};

// Secret generator utilities
class SecretGenerator {
public:
    // Password generation
    static std::string generatePassword(uint32_t length = 32,
                                       bool includeUpper = true,
                                       bool includeLower = true,
                                       bool includeDigits = true,
                                       bool includeSpecial = true);
    
    // API key generation
    static std::string generateApiKey(const std::string& prefix = "",
                                      uint32_t length = 32);
    
    // SSH key generation
    struct SSHKeyPair {
        std::string privateKey;
        std::string publicKey;
        std::string fingerprint;
    };
    static SSHKeyPair generateSSHKeyPair(const std::string& comment = "");
    
    // Certificate generation
    struct TLSConfig {
        std::string commonName;
        std::vector<std::string> altNames;
        uint32_t validityDays;
        std::string keyAlgorithm = "RSA";
        uint32_t keySize = 2048;
    };
    struct TLSCertificate {
        std::string certificate;
        std::string privateKey;
        std::string csr;
    };
    static TLSCertificate generateSelfSignedCert(const TLSConfig& config);
    static TLSCertificate generateCSR(const TLSConfig& config);
    
    // Database credential generation
    struct DBCredentials {
        std::string username;
        std::string password;
        std::string connectionString;
    };
    static DBCredentials generateDBCredentials(const std::string& database,
                                                const std::string& role);
};

} // namespace Security
} // namespace RawrXD
