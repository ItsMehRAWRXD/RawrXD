// RawrXD Encryption Manager
// Phase Q.1: Data encryption at rest and in transit
// AES-256-GCM, ChaCha20-Poly1305, TLS 1.3 support

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <map>
#include <chrono>

namespace RawrXD {
namespace Security {

// Encryption algorithms
enum class EncryptionAlgorithm {
    AES_256_GCM,        // AES-256-GCM (hardware accelerated)
    AES_128_GCM,        // AES-128-GCM
    CHACHA20_POLY1305,  // ChaCha20-Poly1305 (software optimized)
    XCHACHA20_POLY1305  // XChaCha20-Poly1305 (extended nonce)
};

// Key types
enum class KeyType {
    DATA_ENCRYPTION,    // For data at rest
    TRANSPORT,          // For TLS/transport
    MODEL_PROTECTION,   // For model weights
    CREDENTIAL,         // For credential storage
    SESSION             // For session encryption
};

// Key metadata
struct KeyMetadata {
    std::string id;
    KeyType type;
    EncryptionAlgorithm algorithm;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;
    std::chrono::system_clock::time_point lastRotatedAt;
    uint32_t rotationCount;
    bool isActive;
    std::map<std::string, std::string> tags;
};

// Encrypted data container
struct EncryptedData {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> tag;  // Authentication tag
    std::string keyId;
    EncryptionAlgorithm algorithm;
    uint64_t version;
};

// TLS configuration
struct TLSConfig {
    uint16_t minVersion = 0x0304;  // TLS 1.3
    std::vector<std::string> cipherSuites = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256"
    };
    std::string certificatePath;
    std::string privateKeyPath;
    std::string caCertificatePath;
    bool verifyClient = false;
    bool ocspStapling = true;
    uint32_t sessionTimeoutMinutes = 120;
};

// Forward declarations
class KeyManagementService;
class SecureEnclave;

// Encryption manager
class EncryptionManager {
public:
    EncryptionManager();
    ~EncryptionManager();
    
    // Lifecycle
    bool initialize(const std::string& masterKeyPath);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Key operations
    std::string generateKey(KeyType type, EncryptionAlgorithm algorithm);
    bool rotateKey(const std::string& keyId);
    bool revokeKey(const std::string& keyId);
    bool activateKey(const std::string& keyId);
    bool deactivateKey(const std::string& keyId);
    
    // Key queries
    KeyMetadata getKeyMetadata(const std::string& keyId) const;
    std::vector<KeyMetadata> getKeysByType(KeyType type) const;
    std::vector<KeyMetadata> getAllKeys() const;
    std::vector<KeyMetadata> getExpiringKeys(uint32_t days) const;
    
    // Encryption/decryption
    EncryptedData encrypt(const std::vector<uint8_t>& plaintext,
                          const std::string& keyId);
    EncryptedData encrypt(const std::string& plaintext,
                          const std::string& keyId);
    
    std::vector<uint8_t> decrypt(const EncryptedData& encrypted);
    std::string decryptToString(const EncryptedData& encrypted);
    
    // Streaming encryption for large data
    class StreamingEncryptor {
    public:
        bool initialize(const std::string& keyId, EncryptionAlgorithm algo);
        std::vector<uint8_t> processChunk(const std::vector<uint8_t>& chunk, bool isLast);
        EncryptedData finalize();
        
    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
    
    // TLS operations
    bool configureTLS(const TLSConfig& config);
    bool reloadCertificates();
    TLSConfig getTLSConfig() const { return tlsConfig_; }
    
    // Secure random
    std::vector<uint8_t> generateSecureRandom(size_t length);
    std::string generateSecureToken(size_t length = 32);
    
    // Hashing
    std::vector<uint8_t> hashSHA256(const std::vector<uint8_t>& data);
    std::vector<uint8_t> hashSHA256(const std::string& data);
    std::string hashPassword(const std::string& password, const std::vector<uint8_t>& salt);
    bool verifyPassword(const std::string& password, const std::string& hash);
    
    // Key derivation
    std::vector<uint8_t> deriveKey(const std::string& password,
                                   const std::vector<uint8_t>& salt,
                                   size_t keyLength,
                                   uint32_t iterations = 100000);
    
    // HMAC
    std::vector<uint8_t> hmacSHA256(const std::vector<uint8_t>& data,
                                    const std::vector<uint8_t>& key);
    bool verifyHMAC(const std::vector<uint8_t>& data,
                    const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& expected);
    
    // Statistics
    struct EncryptionStats {
        uint64_t bytesEncrypted;
        uint64_t bytesDecrypted;
        uint64_t encryptionOps;
        uint64_t decryptionOps;
        uint64_t failedOps;
        double avgEncryptionTimeMs;
        double avgDecryptionTimeMs;
    };
    EncryptionStats getStats() const;
    
    // Compliance
    bool FIPSModeEnabled() const { return fipsMode_; }
    void enableFIPSMode(bool enable);
    
private:
    void keyRotationLoop();
    bool loadMasterKey(const std::string& path);
    bool saveMasterKey(const std::string& path);
    
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread rotationThread_;
    mutable std::mutex mutex_;
    
    std::map<std::string, std::vector<uint8_t>> keys_;
    std::map<std::string, KeyMetadata> keyMetadata_;
    
    std::vector<uint8_t> masterKey_;
    TLSConfig tlsConfig_;
    bool fipsMode_ = false;
    
    // Statistics
    std::atomic<uint64_t> bytesEncrypted_{0};
    std::atomic<uint64_t> bytesDecrypted_{0};
    std::atomic<uint64_t> encryptionOps_{0};
    std::atomic<uint64_t> decryptionOps_{0};
    std::atomic<uint64_t> failedOps_{0};
};

// Secure memory
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size);
    ~SecureBuffer();
    
    // Disable copy
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // Enable move
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    
    uint8_t* data() { return data_; }
    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }
    
    void zero();
    bool isZero() const;
    
private:
    uint8_t* data_;
    size_t size_;
    bool mlocked_;
};

// Hardware security module interface
class HSMInterface {
public:
    virtual ~HSMInterface() = default;
    
    virtual bool connect(const std::string& config) = 0;
    virtual void disconnect() = 0;
    virtual bool isConnected() const = 0;
    
    virtual std::string generateKeyHSM(KeyType type, EncryptionAlgorithm algo) = 0;
    virtual EncryptedData encryptHSM(const std::vector<uint8_t>& plaintext,
                                     const std::string& keyId) = 0;
    virtual std::vector<uint8_t> decryptHSM(const EncryptedData& encrypted) = 0;
    virtual bool signHSM(const std::vector<uint8_t>& data,
                         const std::string& keyId,
                         std::vector<uint8_t>& signature) = 0;
    virtual bool verifyHSM(const std::vector<uint8_t>& data,
                           const std::vector<uint8_t>& signature,
                           const std::string& keyId) = 0;
};

} // namespace Security
} // namespace RawrXD
