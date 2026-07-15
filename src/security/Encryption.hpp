/**
 * Encryption.hpp
 *
 * Phase G Batch 3/5: Encryption & Cryptography
 *
 * Comprehensive encryption layer with AES-256-GCM, ChaCha20-Poly1305,
 * RSA/ECIES key exchange, and secure key management.
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <mutex>

namespace Security {

// ============================================================================
// Secure Buffer
// ============================================================================

/**
 * Secure memory buffer that clears on destruction.
 */
class SecureBuffer {
public:
    SecureBuffer();
    explicit SecureBuffer(size_t size);
    SecureBuffer(const void* data, size_t size);
    ~SecureBuffer();
    
    // Disable copy
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // Enable move
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    
    // Access
    uint8_t* Data() { return data_.get(); }
    const uint8_t* Data() const { return data_.get(); }
    size_t Size() const { return size_; }
    bool Empty() const { return size_ == 0; }
    
    // Resize
    void Resize(size_t newSize);
    void Clear();
    
    // Comparison
    bool operator==(const SecureBuffer& other) const;
    bool operator!=(const SecureBuffer& other) const;
    
    // Base64 encoding/decoding
    std::string ToBase64() const;
    static SecureBuffer FromBase64(const std::string& base64);
    
    // Hex encoding
    std::string ToHex() const;
    static SecureBuffer FromHex(const std::string& hex);
    
private:
    std::unique_ptr<uint8_t[]> data_;
    size_t size_;
    
    void SecureZero();
};

// ============================================================================
// Key Derivation
// ============================================================================

/**
 * PBKDF2 key derivation.
 */
class KeyDerivation {
public:
    static SecureBuffer PBKDF2(const std::string& password,
                                const SecureBuffer& salt,
                                size_t keyLength,
                                uint32_t iterations = 100000);
    
    static SecureBuffer Argon2id(const std::string& password,
                                  const SecureBuffer& salt,
                                  size_t keyLength,
                                  uint32_t memoryKB = 65536,
                                  uint32_t iterations = 3,
                                  uint32_t parallelism = 4);
    
    static SecureBuffer Scrypt(const std::string& password,
                                const SecureBuffer& salt,
                                size_t keyLength,
                                uint64_t N = 16384,
                                uint32_t r = 8,
                                uint32_t p = 1);
    
    // Generate random salt
    static SecureBuffer GenerateSalt(size_t length = 32);
};

// ============================================================================
// Symmetric Encryption
// ============================================================================

enum class CipherAlgorithm {
    AES_256_GCM,
    AES_256_CBC,
    CHACHA20_POLY1305,
    XCHACHA20_POLY1305
};

struct EncryptedData {
    SecureBuffer ciphertext;
    SecureBuffer nonce;      // IV/nonce
    SecureBuffer tag;        // Authentication tag (for AEAD)
    SecureBuffer aad;        // Additional authenticated data
    CipherAlgorithm algorithm;
    
    std::string ToBase64() const;
    static EncryptedData FromBase64(const std::string& base64);
};

/**
 * Symmetric encryption engine.
 */
class SymmetricCipher {
public:
    explicit SymmetricCipher(CipherAlgorithm algo = CipherAlgorithm::AES_256_GCM);
    ~SymmetricCipher();
    
    // Key management
    void SetKey(const SecureBuffer& key);
    SecureBuffer GenerateKey() const;
    
    // Encryption/Decryption
    EncryptedData Encrypt(const SecureBuffer& plaintext,
                          const SecureBuffer& aad = SecureBuffer());
    
    SecureBuffer Decrypt(const EncryptedData& encrypted);
    
    // Stream encryption
    void InitEncryptStream(SecureBuffer& header);
    SecureBuffer EncryptChunk(const SecureBuffer& chunk, bool final = false);
    
    void InitDecryptStream(const SecureBuffer& header);
    SecureBuffer DecryptChunk(const SecureBuffer& chunk, bool final = false);
    
    // Static convenience methods
    static EncryptedData EncryptWithKey(const SecureBuffer& key,
                                         const SecureBuffer& plaintext,
                                         CipherAlgorithm algo = CipherAlgorithm::AES_256_GCM);
    
    static SecureBuffer DecryptWithKey(const SecureBuffer& key,
                                        const EncryptedData& encrypted);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    CipherAlgorithm algorithm_;
};

// ============================================================================
// Asymmetric Encryption
// ============================================================================

enum class KeyAlgorithm {
    RSA_4096,
    RSA_2048,
    ECDH_P256,
    ECDH_P384,
    ECDH_P521,
    X25519,
    X448
};

struct KeyPair {
    SecureBuffer privateKey;
    SecureBuffer publicKey;
    KeyAlgorithm algorithm;
    
    std::string ToPEM() const;
    static KeyPair FromPEM(const std::string& pem);
};

/**
 * Asymmetric encryption engine.
 */
class AsymmetricCipher {
public:
    explicit AsymmetricCipher(KeyAlgorithm algo = KeyAlgorithm::RSA_4096);
    ~AsymmetricCipher();
    
    // Key generation
    KeyPair GenerateKeyPair();
    void LoadKeyPair(const KeyPair& keyPair);
    void LoadPublicKey(const SecureBuffer& publicKey);
    
    // Encryption/Decryption
    EncryptedData Encrypt(const SecureBuffer& plaintext);
    SecureBuffer Decrypt(const EncryptedData& encrypted);
    
    // Signing/Verification
    SecureBuffer Sign(const SecureBuffer& message);
    bool Verify(const SecureBuffer& message, const SecureBuffer& signature);
    
    // Key exchange
    SecureBuffer DeriveSharedSecret(const SecureBuffer& otherPublicKey);
    
    // Static methods
    static KeyPair GenerateKeyPairStatic(KeyAlgorithm algo);
    static SecureBuffer EncryptWithPublicKey(const SecureBuffer& publicKey,
                                              const SecureBuffer& plaintext,
                                              KeyAlgorithm algo);
    static SecureBuffer DecryptWithPrivateKey(const SecureBuffer& privateKey,
                                               const SecureBuffer& ciphertext,
                                               KeyAlgorithm algo);
    static SecureBuffer SignWithPrivateKey(const SecureBuffer& privateKey,
                                            const SecureBuffer& message,
                                            KeyAlgorithm algo);
    static bool VerifyWithPublicKey(const SecureBuffer& publicKey,
                                     const SecureBuffer& message,
                                     const SecureBuffer& signature,
                                     KeyAlgorithm algo);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    KeyAlgorithm algorithm_;
};

// ============================================================================
// Hash Functions
// ============================================================================

enum class HashAlgorithm {
    SHA_256,
    SHA_384,
    SHA_512,
    SHA3_256,
    SHA3_512,
    BLAKE2b,
    BLAKE2s,
    BLAKE3
};

class Hash {
public:
    explicit Hash(HashAlgorithm algo = HashAlgorithm::SHA_256);
    ~Hash();
    
    // Incremental hashing
    void Update(const SecureBuffer& data);
    void Update(const void* data, size_t length);
    SecureBuffer Finalize();
    void Reset();
    
    // Static one-shot methods
    static SecureBuffer Compute(const SecureBuffer& data,
                                 HashAlgorithm algo = HashAlgorithm::SHA_256);
    static SecureBuffer Compute(const void* data, size_t length,
                                 HashAlgorithm algo = HashAlgorithm::SHA_256);
    static SecureBuffer Compute(const std::string& data,
                                 HashAlgorithm algo = HashAlgorithm::SHA_256);
    
    // HMAC
    static SecureBuffer HMAC(const SecureBuffer& key,
                              const SecureBuffer& data,
                              HashAlgorithm algo = HashAlgorithm::SHA_256);
    
    // HKDF
    static SecureBuffer HKDF_Extract(const SecureBuffer& salt,
                                    const SecureBuffer& ikm,
                                    HashAlgorithm algo = HashAlgorithm::SHA_256);
    static SecureBuffer HKDF_Expand(const SecureBuffer& prk,
                                     const SecureBuffer& info,
                                     size_t length,
                                     HashAlgorithm algo = HashAlgorithm::SHA_256);
    static SecureBuffer HKDF(const SecureBuffer& salt,
                            const SecureBuffer& ikm,
                            const SecureBuffer& info,
                            size_t length,
                            HashAlgorithm algo = HashAlgorithm::SHA_256);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Digital Signatures
// ============================================================================

enum class SignatureAlgorithm {
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ECDSA_P521_SHA512,
    Ed25519,
    Ed448,
    RSA_PSS_SHA256,
    RSA_PSS_SHA512
};

class Signature {
public:
    explicit Signature(SignatureAlgorithm algo = SignatureAlgorithm::Ed25519);
    ~Signature();
    
    // Key management
    KeyPair GenerateKeyPair();
    void LoadKeyPair(const KeyPair& keyPair);
    void LoadPublicKey(const SecureBuffer& publicKey);
    
    // Sign/Verify
    SecureBuffer Sign(const SecureBuffer& message);
    bool Verify(const SecureBuffer& message, const SecureBuffer& signature);
    
    // Static methods
    static KeyPair GenerateKeyPairStatic(SignatureAlgorithm algo);
    static SecureBuffer SignWithPrivateKey(const SecureBuffer& privateKey,
                                            const SecureBuffer& message,
                                            SignatureAlgorithm algo);
    static bool VerifyWithPublicKey(const SecureBuffer& publicKey,
                                     const SecureBuffer& message,
                                     const SecureBuffer& signature,
                                     SignatureAlgorithm algo);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    SignatureAlgorithm algorithm_;
};

// ============================================================================
// Certificate Management
// ============================================================================

struct Certificate {
    std::string subject;
    std::string issuer;
    SecureBuffer publicKey;
    uint64_t validFrom;
    uint64_t validUntil;
    std::vector<std::string> purposes;
    std::map<std::string, std::string> extensions;
    SecureBuffer signature;
    
    std::string ToPEM() const;
    static Certificate FromPEM(const std::string& pem);
    bool IsValid() const;
    bool IsExpired() const;
};

class CertificateManager {
public:
    CertificateManager();
    ~CertificateManager();
    
    // Certificate generation
    Certificate GenerateSelfSigned(const std::string& subject,
                                    const KeyPair& keyPair,
                                    uint64_t validityDays = 365);
    
    Certificate GenerateCertificate(const std::string& subject,
                                     const SecureBuffer& publicKey,
                                     const Certificate& issuerCert,
                                     const SecureBuffer& issuerPrivateKey,
                                     uint64_t validityDays = 365);
    
    // Certificate loading
    bool LoadCertificate(const Certificate& cert);
    bool LoadCertificatePEM(const std::string& pem);
    bool LoadTrustedCA(const Certificate& ca);
    
    // Verification
    bool VerifyCertificate(const Certificate& cert);
    bool VerifyCertificateChain(const Certificate& cert,
                                 const std::vector<Certificate>& chain);
    
    // Certificate store
    std::vector<Certificate> GetTrustedCAs() const;
    std::optional<Certificate> FindCertificate(const std::string& subject);
    void RemoveCertificate(const std::string& subject);
    
    // CRL/OCSP
    void LoadCRL(const SecureBuffer& crlData);
    bool IsRevoked(const Certificate& cert);
    
private:
    std::vector<Certificate> trustedCAs_;
    std::vector<Certificate> certificates_;
    std::vector<SecureBuffer> crlEntries_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Secure Random
// ============================================================================

class SecureRandom {
public:
    // Generate random bytes
    static SecureBuffer Generate(size_t length);
    static void Fill(void* buffer, size_t length);
    
    // Generate random values
    static uint32_t UInt32();
    static uint64_t UInt64();
    static double Double();  // [0, 1)
    
    // Generate random within range
    static uint32_t UInt32Range(uint32_t min, uint32_t max);
    static uint64_t UInt64Range(uint64_t min, uint64_t max);
    
    // Shuffle
    template<typename T>
    static void Shuffle(std::vector<T>& vec);
};

// ============================================================================
// Key Store
// ============================================================================

enum class KeyProtection {
    NONE,           // Unencrypted storage
    PASSWORD,       // Password-based encryption
    HARDWARE,       // Hardware security module
    TPM             // Trusted Platform Module
};

struct StoredKey {
    std::string id;
    std::string type;       // "symmetric", "asymmetric", "hmac"
    SecureBuffer keyData;
    KeyProtection protection;
    uint64_t createdAt;
    uint64_t expiresAt;
    std::map<std::string, std::string> metadata;
};

class KeyStore {
public:
    KeyStore();
    ~KeyStore();
    
    // Initialize
    bool Initialize(const std::string& path, KeyProtection protection);
    void Shutdown();
    
    // Key storage
    bool StoreKey(const StoredKey& key, const std::string& password = "");
    std::optional<StoredKey> LoadKey(const std::string& keyId,
                                      const std::string& password = "");
    bool DeleteKey(const std::string& keyId);
    bool KeyExists(const std::string& keyId);
    
    // Key generation and storage
    std::string GenerateAndStoreSymmetricKey(const std::string& keyId,
                                                size_t keyLength = 32,
                                                const std::string& password = "");
    std::string GenerateAndStoreKeyPair(const std::string& keyId,
                                         KeyAlgorithm algo = KeyAlgorithm::RSA_4096,
                                         const std::string& password = "");
    
    // Key listing
    std::vector<std::string> ListKeys() const;
    std::vector<std::string> ListExpiredKeys() const;
    
    // Key rotation
    bool RotateKey(const std::string& keyId, const std::string& password = "");
    
    // Backup/Restore
    bool ExportKey(const std::string& keyId, SecureBuffer& exported, const std::string& password);
    bool ImportKey(const SecureBuffer& exported, const std::string& password = "");
    
private:
    std::string path_;
    KeyProtection protection_;
    std::map<std::string, StoredKey> keys_;
    mutable std::mutex mutex_;
    
    SecureBuffer DeriveStorageKey(const std::string& password,
                                   const SecureBuffer& salt);
};

// ============================================================================
// TLS/SSL Context
// ============================================================================

struct TLSConfig {
    std::string certPath;
    std::string keyPath;
    std::string caPath;
    std::vector<std::string> cipherSuites;
    std::string minVersion = "TLSv1.3";
    bool verifyPeer = true;
    bool verifyHostname = true;
};

class TLSContext {
public:
    TLSContext();
    ~TLSContext();
    
    bool Initialize(const TLSConfig& config);
    void Shutdown();
    
    // Handshake
    bool PerformHandshake();
    
    // Encrypt/Decrypt for network
    SecureBuffer Encrypt(const SecureBuffer& plaintext);
    SecureBuffer Decrypt(const SecureBuffer& ciphertext);
    
    // Session management
    SecureBuffer ExportSession();
    bool ImportSession(const SecureBuffer& sessionData);
    
    // Certificate info
    Certificate GetPeerCertificate() const;
    bool VerifyPeer();
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Encryption Manager
// ============================================================================

/**
 * High-level encryption manager for application use.
 */
class EncryptionManager {
public:
    struct Config {
        std::string keyStorePath;
        KeyProtection keyProtection = KeyProtection::PASSWORD;
        CipherAlgorithm defaultCipher = CipherAlgorithm::AES_256_GCM;
        HashAlgorithm defaultHash = HashAlgorithm::SHA_256;
        SignatureAlgorithm defaultSignature = SignatureAlgorithm::Ed25519;
    };
    
    EncryptionManager();
    ~EncryptionManager();
    
    bool Initialize(const Config& config);
    void Shutdown();
    
    // High-level encryption
    EncryptedData EncryptData(const SecureBuffer& plaintext,
                               const std::string& keyId = "");
    SecureBuffer DecryptData(const EncryptedData& encrypted,
                              const std::string& keyId = "");
    
    // Password-based encryption
    EncryptedData EncryptWithPassword(const SecureBuffer& plaintext,
                                       const std::string& password);
    SecureBuffer DecryptWithPassword(const EncryptedData& encrypted,
                                      const std::string& password);
    
    // Signing
    SecureBuffer SignData(const SecureBuffer& data, const std::string& keyId);
    bool VerifySignature(const SecureBuffer& data,
                          const SecureBuffer& signature,
                          const SecureBuffer& publicKey);
    
    // Hashing
    SecureBuffer HashData(const SecureBuffer& data);
    SecureBuffer HashData(const std::string& data);
    
    // Key management
    std::string GenerateDataEncryptionKey();
    bool RotateEncryptionKey(const std::string& keyId);
    
    // Secure communication
    std::unique_ptr<TLSContext> CreateTLSClient(const TLSConfig& config);
    std::unique_ptr<TLSContext> CreateTLSServer(const TLSConfig& config);
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    std::unique_ptr<KeyStore> keyStore_;
    std::string defaultKeyId_;
    mutable std::mutex mutex_;
};

} // namespace Security
