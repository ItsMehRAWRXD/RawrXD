// Phase U.4/5: Quantum Security Layer
// RawrXD Quantum Security Layer - Post-quantum cryptography and quantum-safe security

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Quantum {

// Post-quantum algorithm types
enum class PostQuantumAlgorithm {
    KYBER,          // Lattice-based KEM
    DILITHIUM,      // Lattice-based signature
    FALCON,         // Lattice-based signature
    SPHINCS_PLUS,   // Hash-based signature
    CLASSIC_MCELIECE, // Code-based KEM
    BIKE,           // Code-based KEM
    HQC             // Code-based KEM
};

// Quantum key
struct QuantumKey {
    std::string key_id;
    PostQuantumAlgorithm algorithm;
    
    // Key material
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    
    // Metadata
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    uint32_t key_size_bits;
    
    // Security level
    uint32_t security_level;  // 1, 3, or 5 (NIST levels)
    
    // Usage
    uint64_t encryption_count;
    uint64_t decryption_count;
    bool is_compromised;
};

// Encrypted message
struct QuantumEncryptedMessage {
    std::string message_id;
    std::string key_id;
    
    // Ciphertext
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> tag;  // Authentication tag
    
    // Additional data
    std::vector<uint8_t> associated_data;
    
    // Algorithm info
    PostQuantumAlgorithm algorithm;
    std::string symmetric_cipher;  // AES-256-GCM, ChaCha20-Poly1305
    
    // Timing
    std::chrono::system_clock::time_point encrypted_at;
};

// Digital signature
struct QuantumSignature {
    std::string signature_id;
    std::string key_id;
    
    // Signature data
    std::vector<uint8_t> signature;
    std::vector<uint8_t> message_hash;
    
    // Algorithm
    PostQuantumAlgorithm algorithm;
    
    // Verification
    bool is_verified;
    std::chrono::system_clock::time_point signed_at;
};

// Quantum random number
struct QuantumRandomNumber {
    std::vector<uint8_t> random_bytes;
    uint32_t entropy_bits;
    std::string source;  // "quantum", "hybrid", "classical"
    std::chrono::system_clock::time_point generated_at;
};

// Security policy
struct QuantumSecurityPolicy {
    std::string policy_id;
    std::string name;
    
    // Key requirements
    PostQuantumAlgorithm preferred_kem;
    PostQuantumAlgorithm preferred_signature;
    uint32_t min_security_level;
    
    // Key lifecycle
    std::chrono::days key_rotation_period;
    std::chrono::days key_expiry;
    bool auto_rotate;
    
    // Encryption settings
    std::string symmetric_algorithm;
    uint32_t symmetric_key_size;
    
    // Quantum resistance
    bool require_quantum_safe;
    bool hybrid_mode;  // Combine classical + post-quantum
    bool quantum_key_distribution;  // Use QKD if available
    
    // Compliance
    std::vector<std::string> compliance_standards;  // NIST, BSI, etc.
};

// Quantum security layer
class IQuantumSecurityLayer {
public:
    virtual ~IQuantumSecurityLayer() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Key generation
    virtual std::string GenerateKeyPair(PostQuantumAlgorithm algorithm, uint32_t security_level) = 0;
    virtual bool DeleteKey(const std::string& key_id) = 0;
    virtual std::optional<QuantumKey> GetKey(const std::string& key_id) = 0;
    virtual std::vector<QuantumKey> ListKeys() = 0;
    virtual bool RotateKey(const std::string& key_id) = 0;
    
    // Key encapsulation (KEM)
    virtual std::vector<uint8_t> EncapsulateSecret(const std::string& public_key_id,
                                                     std::vector<uint8_t>& ciphertext) = 0;
    virtual std::optional<std::vector<uint8_t>> DecapsulateSecret(
        const std::string& private_key_id,
        const std::vector<uint8_t>& ciphertext) = 0;
    
    // Encryption/Decryption
    virtual QuantumEncryptedMessage Encrypt(const std::string& key_id,
                                              const std::vector<uint8_t>& plaintext,
                                              const std::vector<uint8_t>& associated_data = {}) = 0;
    virtual std::optional<std::vector<uint8_t>> Decrypt(
        const std::string& key_id,
        const QuantumEncryptedMessage& ciphertext) = 0;
    
    // Signatures
    virtual QuantumSignature Sign(const std::string& key_id,
                                   const std::vector<uint8_t>& message) = 0;
    virtual bool Verify(const QuantumSignature& signature,
                        const std::vector<uint8_t>& message) = 0;
    
    // Random number generation
    virtual QuantumRandomNumber GenerateRandom(uint32_t num_bytes, bool use_quantum = true) = 0;
    virtual std::vector<uint8_t> GenerateSecureRandom(uint32_t num_bytes) = 0;
    
    // Hashing
    virtual std::vector<uint8_t> Hash(const std::vector<uint8_t>& data,
                                        const std::string& algorithm = "SHA3-256") = 0;
    virtual std::vector<uint8_t> Hash(const std::string& data,
                                        const std::string& algorithm = "SHA3-256") = 0;
    
    // Security policy
    virtual std::string CreateSecurityPolicy(const QuantumSecurityPolicy& policy) = 0;
    virtual bool UpdateSecurityPolicy(const QuantumSecurityPolicy& policy) = 0;
    virtual bool DeleteSecurityPolicy(const std::string& policy_id) = 0;
    virtual bool ApplySecurityPolicy(const std::string& policy_id) = 0;
    virtual std::optional<QuantumSecurityPolicy> GetSecurityPolicy(const std::string& policy_id) = 0;
    
    // Quantum key distribution (QKD)
    virtual bool IsQKDAvailable() = 0;
    virtual std::string InitiateQKDSession(const std::string& remote_party) = 0;
    virtual std::vector<uint8_t> GetQKDKey(const std::string& session_id) = 0;
    virtual void TerminateQKDSession(const std::string& session_id) = 0;
    
    // Security assessment
    virtual bool IsQuantumSafe() = 0;
    virtual std::vector<std::string> GetVulnerabilities() = 0;
    virtual std::vector<std::string> GetRecommendations() = 0;
    
    // Statistics
    virtual struct SecurityStatistics {
        uint64_t keys_generated;
        uint64_t encryptions_performed;
        uint64_t decryptions_performed;
        uint64_t signatures_created;
        uint64_t signatures_verified;
        uint64_t random_bytes_generated;
        uint32_t active_keys;
        uint32_t expired_keys;
        uint32_t compromised_keys;
        double average_encryption_time_ms;
        double average_decryption_time_ms;
    } GetStatistics() = 0;
};

// Local quantum security layer
class LocalQuantumSecurityLayer : public IQuantumSecurityLayer {
public:
    LocalQuantumSecurityLayer();
    ~LocalQuantumSecurityLayer() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string GenerateKeyPair(PostQuantumAlgorithm algorithm, uint32_t security_level) override;
    bool DeleteKey(const std::string& key_id) override;
    std::optional<QuantumKey> GetKey(const std::string& key_id) override;
    std::vector<QuantumKey> ListKeys() override;
    bool RotateKey(const std::string& key_id) override;
    
    std::vector<uint8_t> EncapsulateSecret(const std::string& public_key_id,
                                             std::vector<uint8_t>& ciphertext) override;
    std::optional<std::vector<uint8_t>> DecapsulateSecret(
        const std::string& private_key_id,
        const std::vector<uint8_t>& ciphertext) override;
    
    QuantumEncryptedMessage Encrypt(const std::string& key_id,
                                     const std::vector<uint8_t>& plaintext,
                                     const std::vector<uint8_t>& associated_data = {}) override;
    std::optional<std::vector<uint8_t>> Decrypt(
        const std::string& key_id,
        const QuantumEncryptedMessage& ciphertext) override;
    
    QuantumSignature Sign(const std::string& key_id,
                           const std::vector<uint8_t>& message) override;
    bool Verify(const QuantumSignature& signature,
                const std::vector<uint8_t>& message) override;
    
    QuantumRandomNumber GenerateRandom(uint32_t num_bytes, bool use_quantum = true) override;
    std::vector<uint8_t> GenerateSecureRandom(uint32_t num_bytes) override;
    
    std::vector<uint8_t> Hash(const std::vector<uint8_t>& data,
                                const std::string& algorithm = "SHA3-256") override;
    std::vector<uint8_t> Hash(const std::string& data,
                                const std::string& algorithm = "SHA3-256") override;
    
    std::string CreateSecurityPolicy(const QuantumSecurityPolicy& policy) override;
    bool UpdateSecurityPolicy(const QuantumSecurityPolicy& policy) override;
    bool DeleteSecurityPolicy(const std::string& policy_id) override;
    bool ApplySecurityPolicy(const std::string& policy_id) override;
    std::optional<QuantumSecurityPolicy> GetSecurityPolicy(const std::string& policy_id) override;
    
    bool IsQKDAvailable() override;
    std::string InitiateQKDSession(const std::string& remote_party) override;
    std::vector<uint8_t> GetQKDKey(const std::string& session_id) override;
    void TerminateQKDSession(const std::string& session_id) override;
    
    bool IsQuantumSafe() override;
    std::vector<std::string> GetVulnerabilities() override;
    std::vector<std::string> GetRecommendations() override;
    
    SecurityStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, QuantumKey> keys_;
    std::unordered_map<std::string, QuantumSecurityPolicy> policies_;
    std::unordered_map<std::string, std::vector<uint8_t>> qkd_sessions_;
    bool initialized_ = false;
    
    bool GenerateKyberKeyPair(QuantumKey& key, uint32_t security_level);
    bool GenerateDilithiumKeyPair(QuantumKey& key, uint32_t security_level);
    bool GenerateFalconKeyPair(QuantumKey& key, uint32_t security_level);
    bool GenerateSphincsKeyPair(QuantumKey& key, uint32_t security_level);
    
    std::vector<uint8_t> GenerateClassicalRandom(uint32_t num_bytes);
    std::vector<uint8_t> GenerateQuantumRandom(uint32_t num_bytes);
};

// Global quantum security layer
extern std::unique_ptr<IQuantumSecurityLayer> g_quantum_security_layer;

// Initialize quantum security layer
bool InitializeQuantumSecurityLayer(const std::string& config_path);
void ShutdownQuantumSecurityLayer();
bool IsQuantumSecurityLayerEnabled();

} // namespace Quantum
} // namespace RawrXD
