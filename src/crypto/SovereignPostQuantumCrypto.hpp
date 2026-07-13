// Phase D.15 Batch 1/5: Post-Quantum Cryptography
// Quantum-resistant algorithms (ML-KEM, ML-DSA, SLH-DSA)
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Crypto {

// Forward declarations
struct PQCKeyPair;
struct PQCSignature;
struct PQCCiphertext;

// ============================================================================
// Post-Quantum Algorithm Types
// ============================================================================

enum class PQCAlgorithm {
    // NIST FIPS 203: ML-KEM (Kyber)
    ML_KEM_512 = 0,
    ML_KEM_768 = 1,
    ML_KEM_1024 = 2,
    
    // NIST FIPS 204: ML-DSA (Dilithium)
    ML_DSA_44 = 10,
    ML_DSA_65 = 11,
    ML_DSA_87 = 12,
    
    // NIST FIPS 205: SLH-DSA (SPHINCS+)
    SLH_DSA_SHA2_128S = 20,
    SLH_DSA_SHA2_128F = 21,
    SLH_DSA_SHA2_256S = 22,
    SLH_DSA_SHA2_256F = 23,
    SLH_DSA_SHAKE_128S = 24,
    SLH_DSA_SHAKE_256S = 25,
    
    // Hybrid (PQC + Classical)
    HYBRID_KEM_X25519_ML_KEM_768 = 100,
    HYBRID_SIG_ECDSA_ML_DSA_65 = 101
};

enum class PQCSecurityLevel {
    LEVEL_1 = 128,   // AES-128 equivalent
    LEVEL_3 = 192,   // AES-192 equivalent
    LEVEL_5 = 256    // AES-256 equivalent
};

struct PQCKeyPair {
    PQCAlgorithm algorithm;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
    PQCSecurityLevel security_level;
    std::chrono::steady_clock::time_point created_at;
    std::map<std::string, std::any> metadata;
};

struct PQCSignature {
    PQCAlgorithm algorithm;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> message_hash;
    std::string context;
    std::chrono::steady_clock::time_point timestamp;
};

struct PQCCiphertext {
    PQCAlgorithm algorithm;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> shared_secret;
    std::chrono::steady_clock::time_point timestamp;
};

// ============================================================================
// ML-KEM (Kyber) Key Encapsulation
// ============================================================================

class MLKEM {
public:
    struct Config {
        PQCAlgorithm variant = PQCAlgorithm::ML_KEM_768;
        bool use_hybrid = false;
        std::string classical_kem = "X25519";  // For hybrid mode
    };
    
    explicit MLKEM(const Config& config);
    ~MLKEM();
    
    bool Initialize();
    void Shutdown();
    
    // Key generation
    PQCKeyPair GenerateKeyPair();
    PQCKeyPair GenerateKeyPairDeterministic(const std::vector<uint8_t>& seed);
    
    // Encapsulation
    PQCCiphertext Encapsulate(const std::vector<uint8_t>& public_key);
    std::vector<uint8_t> Decapsulate(const PQCCiphertext& ciphertext,
                                      const std::vector<uint8_t>& secret_key);
    
    // Hybrid operations
    PQCCiphertext HybridEncapsulate(const std::vector<uint8_t>& pq_public_key,
                                     const std::vector<uint8_t>& classical_public_key);
    std::vector<uint8_t> HybridDecapsulate(const PQCCiphertext& pq_ciphertext,
                                            const std::vector<uint8_t>& classical_ciphertext,
                                            const std::vector<uint8_t>& pq_secret_key,
                                            const std::vector<uint8_t>& classical_secret_key);
    
    // Key serialization
    std::vector<uint8_t> SerializePublicKey(const std::vector<uint8_t>& public_key);
    std::vector<uint8_t> DeserializePublicKey(const std::vector<uint8_t>& serialized);
    std::vector<uint8_t> SerializeSecretKey(const std::vector<uint8_t>& secret_key);
    
    // Sizes
    size_t GetPublicKeySize() const;
    size_t GetSecretKeySize() const;
    size_t GetCiphertextSize() const;
    size_t GetSharedSecretSize() const;
    
private:
    Config config_;
    void* kem_context_;
    
    size_t GetVariantPublicKeySize(PQCAlgorithm variant) const;
    size_t GetVariantSecretKeySize(PQCAlgorithm variant) const;
    size_t GetVariantCiphertextSize(PQCAlgorithm variant) const;
};

// ============================================================================
// ML-DSA (Dilithium) Digital Signatures
// ============================================================================

class MLDSA {
public:
    struct Config {
        PQCAlgorithm variant = PQCAlgorithm::ML_DSA_65;
        bool use_hybrid = false;
        std::string classical_sig = "ECDSA_P256";  // For hybrid mode
        bool deterministic = false;
    };
    
    explicit MLDSA(const Config& config);
    ~MLDSA();
    
    bool Initialize();
    void Shutdown();
    
    // Key generation
    PQCKeyPair GenerateKeyPair();
    PQCKeyPair GenerateKeyPairDeterministic(const std::vector<uint8_t>& seed);
    
    // Signing
    PQCSignature Sign(const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& secret_key,
                      const std::string& context = "");
    PQCSignature SignDeterministic(const std::vector<uint8_t>& message,
                                    const std::vector<uint8_t>& secret_key,
                                    const std::vector<uint8_t>& randomness,
                                    const std::string& context = "");
    
    // Verification
    bool Verify(const std::vector<uint8_t>& message,
                const PQCSignature& signature,
                const std::vector<uint8_t>& public_key);
    bool VerifyWithContext(const std::vector<uint8_t>& message,
                            const PQCSignature& signature,
                            const std::vector<uint8_t>& public_key,
                            const std::string& context);
    
    // Hybrid signatures
    PQCSignature HybridSign(const std::vector<uint8_t>& message,
                            const std::vector<uint8_t>& pq_secret_key,
                            const std::vector<uint8_t>& classical_secret_key);
    bool HybridVerify(const std::vector<uint8_t>& message,
                      const PQCSignature& signature,
                      const std::vector<uint8_t>& pq_public_key,
                      const std::vector<uint8_t>& classical_public_key);
    
    // Pre-hashed signing
    PQCSignature SignHash(const std::vector<uint8_t>& message_hash,
                          const std::vector<uint8_t>& secret_key,
                          const std::string& hash_algorithm = "SHA3-256");
    bool VerifyHash(const std::vector<uint8_t>& message_hash,
                    const PQCSignature& signature,
                    const std::vector<uint8_t>& public_key,
                    const std::string& hash_algorithm = "SHA3-256");
    
    // Sizes
    size_t GetPublicKeySize() const;
    size_t GetSecretKeySize() const;
    size_t GetSignatureSize() const;
    
private:
    Config config_;
    void* sig_context_;
    
    size_t GetVariantPublicKeySize(PQCAlgorithm variant) const;
    size_t GetVariantSecretKeySize(PQCAlgorithm variant) const;
    size_t GetVariantSignatureSize(PQCAlgorithm variant) const;
};

// ============================================================================
// SLH-DSA (SPHINCS+) Stateless Hash Signatures
// ============================================================================

class SLHDSA {
public:
    struct Config {
        PQCAlgorithm variant = PQCAlgorithm::SLH_DSA_SHA2_128S;
        bool robust = true;  // robust vs simple variant
    };
    
    explicit SLHDSA(const Config& config);
    ~SLHDSA();
    
    bool Initialize();
    void Shutdown();
    
    // Key generation
    PQCKeyPair GenerateKeyPair();
    
    // Signing (stateless - no state management needed)
    PQCSignature Sign(const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& secret_key);
    
    // Verification
    bool Verify(const std::vector<uint8_t>& message,
                const PQCSignature& signature,
                const std::vector<uint8_t>& public_key);
    
    // Sizes (SLH-DSA signatures are large)
    size_t GetPublicKeySize() const;
    size_t GetSecretKeySize() const;
    size_t GetSignatureSize() const;
    
    // Trade-off info
    struct TradeOffInfo {
        size_t signature_size;
        int sign_time_ms;
        int verify_time_ms;
        bool fast_signing;  // S variants
        bool small_signatures;  // S variants
    };
    TradeOffInfo GetTradeOffInfo() const;
    
private:
    Config config_;
    void* sphincs_context_;
};

// ============================================================================
// PQC Algorithm Selector
// ============================================================================

class PQCAlgorithmSelector {
public:
    struct SelectionCriteria {
        PQCSecurityLevel min_security_level = PQCSecurityLevel::LEVEL_3;
        size_t max_signature_size = 0;  // 0 = no limit
        size_t max_ciphertext_size = 0;
        int max_latency_ms = 0;
        bool require_fips_certified = true;
        bool prefer_small_signatures = false;
        bool prefer_fast_signing = false;
    };
    
    struct AlgorithmRecommendation {
        PQCAlgorithm kem_algorithm;
        PQCAlgorithm sig_algorithm;
        std::string rationale;
        PQCSecurityLevel achieved_security;
        size_t estimated_bandwidth;
        int estimated_latency_ms;
    };
    
    explicit PQCAlgorithmSelector();
    
    // Selection
    AlgorithmRecommendation SelectAlgorithms(const SelectionCriteria& criteria);
    std::vector<AlgorithmRecommendation> GetAllOptions(const SelectionCriteria& criteria);
    
    // Comparison
    struct AlgorithmComparison {
        PQCAlgorithm algorithm;
        PQCSecurityLevel security_level;
        size_t public_key_size;
        size_t secret_key_size;
        size_t ciphertext_or_sig_size;
        int keygen_time_ms;
        int encaps_sign_time_ms;
        int decaps_verify_time_ms;
        bool is_nist_certified;
    };
    std::vector<AlgorithmComparison> CompareKEMs();
    std::vector<AlgorithmComparison> CompareSignatures();
    
    // Migration helpers
    bool IsAlgorithmDeprecated(PQCAlgorithm algorithm) const;
    std::vector<PQCAlgorithm> GetRecommendedUpgrades(PQCAlgorithm current) const;
    
private:
    std::map<PQCAlgorithm, AlgorithmComparison> kem_catalog_;
    std::map<PQCAlgorithm, AlgorithmComparison> sig_catalog_;
};

// ============================================================================
// PQC Crypto Provider
// ============================================================================

class PQCCryptoProvider {
public:
    struct Config {
        PQCAlgorithm default_kem = PQCAlgorithm::ML_KEM_768;
        PQCAlgorithm default_sig = PQCAlgorithm::ML_DSA_65;
        bool enable_hybrid = true;
        bool auto_rotate_keys = true;
        std::chrono::days key_rotation_interval{90};
    };
    
    explicit PQCCryptoProvider(const Config& config);
    ~PQCCryptoProvider();
    
    bool Initialize();
    void Shutdown();
    
    // Algorithm access
    MLKEM* GetMLKEM();
    MLDSA* GetMLDSA();
    SLHDSA* GetSLHDSA();
    PQCAlgorithmSelector* GetSelector();
    
    // High-level API
    PQCKeyPair GenerateKEMKeyPair(PQCAlgorithm algorithm = PQCAlgorithm::ML_KEM_768);
    PQCKeyPair GenerateSignatureKeyPair(PQCAlgorithm algorithm = PQCAlgorithm::ML_DSA_65);
    
    PQCCiphertext Encapsulate(const std::vector<uint8_t>& public_key,
                             PQCAlgorithm algorithm = PQCAlgorithm::ML_KEM_768);
    std::vector<uint8_t> Decapsulate(const PQCCiphertext& ciphertext,
                                      const std::vector<uint8_t>& secret_key,
                                      PQCAlgorithm algorithm = PQCAlgorithm::ML_KEM_768);
    
    PQCSignature Sign(const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& secret_key,
                      PQCAlgorithm algorithm = PQCAlgorithm::ML_DSA_65);
    bool Verify(const std::vector<uint8_t>& message,
                const PQCSignature& signature,
                const std::vector<uint8_t>& public_key,
                PQCAlgorithm algorithm = PQCAlgorithm::ML_DSA_65);
    
    // Key management
    bool RotateKeys(const std::string& key_id);
    std::chrono::steady_clock::time_point GetKeyExpiry(const std::string& key_id) const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<MLKEM> ml_kem_;
    std::unique_ptr<MLDSA> ml_dsa_;
    std::unique_ptr<SLHDSA> slh_dsa_;
    std::unique_ptr<PQCAlgorithmSelector> selector_;
    
    std::map<std::string, std::pair<PQCKeyPair, std::chrono::steady_clock::time_point>> key_store_;
    mutable std::mutex key_store_mutex_;
};

} // namespace Crypto
} // namespace Sovereign
