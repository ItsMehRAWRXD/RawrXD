// Phase D.15 Batch 4/5: Quantum-Safe Key Exchange
// Advanced key exchange protocols with post-quantum security
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
struct QSKeyExchangeSession;
struct QSSharedSecret;

// ============================================================================
// Quantum-Safe Key Exchange Types
// ============================================================================

enum class QSKEMechanism {
    // NIST standardized KEMs
    ML_KEM_512 = 0,
    ML_KEM_768 = 1,
    ML_KEM_1024 = 2,
    
    // Hybrid mechanisms
    X25519_ML_KEM_768 = 100,
    X448_ML_KEM_1024 = 101,
    P256_ML_KEM_768 = 102,
    P384_ML_KEM_1024 = 103,
    
    // Pre-shared key hybrids
    PSK_ML_KEM_768 = 200,
    PSK_X25519_ML_KEM_768 = 201
};

enum class QSKERole {
    INITIATOR = 0,
    RESPONDER = 1
};

enum class QSKESessionState {
    INITIAL = 0,
    KEYPAIR_GENERATED = 1,
    ENCAPSULATION_SENT = 2,
    DECAPSULATION_RECEIVED = 3,
    SHARED_SECRET_DERIVED = 4,
    COMPLETE = 5,
    FAILED = 6
};

struct QSPublicKey {
    QSKEMechanism mechanism;
    std::vector<uint8_t> pq_public_key;
    std::vector<uint8_t> classical_public_key;  // For hybrid
    std::vector<uint8_t> identity_key;          // For authenticated KEM
    std::chrono::steady_clock::time_point generated_at;
    int validity_days = 365;
};

struct QSSecretKey {
    QSKEMechanism mechanism;
    std::vector<uint8_t> pq_secret_key;
    std::vector<uint8_t> classical_secret_key;  // For hybrid
    std::vector<uint8_t> identity_secret_key;   // For authenticated KEM
    std::chrono::steady_clock::time_point generated_at;
};

struct QSCiphertext {
    QSKEMechanism mechanism;
    std::vector<uint8_t> pq_ciphertext;
    std::vector<uint8_t> classical_ciphertext;  // For hybrid
    std::vector<uint8_t> nonce;
    std::chrono::steady_clock::time_point generated_at;
};

struct QSSharedSecret {
    QSKEMechanism mechanism;
    std::vector<uint8_t> secret;
    int security_bits;
    bool is_hybrid;
    std::chrono::steady_clock::time_point derived_at;
    std::map<std::string, std::any> metadata;
};

struct QSKESession {
    std::string session_id;
    QSKERole role;
    QSKESessionState state;
    QSKEMechanism mechanism;
    QSPublicKey public_key;
    QSSecretKey secret_key;
    QSCiphertext ciphertext;
    QSSharedSecret shared_secret;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point completed_at;
    std::map<std::string, std::any> context;
};

// ============================================================================
// Quantum-Safe KEM Engine
// ============================================================================

class QSKEMEngine {
public:
    struct Config {
        QSKEMechanism default_mechanism = QSKEMechanism::ML_KEM_768;
        bool enable_hybrid = true;
        bool enable_pre_shared_key = false;
        int key_rotation_interval_days = 90;
    };
    
    explicit QSKEMEngine(const Config& config);
    ~QSKEMEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Key generation
    std::pair<QSPublicKey, QSSecretKey> GenerateKeyPair(QSKEMechanism mechanism);
    std::pair<QSPublicKey, QSSecretKey> GenerateKeyPairDeterministic(
        QSKEMechanism mechanism, const std::vector<uint8_t>& seed);
    
    // Encapsulation
    std::pair<QSCiphertext, QSSharedSecret> Encapsulate(
        const QSPublicKey& public_key);
    
    // Decapsulation
    QSSharedSecret Decapsulate(const QSCiphertext& ciphertext,
                               const QSSecretKey& secret_key);
    
    // Hybrid operations
    std::pair<QSCiphertext, QSSharedSecret> HybridEncapsulate(
        const QSPublicKey& pq_public_key,
        const std::vector<uint8_t>& classical_public_key);
    QSSharedSecret HybridDecapsulate(
        const QSCiphertext& pq_ciphertext,
        const std::vector<uint8_t>& classical_ciphertext,
        const QSSecretKey& pq_secret_key,
        const std::vector<uint8_t>& classical_secret_key);
    
    // PSK hybrid
    std::pair<QSCiphertext, QSSharedSecret> PSKHybridEncapsulate(
        const QSPublicKey& public_key,
        const std::vector<uint8_t>& pre_shared_key);
    QSSharedSecret PSKHybridDecapsulate(
        const QSCiphertext& ciphertext,
        const QSSecretKey& secret_key,
        const std::vector<uint8_t>& pre_shared_key);
    
    // Key derivation
    std::vector<uint8_t> DeriveSessionKeys(const QSSharedSecret& shared_secret,
                                           const std::string& context);
    std::vector<uint8_t> DeriveApplicationKey(const QSSharedSecret& shared_secret,
                                               const std::string& purpose);
    
    // Validation
    bool ValidatePublicKey(const QSPublicKey& public_key);
    bool ValidateCiphertext(const QSCiphertext& ciphertext);
    bool ValidateSharedSecret(const QSSharedSecret& secret);
    
    // Sizes
    struct MechanismSizes {
        size_t public_key_size;
        size_t secret_key_size;
        size_t ciphertext_size;
        size_t shared_secret_size;
    };
    MechanismSizes GetSizes(QSKEMechanism mechanism) const;
    
    // Security level
    int GetSecurityLevel(QSKEMechanism mechanism) const;
    
private:
    Config config_;
    std::map<QSKEMechanism, MechanismSizes> size_cache_;
    
    std::vector<uint8_t> CombineSecrets(const std::vector<uint8_t>& pq_secret,
                                       const std::vector<uint8_t>& classical_secret);
    std::vector<uint8_t> HKDF(const std::vector<uint8_t>& ikm,
                             const std::vector<uint8_t>& salt,
                             const std::string& info,
                             size_t length);
};

// ============================================================================
// Authenticated KEM
// ============================================================================

class AuthenticatedKEM {
public:
    struct Config {
        bool mutual_authentication = true;
        QSKEMechanism kem_mechanism = QSKEMechanism::ML_KEM_768;
        std::string signature_algorithm = "ML_DSA_65";
        int challenge_timeout_ms = 30000;
    };
    
    struct AuthCredentials {
        std::string identity;
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> private_key;
        std::vector<uint8_t> certificate;
    };
    
    explicit AuthenticatedKEM(const Config& config);
    ~AuthenticatedKEM();
    
    bool Initialize();
    void Shutdown();
    
    // Initiator side
    struct AuthInitRequest {
        QSPublicKey kem_public_key;
        std::vector<uint8_t> identity;
        std::vector<uint8_t> signature;
        std::vector<uint8_t> timestamp;
    };
    AuthInitRequest CreateAuthInitRequest(const AuthCredentials& credentials);
    
    struct AuthInitResponse {
        QSCiphertext ciphertext;
        std::vector<uint8_t> identity;
        std::vector<uint8_t> signature;
        bool mutual_auth_complete;
    };
    AuthInitResponse ProcessAuthInitResponse(const AuthInitResponse& response,
                                             const QSSecretKey& secret_key,
                                             const AuthCredentials& credentials);
    
    // Responder side
    bool VerifyAuthInitRequest(const AuthInitRequest& request,
                               const std::vector<uint8_t>& expected_identity);
    AuthInitResponse CreateAuthInitResponse(const AuthInitRequest& request,
                                           const AuthCredentials& credentials,
                                           QSKEMEngine* kem_engine);
    
    // Final verification
    bool VerifyMutualAuth(const AuthInitResponse& response,
                         const AuthCredentials& peer_credentials);
    
private:
    Config config_;
    
    std::vector<uint8_t> SignChallenge(const std::vector<uint8_t>& challenge,
                                      const std::vector<uint8_t>& private_key);
    bool VerifyChallenge(const std::vector<uint8_t>& challenge,
                        const std::vector<uint8_t>& signature,
                        const std::vector<uint8_t>& public_key);
    std::vector<uint8_t> GenerateChallenge();
};

// ============================================================================
// Quantum-Safe Key Exchange Protocol
// ============================================================================

class QSKeyExchangeProtocol {
public:
    struct Config {
        std::vector<QSKEMechanism> supported_mechanisms = {
            QSKEMechanism::ML_KEM_768,
            QSKEMechanism::X25519_ML_KEM_768
        };
        QSKEMechanism preferred_mechanism = QSKEMechanism::ML_KEM_768;
        bool require_mutual_auth = false;
        int handshake_timeout_ms = 30000;
        int max_retries = 3;
    };
    
    enum class ProtocolState {
        IDLE = 0,
        HELLO_SENT = 1,
        HELLO_RECEIVED = 2,
        KEY_EXCHANGE_SENT = 3,
        KEY_EXCHANGE_RECEIVED = 4,
        COMPLETE = 5,
        FAILED = 6
    };
    
    explicit QSKeyExchangeProtocol(const Config& config);
    ~QSKeyExchangeProtocol();
    
    bool Initialize(QSKERole role);
    void Shutdown();
    
    // Protocol messages
    struct HelloMessage {
        uint16_t version;
        std::vector<QSKEMechanism> supported_mechanisms;
        std::vector<uint8_t> random;
        std::vector<uint8_t> extensions;
    };
    
    struct KeyExchangeMessage {
        QSKEMechanism selected_mechanism;
        QSPublicKey public_key;
        std::vector<uint8_t> auth_data;
    };
    
    struct KeyConfirmationMessage {
        QSCiphertext ciphertext;
        std::vector<uint8_t> confirmation_hash;
    };
    
    // Initiator flow
    HelloMessage CreateHello();
    KeyExchangeMessage ProcessHelloResponse(const HelloMessage& peer_hello);
    std::optional<QSSharedSecret> ProcessKeyConfirmation(
        const KeyConfirmationMessage& confirmation,
        const QSSecretKey& secret_key);
    
    // Responder flow
    std::optional<HelloMessage> ProcessHello(const HelloMessage& hello);
    KeyConfirmationMessage CreateKeyConfirmation(
        const KeyExchangeMessage& key_exchange,
        QSKEMEngine* kem_engine);
    
    // State management
    ProtocolState GetState() const;
    bool IsComplete() const;
    QSSharedSecret GetSharedSecret() const;
    
    // Serialization
    std::vector<uint8_t> SerializeHello(const HelloMessage& msg);
    HelloMessage DeserializeHello(const std::vector<uint8_t>& data);
    std::vector<uint8_t> SerializeKeyExchange(const KeyExchangeMessage& msg);
    KeyExchangeMessage DeserializeKeyExchange(const std::vector<uint8_t>& data);
    
private:
    Config config_;
    QSKERole role_;
    ProtocolState state_;
    
    HelloMessage sent_hello_;
    HelloMessage received_hello_;
    QSSecretKey ephemeral_secret_key_;
    QSSharedSecret shared_secret_;
    
    QSKEMechanism NegotiateMechanism(const std::vector<QSKEMechanism>& peer_mechanisms);
    std::vector<uint8_t> ComputeConfirmationHash(const QSSharedSecret& secret);
};

// ============================================================================
// Session Key Manager
// ============================================================================

class SessionKeyManager {
public:
    struct Config {
        int max_active_sessions = 10000;
        std::chrono::seconds session_timeout{3600};
        bool enable_key_rotation = true;
        std::chrono::minutes rotation_interval{60};
        bool forward_secrecy = true;
    };
    
    struct SessionKeys {
        std::vector<uint8_t> encryption_key;
        std::vector<uint8_t> integrity_key;
        std::vector<uint8_t> iv_seed;
        uint64_t sequence_number;
        std::chrono::steady_clock::time_point created_at;
        std::chrono::steady_clock::time_point expires_at;
    };
    
    explicit SessionKeyManager(const Config& config);
    ~SessionKeyManager();
    
    bool Initialize();
    void Shutdown();
    
    // Session creation
    std::string CreateSession(const QSSharedSecret& shared_secret);
    std::string CreateSession(const QSSharedSecret& shared_secret,
                             const std::string& session_id);
    
    // Key derivation
    SessionKeys DeriveSessionKeys(const std::string& session_id);
    SessionKeys DeriveSessionKeys(const QSSharedSecret& shared_secret,
                                 const std::string& context);
    
    // Key rotation
    bool RotateSessionKeys(const std::string& session_id);
    SessionKeys GetCurrentKeys(const std::string& session_id);
    SessionKeys GetNextKeys(const std::string& session_id);
    
    // Session management
    bool IsSessionValid(const std::string& session_id) const;
    bool TerminateSession(const std::string& session_id);
    void TerminateAllSessions();
    
    // Queries
    int GetActiveSessionCount() const;
    std::vector<std::string> GetActiveSessions() const;
    std::chrono::steady_clock::time_point GetSessionExpiry(const std::string& session_id) const;
    
    // Cleanup
    int CleanupExpiredSessions();
    
private:
    Config config_;
    std::map<std::string, std::pair<QSSharedSecret, SessionKeys>> sessions_;
    mutable std::mutex sessions_mutex_;
    std::thread cleanup_thread_;
    std::atomic<bool> running_{false};
    
    void CleanupLoop();
    SessionKeys DeriveKeysInternal(const QSSharedSecret& secret,
                                   const std::string& context,
                                   uint64_t sequence);
};

// ============================================================================
// Quantum-Safe Key Exchange Runtime
// ============================================================================

class QSKeyExchangeRuntime {
public:
    struct Config {
        QSKEMEngine::Config kem;
        AuthenticatedKEM::Config auth_kem;
        QSKeyExchangeProtocol::Config protocol;
        SessionKeyManager::Config sessions;
    };
    
    explicit QSKeyExchangeRuntime(const Config& config);
    ~QSKeyExchangeRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    QSKEMEngine* GetKEMEngine();
    AuthenticatedKEM* GetAuthenticatedKEM();
    QSKeyExchangeProtocol* GetProtocol();
    SessionKeyManager* GetSessionManager();
    
    // High-level API
    std::pair<QSPublicKey, QSSecretKey> GenerateKeyPair(QSKEMechanism mechanism);
    
    QSSharedSecret PerformKeyExchange(const QSPublicKey& peer_public_key,
                                     const QSSecretKey& local_secret_key,
                                     QSKERole role);
    
    std::string EstablishSession(const QSSharedSecret& shared_secret);
    
    // Authenticated exchange
    QSSharedSecret PerformAuthenticatedExchange(
        const AuthCredentials& local_credentials,
        const AuthCredentials& peer_credentials,
        QSKERole role);
    
    // Protocol execution
    bool ExecuteKeyExchangeProtocol(QSKERole role,
                                     std::function<bool(const std::vector<uint8_t>&)> send,
                                     std::function<std::optional<std::vector<uint8_t>>()>
receive);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<QSKEMEngine> kem_engine_;
    std::unique_ptr<AuthenticatedKEM> auth_kem_;
    std::unique_ptr<QSKeyExchangeProtocol> protocol_;
    std::unique_ptr<SessionKeyManager> session_manager_;
};

} // namespace Crypto
} // namespace Sovereign
