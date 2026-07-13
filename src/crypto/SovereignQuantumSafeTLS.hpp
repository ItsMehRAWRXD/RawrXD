// Phase D.15 Batch 3/5: Quantum-Safe TLS
// TLS 1.3 with post-quantum key exchange and signatures
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
struct QSTLSConfig;
struct QSCipherSuite;
struct QSCertificate;

// ============================================================================
// Quantum-Safe TLS Types
// ============================================================================

enum class QSKEMSuite {
    // Pure PQC
    ML_KEM_512 = 0,
    ML_KEM_768 = 1,
    ML_KEM_1024 = 2,
    
    // Hybrid (ECDH + PQC)
    X25519_ML_KEM_768 = 100,
    P256_ML_KEM_768 = 101,
    P384_ML_KEM_1024 = 102,
    X448_ML_KEM_1024 = 103
};

enum class QSSignatureSuite {
    // Pure PQC
    ML_DSA_44 = 0,
    ML_DSA_65 = 1,
    ML_DSA_87 = 2,
    
    // Hybrid
    ECDSA_P256_ML_DSA_65 = 100,
    ECDSA_P384_ML_DSA_87 = 101,
    ED25519_ML_DSA_65 = 102
};

enum class QSTLSVersion {
    TLS_1_3 = 0,
    TLS_1_3_PQ = 1  // Draft/experimental PQC TLS
};

enum class QSCertificateType {
    PQ_SELF_SIGNED = 0,
    PQ_CA_SIGNED = 1,
    HYBRID_CA_SIGNED = 2,
    PQ_CHAIN = 3
};

struct QSCipherSuite {
    std::string name;
    QSKEMSuite kem_suite;
    QSSignatureSuite sig_suite;
    std::string symmetric_cipher;  // AES-256-GCM, CHACHA20-POLY1305
    std::string hash_algorithm;  // SHA3-256, SHA3-384
    int security_level;
    bool is_hybrid;
};

struct QSCertificate {
    QSCertificateType type;
    std::vector<uint8_t> pq_public_key;
    std::vector<uint8_t> pq_signature;
    std::vector<uint8_t> classical_public_key;  // For hybrid
    std::vector<uint8_t> classical_signature;   // For hybrid
    std::string subject;
    std::string issuer;
    std::chrono::steady_clock::time_point valid_from;
    std::chrono::steady_clock::time_point valid_until;
    std::vector<uint8_t> serial_number;
    std::map<std::string, std::string> extensions;
    std::vector<QSCertificate> chain;
};

struct QSTLSConfig {
    QSTLSVersion version = QSTLSVersion::TLS_1_3_PQ;
    std::vector<QSCipherSuite> cipher_suites;
    std::vector<QSKEMSuite> supported_kems;
    std::vector<QSSignatureSuite> supported_sigs;
    bool verify_peer = true;
    std::string ca_file;
    std::string cert_file;
    std::string key_file;
    int handshake_timeout_ms = 10000;
    bool session_resumption = true;
    bool early_data = false;
};

// ============================================================================
// Quantum-Safe Handshake
// ============================================================================

class QSHandshake {
public:
    enum class State {
        INITIAL = 0,
        CLIENT_HELLO_SENT = 1,
        SERVER_HELLO_RECEIVED = 2,
        SERVER_FINISHED_RECEIVED = 3,
        CLIENT_FINISHED_SENT = 4,
        COMPLETED = 5,
        FAILED = 6
    };
    
    struct HandshakeContext {
        State state;
        QSCipherSuite negotiated_suite;
        std::vector<uint8_t> client_random;
        std::vector<uint8_t> server_random;
        std::vector<uint8_t> shared_secret;
        std::vector<uint8_t> handshake_secret;
        std::vector<uint8_t> master_secret;
        std::vector<uint8_t> client_traffic_secret;
        std::vector<uint8_t> server_traffic_secret;
        std::vector<uint8_t> pq_ciphertext;
        std::vector<uint8_t> pq_public_key;
    };
    
    explicit QSHandshake(const QSTLSConfig& config);
    ~QSHandshake();
    
    bool Initialize(bool is_server);
    void Shutdown();
    
    // Client side
    std::vector<uint8_t> GenerateClientHello();
    bool ProcessServerHello(const std::vector<uint8_t>& server_hello);
    bool ProcessServerFinished(const std::vector<uint8_t>& server_finished);
    std::vector<uint8_t> GenerateClientFinished();
    
    // Server side
n    bool ProcessClientHello(const std::vector<uint8_t>& client_hello);
    std::vector<uint8_t> GenerateServerHello();
    std::vector<uint8_t> GenerateServerFinished();
    bool ProcessClientFinished(const std::vector<uint8_t>& client_finished);
    
    // Key derivation
    std::vector<uint8_t> DeriveSharedSecret(const std::vector<uint8_t>& pq_secret_key,
                                           const std::vector<uint8_t>& pq_ciphertext);
    std::vector<uint8_t> DeriveHandshakeSecret(const std::vector<uint8_t>& shared_secret);
    std::vector<uint8_t> DeriveTrafficSecrets(const std::vector<uint8_t>& handshake_secret);
    
    // State
    State GetState() const;
    HandshakeContext GetContext() const;
    bool IsComplete() const;
    bool HasFailed() const;
    
private:
    QSTLSConfig config_;
    HandshakeContext context_;
    bool is_server_;
    mutable std::mutex context_mutex_;
    
    std::vector<uint8_t> GenerateRandom(size_t length);
    QSCipherSuite NegotiateCipherSuite(const std::vector<uint8_t>& client_suites);
    std::vector<uint8_t> HKDFExtract(const std::vector<uint8_t>& salt,
                                    const std::vector<uint8_t>& ikm);
    std::vector<uint8_t> HKDFExpand(const std::vector<uint8_t>& prk,
                                   const std::vector<uint8_t>& info,
                                   size_t length);
};

// ============================================================================
// Quantum-Safe Certificate Manager
// ============================================================================

class QSCertificateManager {
public:
    struct Config {
        std::string cert_store_path;
        std::string private_key_path;
        bool auto_renew = true;
        std::chrono::days renewal_before_expiry{30};
        bool verify_chain = true;
        bool verify_revocation = true;
    };
    
    explicit QSCertificateManager(const Config& config);
    ~QSCertificateManager();
    
    bool Initialize();
    void Shutdown();
    
    // Certificate generation
    QSCertificate GenerateSelfSigned(const std::string& subject,
                                      QSSignatureSuite sig_suite,
                                      const std::chrono::years& validity);
    QSCertificate GenerateCSR(const std::string& subject,
                               QSSignatureSuite sig_suite);
    QSCertificate SignCSR(const QSCertificate& csr,
                          const QSCertificate& ca_cert,
                          const std::vector<uint8_t>& ca_private_key);
    
    // Certificate loading
    bool LoadCertificate(const std::string& cert_file);
    bool LoadPrivateKey(const std::string& key_file);
    bool LoadCAStore(const std::string& ca_file);
    
    // Certificate queries
    QSCertificate GetCertificate() const;
    QSCertificate GetCertificate(const std::string& cert_id) const;
    std::vector<QSCertificate> GetCertificateChain() const;
    
    // Verification
    bool VerifyCertificate(const QSCertificate& cert);
    bool VerifyCertificateChain(const std::vector<QSCertificate>& chain);
    bool VerifyHostname(const QSCertificate& cert, const std::string& hostname);
    bool CheckExpiry(const QSCertificate& cert);
    
    // Renewal
    bool NeedsRenewal(const QSCertificate& cert);
    bool RenewCertificate();
    
    // Export
    bool ExportToPEM(const QSCertificate& cert, const std::string& file_path);
    bool ExportToDER(const QSCertificate& cert, const std::string& file_path);
    QSCertificate ImportFromPEM(const std::string& file_path);
    
private:
    Config config_;
    QSCertificate certificate_;
    std::vector<uint8_t> private_key_;
    std::vector<QSCertificate> ca_store_;
    mutable std::mutex cert_mutex_;
    
    std::vector<uint8_t> GenerateSerialNumber();
    std::vector<uint8_t> SignCertificate(const QSCertificate& cert,
                                        const std::vector<uint8_t>& private_key,
                                        QSSignatureSuite sig_suite);
};

// ============================================================================
// Quantum-Safe TLS Session
// ============================================================================

class QSTLSSession {
public:
    struct Config {
        QSTLSConfig tls_config;
        int buffer_size = 16384;
        bool enable_0rtt = false;
        std::chrono::seconds session_timeout{3600};
    };
    
    struct Record {
        uint8_t content_type;
        uint16_t version;
        uint16_t length;
        std::vector<uint8_t> encrypted_data;
    };
    
    explicit QSTLSSession(const Config& config);
    ~QSTLSSession();
    
    bool Initialize(int socket_fd, bool is_server);
    void Shutdown();
    
    // Handshake
    bool PerformHandshake();
    bool PerformHandshakeAsync();
    bool IsHandshakeComplete() const;
    
    // Data transfer
    ssize_t Send(const void* data, size_t length);
    ssize_t Receive(void* buffer, size_t length);
    
    // Record layer
    std::vector<uint8_t> EncryptRecord(const std::vector<uint8_t>& plaintext,
                                      uint8_t content_type);
    std::pair<std::vector<uint8_t>, uint8_t> DecryptRecord(
        const std::vector<uint8_t>& ciphertext);
    
    // Session management
    std::vector<uint8_t> ExportKeyingMaterial(const std::string& label,
                                             size_t length);
    bool Resumable() const;
    std::vector<uint8_t> GetSessionTicket();
    bool ResumeSession(const std::vector<uint8_t>& session_ticket);
    
    // State
    bool IsConnected() const;
    QSCipherSuite GetNegotiatedSuite() const;
    QSCertificate GetPeerCertificate() const;
    void Close();
    
private:
    Config config_;
    int socket_fd_;
    bool is_server_;
    bool connected_;
    
    std::unique_ptr<QSHandshake> handshake_;
    std::vector<uint8_t> write_key_;
    std::vector<uint8_t> read_key_;
    uint64_t write_seq_;
    uint64_t read_seq_;
    
    std::vector<uint8_t> pending_write_;
    std::vector<uint8_t> pending_read_;
    mutable std::mutex session_mutex_;
    
    bool WriteRecord(const Record& record);
    std::optional<Record> ReadRecord();
    void IncrementWriteSeq();
    void IncrementReadSeq();
};

// ============================================================================
// Quantum-Safe TLS Server
// ============================================================================

class QSTLSServer {
public:
    struct Config {
        QSTLSConfig tls_config;
        QSCertificateManager::Config cert_config;
        std::string bind_address = "0.0.0.0";
        int port = 8443;
        int backlog = 128;
        int worker_threads = 4;
        bool reuse_address = true;
        bool tcp_nodelay = true;
    };
    
    using ConnectionHandler = std::function<void(std::unique_ptr<QSTLSSession>)>;
    
    explicit QSTLSServer(const Config& config);
    ~QSTLSServer();
    
    bool Initialize();
    void Shutdown();
    
    // Server lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const;
    
    // Connection handling
    void SetConnectionHandler(ConnectionHandler handler);
    std::unique_ptr<QSTLSSession> Accept();
    
    // Statistics
    struct ServerStats {
        int total_connections;
        int active_connections;
        int failed_handshakes;
        int successful_handshakes;
        std::map<QSCipherSuite, int> cipher_suite_usage;
    };
    ServerStats GetStats() const;
    
private:
    Config config_;
    int listen_fd_;
    std::atomic<bool> running_{false};
    ConnectionHandler connection_handler_;
    
    std::unique_ptr<QSCertificateManager> cert_manager_;
    std::vector<std::thread> worker_threads_;
    std::atomic<int> total_connections_{0};
    std::atomic<int> active_connections_{0};
    std::atomic<int> failed_handshakes_{0};
    std::atomic<int> successful_handshakes_{0};
    std::map<QSCipherSuite, std::atomic<int>> cipher_suite_usage_;
    
    void AcceptLoop();
    void HandleConnection(int client_fd);
};

// ============================================================================
// Quantum-Safe TLS Client
// ============================================================================

class QSTLSClient {
public:
    struct Config {
        QSTLSConfig tls_config;
        std::string default_server;
        int default_port = 8443;
        int connect_timeout_ms = 10000;
        bool verify_hostname = true;
    };
    
    explicit QSTLSClient(const Config& config);
    ~QSTLSClient();
    
    bool Initialize();
    void Shutdown();
    
    // Connection
    std::unique_ptr<QSTLSSession> Connect(const std::string& hostname,
                                         int port = 0);
    std::unique_ptr<QSTLSSession> Connect(const std::string& hostname,
                                         int port,
                                         const QSCipherSuite& preferred_suite);
    
    // Async connection
    void ConnectAsync(const std::string& hostname,
                     int port,
                     std::function<void(std::unique_ptr<QSTLSSession>, bool)> callback);
    
    // Session reuse
    void SetSessionCache(std::shared_ptr<void> cache);
    std::vector<uint8_t> GetSessionData(const std::string& hostname);
    void SetSessionData(const std::string& hostname,
                       const std::vector<uint8_t>& session_data);
    
private:
    Config config_;
    std::map<std::string, std::vector<uint8_t>> session_cache_;
    mutable std::mutex cache_mutex_;
    
    int ResolveAndConnect(const std::string& hostname, int port);
};

// ============================================================================
// Quantum-Safe TLS Runtime
// ============================================================================

class QSTLSRuntime {
public:
    struct Config {
        QSTLSConfig tls;
        QSCertificateManager::Config certs;
        QSTLSServer::Config server;
        QSTLSClient::Config client;
    };
    
    explicit QSTLSRuntime(const Config& config);
    ~QSTLSRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    QSCertificateManager* GetCertificateManager();
    
    // Server creation
    std::unique_ptr<QSTLSServer> CreateServer(const QSTLSServer::Config& config);
    
    // Client creation
    std::unique_ptr<QSTLSClient> CreateClient(const QSTLSClient::Config& config);
    
    // Session creation
    std::unique_ptr<QSTLSSession> CreateSession(const QSTLSSession::Config& config);
    
    // Cipher suite utilities
    std::vector<QSCipherSuite> GetRecommendedCipherSuites(int security_level);
    QSCipherSuite GetStrongestCipherSuite();
    bool IsCipherSuiteSupported(const QSCipherSuite& suite);
    
    // Security info
    struct SecurityInfo {
        int achieved_security_bits;
        bool is_quantum_safe;
        bool is_hybrid;
        std::string kem_algorithm;
        std::string sig_algorithm;
        std::string symmetric_cipher;
    };
    SecurityInfo GetSecurityInfo(const QSCipherSuite& suite);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<QSCertificateManager> cert_manager_;
};

} // namespace Crypto
} // namespace Sovereign
