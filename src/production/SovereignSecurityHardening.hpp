// Phase D.10 Batch 2/5: Security Hardening
// Production-grade security hardening and vulnerability mitigation
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Production {

// ============================================================================
// Security Policy Engine
// ============================================================================

enum class SecurityLevel {
    PERMISSIVE = 0,
    STANDARD = 1,
    RESTRICTIVE = 2,
    PARANOID = 3
};

struct SecurityPolicy {
    std::string id;
    std::string name;
    SecurityLevel level;
    std::map<std::string, bool> rules;
    std::vector<std::string> allowed_algorithms;
    std::vector<std::string> blocked_ciphers;
    int min_key_size = 2048;
    bool enforce_tls_1_3 = false;
    bool require_mutual_tls = false;
    std::chrono::seconds session_timeout{3600};
    int max_failed_attempts = 5;
    std::chrono::seconds lockout_duration{300};
};

class SecurityPolicyEngine {
public:
    struct Config {
        SecurityLevel default_level = SecurityLevel::STANDARD;
        bool auto_update_policies = true;
        std::string policy_store_path;
    };
    
    explicit SecurityPolicyEngine(const Config& config);
    ~SecurityPolicyEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Policy management
    bool LoadPolicy(const SecurityPolicy& policy);
    bool ActivatePolicy(const std::string& policy_id);
    bool DeactivatePolicy(const std::string& policy_id);
    SecurityPolicy GetActivePolicy() const;
    std::vector<SecurityPolicy> GetAllPolicies() const;
    
    // Rule evaluation
    bool EvaluateRule(const std::string& rule_name, const std::map<std::string, std::any>& context);
    bool CheckCompliance(const std::string& component);
    std::vector<std::string> GetViolations() const;
    
    // Default policies
    static SecurityPolicy CreateDefaultPolicy(SecurityLevel level);
    static SecurityPolicy CreateCISPolicy();
    static SecurityPolicy CreateNISTPolicy();
    static SecurityPolicy CreatePCIDSSPolicy();
    static SecurityPolicy CreateHIPAAPolicy();
    
private:
    Config config_;
    std::map<std::string, SecurityPolicy> policies_;
    std::string active_policy_id_;
    mutable std::mutex policies_mutex_;
};

// ============================================================================
// Vulnerability Scanner
// ============================================================================

enum class VulnerabilitySeverity {
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

struct Vulnerability {
    std::string id;
    std::string cve_id;
    std::string title;
    std::string description;
    VulnerabilitySeverity severity;
    std::string affected_component;
    std::string affected_version;
    std::string fixed_version;
    std::vector<std::string> references;
    std::map<std::string, std::string> metadata;
    std::chrono::steady_clock::time_point discovered_at;
};

class VulnerabilityScanner {
public:
    struct Config {
        bool enable_continuous_scanning = true;
        std::chrono::hours scan_interval{24};
        std::string vulnerability_db_url;
        bool auto_update_db = true;
        std::vector<std::string> scan_paths;
        bool scan_dependencies = true;
        bool scan_containers = true;
    };
    
    explicit VulnerabilityScanner(const Config& config);
    ~VulnerabilityScanner();
    
    bool Initialize();
    void Shutdown();
    
    // Scanning
    std::vector<Vulnerability> ScanComponent(const std::string& component);
    std::vector<Vulnerability> ScanDependencies();
    std::vector<Vulnerability> ScanContainers();
    std::vector<Vulnerability> RunFullScan();
    
    // CVE database
    bool UpdateDatabase();
    std::vector<Vulnerability> LookupCVE(const std::string& cve_id);
    std::vector<Vulnerability> FindByComponent(const std::string& component);
    
    // Reporting
    void GenerateReport(const std::string& path);
    std::map<VulnerabilitySeverity, int> GetSeverityCounts() const;
    bool HasCriticalVulnerabilities() const;
    
    // Remediation
    std::vector<std::string> GetRemediationSteps(const Vulnerability& vuln);
    bool CanAutoFix(const Vulnerability& vuln);
    bool ApplyFix(const Vulnerability& vuln);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::vector<Vulnerability> vulnerabilities_;
    mutable std::mutex vulns_mutex_;
    
    std::thread scan_thread_;
    
    void ScanLoop();
    std::vector<Vulnerability> ScanFile(const std::string& path);
    VulnerabilitySeverity ParseCVSSScore(double score);
};

// ============================================================================
// Intrusion Detection System
// ============================================================================

struct SecurityEvent {
    std::string id;
    std::string type;
    std::string source_ip;
    std::string target;
    std::string description;
    VulnerabilitySeverity severity;
    std::map<std::string, std::string> details;
    std::chrono::steady_clock::time_point detected_at;
    bool acknowledged = false;
};

class IntrusionDetectionSystem {
public:
    struct Config {
        bool enable_network_monitoring = true;
        bool enable_file_integrity_monitoring = true;
        bool enable_process_monitoring = true;
        std::vector<std::string> monitored_paths;
        std::vector<std::string> protected_files;
        int alert_threshold = 10;
        std::chrono::seconds detection_window{60};
    };
    
    explicit IntrusionDetectionSystem(const Config& config);
    ~IntrusionDetectionSystem();
    
    bool Initialize();
    void Shutdown();
    
    // Detection
    void AnalyzeNetworkTraffic(const std::string& source, const std::string& destination,
                               int port, size_t bytes);
    void AnalyzeFileAccess(const std::string& path, const std::string& operation,
                           const std::string& user);
    void AnalyzeProcessExecution(const std::string& command, const std::string& user);
    void AnalyzeLoginAttempt(const std::string& username, const std::string& source_ip,
                            bool success);
    
    // Signatures
    void LoadSignature(const std::string& signature);
    void LoadSignaturesFromFile(const std::string& path);
    void UpdateSignatures();
    
    // Events
    std::vector<SecurityEvent> GetEvents(VulnerabilitySeverity min_severity = VulnerabilitySeverity::LOW);
    std::vector<SecurityEvent> GetEventsSince(std::chrono::steady_clock::time_point since);
    void AcknowledgeEvent(const std::string& event_id);
    
    // Blocking
    void BlockIP(const std::string& ip, std::chrono::hours duration);
    void UnblockIP(const std::string& ip);
    std::vector<std::string> GetBlockedIPs() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::vector<SecurityEvent> events_;
    std::mutex events_mutex_;
    
    std::map<std::string, std::chrono::steady_clock::time_point> blocked_ips_;
    std::mutex blocked_mutex_;
    
    std::vector<std::string> signatures_;
    
    std::thread detection_thread_;
    
    void DetectionLoop();
    bool MatchesSignature(const SecurityEvent& event);
    void RaiseAlert(const SecurityEvent& event);
};

// ============================================================================
// Encryption Manager
// ============================================================================

enum class EncryptionAlgorithm {
    AES_256_GCM = 0,
    CHACHA20_POLY1305 = 1,
    RSA_4096 = 2,
    ECDH_P256 = 3,
    ECDH_P384 = 4,
    ECDH_P521 = 5
};

class EncryptionManager {
public:
    struct Config {
        EncryptionAlgorithm default_algorithm = EncryptionAlgorithm::AES_256_GCM;
        bool enable_hardware_acceleration = true;
        bool enable_key_rotation = true;
        std::chrono::days key_rotation_interval{90};
        std::string key_store_path;
        bool use_hsm = false;
        std::string hsm_library_path;
    };
    
    explicit EncryptionManager(const Config& config);
    ~EncryptionManager();
    
    bool Initialize();
    void Shutdown();
    
    // Symmetric encryption
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& key,
                                  EncryptionAlgorithm algorithm);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& key,
                                  EncryptionAlgorithm algorithm);
    
    // Asymmetric encryption
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> GenerateKeyPair(EncryptionAlgorithm algorithm);
    std::vector<uint8_t> EncryptWithPublicKey(const std::vector<uint8_t>& plaintext,
                                             const std::vector<uint8_t>& public_key);
    std::vector<uint8_t> DecryptWithPrivateKey(const std::vector<uint8_t>& ciphertext,
                                              const std::vector<uint8_t>& private_key);
    
    // Key management
    std::vector<uint8_t> GenerateKey(size_t length);
    bool StoreKey(const std::string& key_id, const std::vector<uint8_t>& key);
    std::vector<uint8_t> RetrieveKey(const std::string& key_id);
    bool RotateKey(const std::string& key_id);
    bool DestroyKey(const std::string& key_id);
    
    // Hashing
    std::vector<uint8_t> Hash(const std::vector<uint8_t>& data, const std::string& algorithm = "SHA256");
    std::vector<uint8_t> HMAC(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::map<std::string, std::vector<uint8_t>> key_store_;
    std::mutex key_mutex_;
};

// ============================================================================
// Secure Communication
// ============================================================================

class SecureCommunication {
public:
    struct Config {
        bool verify_peer = true;
        std::string ca_cert_path;
        std::string cert_path;
        std::string key_path;
        std::vector<std::string> cipher_suites;
        std::string min_tls_version = "1.2";
        bool enable_ocsp = true;
        bool enable_certificate_pinning = false;
        std::vector<std::string> pinned_certificates;
    };
    
    explicit SecureCommunication(const Config& config);
    ~SecureCommunication();
    
    bool Initialize();
    void Shutdown();
    
    // TLS operations
    int CreateTLSSocket(const std::string& host, int port);
    bool PerformHandshake(int socket_fd);
    bool VerifyCertificate(int socket_fd);
    
    // Certificate management
    bool LoadCertificate(const std::string& path);
    bool LoadPrivateKey(const std::string& path);
    bool LoadCA(const std::string& path);
    bool PinCertificate(const std::string& fingerprint);
    
    // Secure channels
    bool SendSecure(int socket_fd, const void* data, size_t size);
    ssize_t ReceiveSecure(int socket_fd, void* buffer, size_t size);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    void* ssl_ctx_ = nullptr;
};

// ============================================================================
// Audit Logger
// ============================================================================

struct AuditEntry {
    std::string id;
    std::string timestamp;
    std::string event_type;
    std::string user_id;
    std::string source_ip;
    std::string resource;
    std::string action;
    bool success;
    std::map<std::string, std::string> details;
    std::string session_id;
    std::string correlation_id;
};

class AuditLogger {
public:
    struct Config {
        std::string log_path;
        bool enable_remote_logging = false;
        std::string remote_endpoint;
        bool encrypt_logs = true;
        std::chrono::seconds flush_interval{5};
        size_t max_log_size_mb = 100;
        int max_log_files = 10;
        bool immutable_logs = false;
    };
    
    explicit AuditLogger(const Config& config);
    ~AuditLogger();
    
    bool Initialize();
    void Shutdown();
    
    // Logging
    void Log(const AuditEntry& entry);
    void LogAuthEvent(const std::string& user, const std::string& action, bool success);
    void LogDataAccess(const std::string& user, const std::string& resource,
                       const std::string& action, bool success);
    void LogAdminAction(const std::string& user, const std::string& action,
                        const std::map<std::string, std::string>& details);
    void LogSecurityEvent(const std::string& event_type, VulnerabilitySeverity severity,
                          const std::map<std::string, std::string>& details);
    
    // Query
    std::vector<AuditEntry> Query(const std::string& start_time, const std::string& end_time,
                                    const std::map<std::string, std::string>& filters);
    std::vector<AuditEntry> GetUserActivity(const std::string& user_id,
                                            std::chrono::hours duration);
    
    // Export
    bool ExportToJSON(const std::string& path);
    bool ExportToCSV(const std::string& path);
    
    // Integrity
    bool VerifyIntegrity();
    std::string GenerateIntegrityHash();
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::vector<AuditEntry> buffer_;
    std::mutex buffer_mutex_;
    
    std::thread flush_thread_;
    
    void FlushLoop();
    void WriteToFile(const std::vector<AuditEntry>& entries);
    void WriteToRemote(const std::vector<AuditEntry>& entries);
};

// ============================================================================
// Security Runtime
// ============================================================================

class SecurityHardeningRuntime {
public:
    struct Config {
        SecurityPolicyEngine::Config policy;
        VulnerabilityScanner::Config scanner;
        IntrusionDetectionSystem::Config ids;
        EncryptionManager::Config encryption;
        SecureCommunication::Config secure_comm;
        AuditLogger::Config audit;
    };
    
    explicit SecurityHardeningRuntime(const Config& config);
    ~SecurityHardeningRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    SecurityPolicyEngine* GetPolicyEngine();
    VulnerabilityScanner* GetVulnerabilityScanner();
    IntrusionDetectionSystem* GetIDS();
    EncryptionManager* GetEncryptionManager();
    SecureCommunication* GetSecureCommunication();
    AuditLogger* GetAuditLogger();
    
    // Security operations
    bool ApplySecurityPolicy(SecurityLevel level);
    bool RunSecurityScan();
    bool VerifySystemIntegrity();
    
    // Compliance
    bool IsCompliant(const std::string& standard);
    std::map<std::string, bool> GetComplianceStatus();
    void GenerateComplianceReport(const std::string& standard, const std::string& path);
    
    // Health
    bool IsSecure() const;
    std::vector<std::string> GetSecurityIssues() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<SecurityPolicyEngine> policy_engine_;
    std::unique_ptr<VulnerabilityScanner> vulnerability_scanner_;
    std::unique_ptr<IntrusionDetectionSystem> ids_;
    std::unique_ptr<EncryptionManager> encryption_manager_;
    std::unique_ptr<SecureCommunication> secure_comm_;
    std::unique_ptr<AuditLogger> audit_logger_;
};

} // namespace Production
} // namespace Sovereign
