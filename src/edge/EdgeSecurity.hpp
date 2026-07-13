/**
 * EdgeSecurity.hpp
 *
 * Phase R Batch 5/5: Edge Security & Management
 *
 * Security features for edge nodes including attestation,
 * secure boot, encryption, and remote management.
 */

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace Edge {

// ============================================================================
// Forward Declarations
// ============================================================================

class EdgeSecurity;
class AttestationService;
class SecureBoot;
class RemoteManagement;
class EdgeFirewall;

// ============================================================================
// Security Level
// ============================================================================

enum class SecurityLevel {
    NONE,
    BASIC,          // Basic encryption
    STANDARD,       // TLS + Authentication
    HIGH,           // Hardware security module
    MAXIMUM         // Full attestation + secure boot
};

std::string SecurityLevelToString(SecurityLevel level);
SecurityLevel SecurityLevelFromString(const std::string& str);

// ============================================================================
// Device Identity
// ============================================================================

struct DeviceIdentity {
    std::string deviceId;
    std::string hardwareFingerprint;
    std::string certificate;
    std::string publicKey;
    std::optional<std::string> tpmPublicKey;
    std::optional<std::string> secureEnclaveId;
    std::chrono::system_clock::time_point issuedAt;
    std::chrono::system_clock::time_point expiresAt;
    std::vector<std::string> capabilities;
    
    bool IsValid() const;
    std::string GenerateFingerprint() const;
};

// ============================================================================
// Attestation Service
// ============================================================================

class AttestationService {
public:
    struct Config {
        bool enableTPM = false;
        bool enableSecureBoot = true;
        bool enableMeasuredBoot = false;
        std::string attestationServerUrl;
        std::chrono::seconds attestationInterval{3600};
        uint32_t maxRetries = 3;
    };
    
    struct AttestationReport {
        std::string deviceId;
        std::string nonce;
        std::vector<uint8_t> quote;
        std::vector<std::pair<std::string, std::string>> pcrs;  // TPM PCR values
        std::string firmwareVersion;
        std::string bootloaderVersion;
        std::string kernelVersion;
        std::vector<std::string> loadedModules;
        std::chrono::system_clock::time_point timestamp;
        std::string signature;
    };
    
    struct AttestationResult {
        bool success;
        bool deviceTrusted;
        std::optional<std::string> error;
        std::vector<std::string> violations;
        std::chrono::system_clock::time_point attestedAt;
        std::chrono::system_clock::time_point expiresAt;
    };
    
    explicit AttestationService(const Config& config);
    ~AttestationService();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Attestation
    AttestationReport GenerateReport();
    AttestationResult VerifyReport(const AttestationReport& report);
    AttestationResult Attest();
    
    // Continuous attestation
    void StartContinuousAttestation();
    void StopContinuousAttestation();
    bool IsContinuousAttestationRunning() const;
    
    // Trust status
    bool IsDeviceTrusted() const;
    std::chrono::system_clock::time_point GetLastAttestationTime() const;
    std::chrono::system_clock::time_point GetAttestationExpiry() const;
    
    // Events
    using AttestationHandler = std::function<void(const AttestationResult&)>;
    void OnAttestationComplete(AttestationHandler handler);
    void OnTrustRevoked(std::function<void(const std::string& reason)> handler);
    
    // PCR management
    void ExtendPCR(uint32_t pcrIndex, const std::vector<uint8_t>& data);
    std::optional<std::vector<uint8_t>> ReadPCR(uint32_t pcrIndex) const;
    void ResetPCR(uint32_t pcrIndex);
    
private:
    Config config_;
    bool initialized_;
    bool continuousRunning_;
    
    AttestationResult lastResult_;
    mutable std::mutex resultMutex_;
    
    std::thread attestationThread_;
    std::atomic<bool> stopAttestation_;
    
    AttestationHandler onComplete_;
    std::function<void(const std::string&)> onTrustRevoked_;
    
    void AttestationLoop();
    AttestationReport GenerateReportInternal();
    std::vector<uint8_t> GetTPMQuote(const std::string& nonce);
    bool VerifySignature(const AttestationReport& report);
};

// ============================================================================
// Secure Boot
// ============================================================================

class SecureBoot {
public:
    struct Config {
        bool enabled = true;
        std::string keystorePath;
        std::vector<std::string> trustedKeys;
        bool enforceSignatureVerification = true;
        bool allowRollback = false;
        uint32_t maxRollbackVersions = 3;
    };
    
    struct BootImage {
        std::string name;
        std::string version;
        std::vector<uint8_t> data;
        std::string signature;
        std::string hash;
        std::chrono::system_clock::time_point signedAt;
        std::string signedBy;
    };
    
    struct BootStatus {
        bool secureBootEnabled;
        bool verifiedBoot;
        std::string bootloaderVersion;
        std::string kernelVersion;
        std::string firmwareVersion;
        std::vector<std::string> verifiedImages;
        std::optional<std::string> error;
    };
    
    explicit SecureBoot(const Config& config);
    
    // Lifecycle
    bool Initialize();
    bool IsEnabled() const;
    
    // Image verification
    bool VerifyImage(const BootImage& image);
    bool LoadVerifiedImage(const BootImage& image);
    
    // Key management
    bool AddTrustedKey(const std::string& key);
    bool RemoveTrustedKey(const std::string& keyId);
    std::vector<std::string> GetTrustedKeys() const;
    
    // Boot chain
    BootStatus GetBootStatus() const;
    bool IsBootVerified() const;
    
    // Rollback protection
    bool IsRollbackAllowed(const std::string& version) const;
    void RecordBootVersion(const std::string& version);
    std::vector<std::string> GetBootHistory() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::vector<std::string> bootHistory_;
    mutable std::mutex historyMutex_;
    
    bool VerifySignature(const BootImage& image);
    bool VerifyHash(const BootImage& image);
};

// ============================================================================
// Edge Firewall
// ============================================================================

class EdgeFirewall {
public:
    struct Config {
        bool enabled = true;
        std::string defaultPolicy = "DROP";
        bool enableLogging = true;
        uint32_t maxRules = 1000;
        bool enableRateLimiting = true;
        uint32_t connectionsPerSecond = 100;
    };
    
    enum class RuleAction {
        ALLOW,
        DROP,
        REJECT,
        LOG
    };
    
    enum class Protocol {
        TCP,
        UDP,
        ICMP,
        ALL
    };
    
    struct FirewallRule {
        std::string ruleId;
        RuleAction action;
        Protocol protocol;
        std::optional<std::string> sourceIP;
        std::optional<std::string> destinationIP;
        std::optional<uint16_t> sourcePort;
        std::optional<uint16_t> destinationPort;
        std::optional<std::string> interface;
        std::optional<std::string> application;
        uint32_t priority;
        bool enabled;
        std::optional<std::string> description;
        std::chrono::system_clock::time_point createdAt;
    };
    
    struct Connection {
        std::string sourceIP;
        uint16_t sourcePort;
        std::string destinationIP;
        uint16_t destinationPort;
        Protocol protocol;
        std::chrono::system_clock::time_point establishedAt;
        uint64_t bytesTransferred;
        std::string state;  // NEW, ESTABLISHED, RELATED, INVALID
    };
    
    explicit EdgeFirewall(const Config& config);
    ~EdgeFirewall();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsEnabled() const;
    
    // Rule management
    std::string AddRule(const FirewallRule& rule);
    void UpdateRule(const std::string& ruleId, const FirewallRule& rule);
    void RemoveRule(const std::string& ruleId);
    void EnableRule(const std::string& ruleId);
    void DisableRule(const std::string& ruleId);
    std::optional<FirewallRule> GetRule(const std::string& ruleId) const;
    std::vector<FirewallRule> GetRules() const;
    
    // Default policy
    void SetDefaultPolicy(RuleAction action);
    RuleAction GetDefaultPolicy() const;
    
    // Connection tracking
    std::vector<Connection> GetActiveConnections() const;
    void CloseConnection(const std::string& connectionId);
    void CloseConnectionsByIP(const std::string& ip);
    
    // Rate limiting
    void SetRateLimit(uint32_t connectionsPerSecond);
    bool CheckRateLimit(const std::string& sourceIP);
    
    // Packet filtering
    bool ShouldAllowPacket(const std::string& sourceIP,
                           uint16_t sourcePort,
                           const std::string& destIP,
                           uint16_t destPort,
                           Protocol protocol);
    
    // Logging
    struct FirewallLog {
        std::chrono::system_clock::time_point timestamp;
        std::string action;
        std::string sourceIP;
        uint16_t sourcePort;
        std::string destIP;
        uint16_t destPort;
        Protocol protocol;
        std::string ruleId;
        std::string reason;
    };
    
    std::vector<FirewallLog> GetLogs(std::chrono::system_clock::time_point from,
                                      std::chrono::system_clock::time_point to) const;
    void ClearLogs();
    
    // Statistics
    struct FirewallStats {
        uint64_t packetsAllowed;
        uint64_t packetsDropped;
        uint64_t packetsRejected;
        uint64_t packetsLogged;
        uint32_t activeConnections;
        uint64_t rateLimitHits;
    };
    FirewallStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, FirewallRule> rules_;
    mutable std::mutex rulesMutex_;
    
    std::vector<Connection> connections_;
    mutable std::mutex connectionsMutex_;
    
    std::deque<FirewallLog> logs_;
    mutable std::mutex logsMutex_;
    
    std::map<std::string, std::deque<std::chrono::system_clock::time_point>> rateLimiters_;
    mutable std::mutex rateLimitMutex_;
    
    FirewallStats stats_;
    mutable std::mutex statsMutex_;
    
    void ApplyRule(const FirewallRule& rule);
    void RemoveRuleInternal(const std::string& ruleId);
    void LogPacket(const FirewallLog& log);
};

// ============================================================================
// Remote Management
// ============================================================================

class RemoteManagement {
public:
    struct Config {
        bool enabled = true;
        uint16_t managementPort = 8443;
        bool requireMutualTLS = true;
        std::vector<std::string> allowedIPs;
        std::chrono::seconds sessionTimeout{3600};
        bool enableCommandLogging = true;
        uint32_t maxConcurrentSessions = 5;
    };
    
    struct ManagementSession {
        std::string sessionId;
        std::string userId;
        std::string clientIP;
        std::chrono::system_clock::time_point establishedAt;
        std::chrono::system_clock::time_point lastActivity;
        std::vector<std::string> permissions;
        bool active;
    };
    
    struct RemoteCommand {
        std::string commandId;
        std::string command;
        std::vector<std::string> args;
        std::string userId;
        std::chrono::system_clock::time_point issuedAt;
        std::optional<std::chrono::seconds> timeout;
    };
    
    struct CommandResult {
        std::string commandId;
        bool success;
        int exitCode;
        std::string stdout;
        std::string stderr;
        std::chrono::milliseconds executionTime;
        std::chrono::system_clock::time_point completedAt;
    };
    
    explicit RemoteManagement(const Config& config);
    ~RemoteManagement();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Session management
    std::optional<ManagementSession> CreateSession(const std::string& userId,
                                                    const std::string& clientIP,
                                                    const std::vector<std::string>& permissions);
    void CloseSession(const std::string& sessionId);
    bool ValidateSession(const std::string& sessionId);
    void RefreshSession(const std::string& sessionId);
    std::vector<ManagementSession> GetActiveSessions() const;
    
    // Command execution
    CommandResult ExecuteCommand(const RemoteCommand& command);
    std::future<CommandResult> ExecuteCommandAsync(const RemoteCommand& command);
    
    // File operations
    bool UploadFile(const std::string& sessionId,
                    const std::string& localPath,
                    const std::vector<uint8_t>& data);
    std::optional<std::vector<uint8_t>> DownloadFile(const std::string& sessionId,
                                                      const std::string& remotePath);
    bool DeleteRemoteFile(const std::string& sessionId, const std::string& path);
    std::vector<std::string> ListRemoteDirectory(const std::string& sessionId,
                                                  const std::string& path);
    
    // Configuration management
    bool UpdateConfiguration(const std::string& sessionId,
                             const std::map<std::string, std::string>& config);
    std::map<std::string, std::string> GetConfiguration(const std::string& sessionId);
    
    // System operations
    bool RestartService(const std::string& sessionId, const std::string& serviceName);
    bool RebootDevice(const std::string& sessionId);
    bool FactoryReset(const std::string& sessionId);
    
    // Logs
    std::vector<std::string> GetSystemLogs(const std::string& sessionId,
                                           uint32_t lines = 100);
    std::vector<std::string> GetServiceLogs(const std::string& sessionId,
                                            const std::string& serviceName,
                                            uint32_t lines = 100);
    
    // Events
    using SessionEventHandler = std::function<void(const ManagementSession&)>;
    void OnSessionCreated(SessionEventHandler handler);
    void OnSessionClosed(SessionEventHandler handler);
    void OnCommandExecuted(std::function<void(const RemoteCommand&, const CommandResult&)> handler);
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, ManagementSession> sessions_;
    mutable std::mutex sessionsMutex_;
    
    SessionEventHandler onSessionCreated_;
    SessionEventHandler onSessionClosed_;
    std::function<void(const RemoteCommand&, const CommandResult&)> onCommandExecuted_;
    
    bool ValidatePermissions(const ManagementSession& session, const std::string& operation);
    void CleanupExpiredSessions();
    void LogCommand(const RemoteCommand& command, const CommandResult& result);
};

// ============================================================================
// Edge Security Manager
// ============================================================================

class EdgeSecurity {
public:
    struct Config {
        SecurityLevel securityLevel;
        AttestationService::Config attestationConfig;
        SecureBoot::Config secureBootConfig;
        EdgeFirewall::Config firewallConfig;
        RemoteManagement::Config remoteManagementConfig;
        bool enableEncryption = true;
        std::string encryptionAlgorithm = "AES-256-GCM";
        std::chrono::seconds keyRotationInterval{86400};  // 24 hours
    };
    
    struct SecurityStatus {
        SecurityLevel currentLevel;
        bool attestationValid;
        bool secureBootEnabled;
        bool firewallEnabled;
        bool remoteManagementEnabled;
        std::chrono::system_clock::time_point lastAttestation;
        std::chrono::system_clock::time_point keyExpiry;
        std::vector<std::string> activeAlerts;
        std::string overallStatus;  // secure, warning, critical
    };
    
    explicit EdgeSecurity(const Config& config);
    ~EdgeSecurity();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Components
    AttestationService* GetAttestationService() { return attestationService_.get(); }
    SecureBoot* GetSecureBoot() { return secureBoot_.get(); }
    EdgeFirewall* GetFirewall() { return firewall_.get(); }
    RemoteManagement* GetRemoteManagement() { return remoteManagement_.get(); }
    
    // Security operations
    bool PerformSecurityCheck();
    SecurityStatus GetSecurityStatus() const;
    std::vector<std::string> GetSecurityRecommendations() const;
    
    // Encryption
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext);
    void RotateKeys();
    
    // Alerts
    struct SecurityAlert {
        std::string alertId;
        std::string severity;
        std::string category;
        std::string message;
        std::chrono::system_clock::time_point timestamp;
        std::optional<std::string> recommendation;
        bool acknowledged;
    };
    
    std::vector<SecurityAlert> GetActiveAlerts() const;
    void AcknowledgeAlert(const std::string& alertId);
    void ClearAlert(const std::string& alertId);
    
    // Events
    using SecurityEventHandler = std::function<void(const SecurityAlert&)>;
    void OnSecurityAlert(SecurityEventHandler handler);
    void OnSecurityLevelChange(std::function<void(SecurityLevel, SecurityLevel)> handler);
    
    // Compliance
    enum class ComplianceStandard {
        FIPS_140_2,
        COMMON_CRITERIA,
        IEC_62443,
        NIST_CYBERSECURITY
    };
    
    bool CheckCompliance(ComplianceStandard standard) const;
    std::vector<std::string> GetComplianceViolations(ComplianceStandard standard) const;
    
private:
    Config config_;
    bool initialized_;
    
    std::unique_ptr<AttestationService> attestationService_;
    std::unique_ptr<SecureBoot> secureBoot_;
    std::unique_ptr<EdgeFirewall> firewall_;
    std::unique_ptr<RemoteManagement> remoteManagement_;
    
    std::vector<SecurityAlert> alerts_;
    mutable std::mutex alertsMutex_;
    
    SecurityEventHandler onAlert_;
    std::function<void(SecurityLevel, SecurityLevel)> onLevelChange_;
    
    std::thread keyRotationThread_;
    std::atomic<bool> stopKeyRotation_;
    
    void KeyRotationLoop();
    void RaiseAlert(const SecurityAlert& alert);
    void CheckSecurityLevel();
};

} // namespace Edge
