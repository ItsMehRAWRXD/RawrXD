/**
 * AuditLogger.hpp
 *
 * Phase G Batch 4/5: Audit Logging & Compliance
 *
 * Comprehensive audit logging with tamper-evident records,
 * compliance reporting, and secure log storage.
 */

#pragma once

#include "Authentication.hpp"
#include "Authorization.hpp"
#include "Encryption.hpp"
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <functional>

namespace Security {

// ============================================================================
// Audit Event Types
// ============================================================================

enum class AuditEventType {
    // Authentication events
    AUTHENTICATION_SUCCESS,
    AUTHENTICATION_FAILURE,
    AUTHENTICATION_MFA_REQUIRED,
    AUTHENTICATION_MFA_SUCCESS,
    AUTHENTICATION_MFA_FAILURE,
    SESSION_CREATED,
    SESSION_DESTROYED,
    SESSION_EXPIRED,
    SESSION_INVALIDATED,
    LOGOUT,
    
    // Authorization events
    AUTHORIZATION_GRANTED,
    AUTHORIZATION_DENIED,
    PERMISSION_CHECK,
    ROLE_ASSIGNED,
    ROLE_REVOKED,
    POLICY_VIOLATION,
    
    // Data access events
    DATA_READ,
    DATA_WRITE,
    DATA_DELETE,
    DATA_EXPORT,
    DATA_IMPORT,
    DATA_ENCRYPTED,
    DATA_DECRYPTED,
    
    // System events
    CONFIGURATION_CHANGE,
    SYSTEM_STARTUP,
    SYSTEM_SHUTDOWN,
    BACKUP_CREATED,
    BACKUP_RESTORED,
    
    // Security events
    SECURITY_ALERT,
    THREAT_DETECTED,
    INTRUSION_ATTEMPT,
    ANOMALY_DETECTED,
    
    // Compliance events
    COMPLIANCE_CHECK,
    COMPLIANCE_VIOLATION,
    RETENTION_POLICY_APPLIED,
    DATA_PURGED
};

std::string AuditEventTypeToString(AuditEventType type);
AuditEventType AuditEventTypeFromString(const std::string& str);

// ============================================================================
// Audit Event Severity
// ============================================================================

enum class AuditSeverity {
    DEBUG,
    INFO,
    NOTICE,
    WARNING,
    ERROR,
    CRITICAL,
    ALERT,
    EMERGENCY
};

std::string AuditSeverityToString(AuditSeverity severity);

// ============================================================================
// Audit Event
// ============================================================================

struct AuditEvent {
    // Event identification
    std::string eventId;
    AuditEventType type;
    AuditSeverity severity;
    
    // Timestamps
    uint64_t timestamp;           // Unix timestamp (milliseconds)
    uint64_t processedAt;         // When event was processed
    
    // Actor information
    std::string identityId;
    std::string identityName;
    std::string sessionId;
    std::string ipAddress;
    std::string userAgent;
    
    // Resource information
    std::string resourceType;
    std::string resourceId;
    std::string resourcePath;
    
    // Action details
    std::string action;
    std::map<std::string, std::string> parameters;
    std::map<std::string, std::string> context;
    
    // Result
    bool success;
    std::string resultCode;
    std::string resultMessage;
    
    // Security
    std::string hash;             // Tamper-evident hash
    std::string previousHash;     // Chain hash
    std::string signature;          // Digital signature
    
    // Compliance
    std::set<std::string> complianceFrameworks;  // GDPR, HIPAA, SOX, etc.
    std::string dataClassification;              // Public, Internal, Confidential, Restricted
    
    AuditEvent();
    
    // Serialization
    std::string ToJson() const;
    static AuditEvent FromJson(const std::string& json);
    
    // Hash computation
    std::string ComputeHash() const;
    
    // Validation
    bool IsValid() const;
};

// ============================================================================
// Audit Filter
// ============================================================================

struct AuditFilter {
    std::set<AuditEventType> types;
    std::set<AuditSeverity> severities;
    std::set<std::string> identityIds;
    std::set<std::string> resourceTypes;
    std::set<std::string> resourceIds;
    std::set<std::string> actions;
    std::set<std::string> complianceFrameworks;
    
    uint64_t startTime = 0;
    uint64_t endTime = UINT64_MAX;
    
    bool successOnly = false;
    bool failureOnly = false;
    
    size_t maxResults = 1000;
    size_t offset = 0;
    
    bool Matches(const AuditEvent& event) const;
};

// ============================================================================
// Audit Log Storage
// ============================================================================

class IAuditStorage {
public:
    virtual ~IAuditStorage() = default;
    
    virtual bool Initialize(const std::map<std::string, std::string>& config) = 0;
    virtual void Shutdown() = 0;
    
    virtual bool StoreEvent(const AuditEvent& event) = 0;
    virtual bool StoreEvents(const std::vector<AuditEvent>& events) = 0;
    
    virtual std::vector<AuditEvent> QueryEvents(const AuditFilter& filter) = 0;
    virtual size_t CountEvents(const AuditFilter& filter) = 0;
    
    virtual bool DeleteEvents(const AuditFilter& filter) = 0;
    virtual bool ArchiveEvents(const AuditFilter& filter, const std::string& archivePath) = 0;
    
    virtual std::string GetStorageType() const = 0;
    virtual std::string GetStatusJson() const = 0;
};

/**
 * File-based audit storage with rotation.
 */
class FileAuditStorage : public IAuditStorage {
public:
    FileAuditStorage();
    ~FileAuditStorage() override;
    
    bool Initialize(const std::map<std::string, std::string>& config) override;
    void Shutdown() override;
    
    bool StoreEvent(const AuditEvent& event) override;
    bool StoreEvents(const std::vector<AuditEvent>& events) override;
    
    std::vector<AuditEvent> QueryEvents(const AuditFilter& filter) override;
    size_t CountEvents(const AuditFilter& filter) override;
    
    bool DeleteEvents(const AuditFilter& filter) override;
    bool ArchiveEvents(const AuditFilter& filter, const std::string& archivePath) override;
    
    std::string GetStorageType() const override { return "file"; }
    std::string GetStatusJson() const override;
    
    // File-specific operations
    bool RotateLog();
    std::vector<std::string> GetLogFiles() const;
    bool CompactLogs();
    
private:
    std::string basePath_;
    size_t maxFileSize_;
    size_t maxFiles_;
    bool encryptLogs_;
    std::string encryptionKeyId_;
    
    std::string currentLogFile_;
    size_t currentFileSize_;
    mutable std::mutex mutex_;
    
    bool WriteEventToFile(const AuditEvent& event, const std::string& filename);
    std::optional<AuditEvent> ReadEventFromLine(const std::string& line);
    std::string GenerateLogFilename();
    void CleanupOldLogs();
};

/**
 * Database-backed audit storage.
 */
class DatabaseAuditStorage : public IAuditStorage {
public:
    DatabaseAuditStorage();
    ~DatabaseAuditStorage() override;
    
    bool Initialize(const std::map<std::string, std::string>& config) override;
    void Shutdown() override;
    
    bool StoreEvent(const AuditEvent& event) override;
    bool StoreEvents(const std::vector<AuditEvent>& events) override;
    
    std::vector<AuditEvent> QueryEvents(const AuditFilter& filter) override;
    size_t CountEvents(const AuditFilter& filter) override;
    
    bool DeleteEvents(const AuditFilter& filter) override;
    bool ArchiveEvents(const AuditFilter& filter, const std::string& archivePath) override;
    
    std::string GetStorageType() const override { return "database"; }
    std::string GetStatusJson() const override;
    
    // Database-specific operations
    bool CreateIndexes();
    bool Vacuum();
    
private:
    std::string connectionString_;
    std::string tableName_;
    size_t batchSize_;
    
    // Placeholder for database connection
    void* dbHandle_ = nullptr;
    mutable std::mutex mutex_;
    
    bool EnsureTableExists();
    std::string BuildWhereClause(const AuditFilter& filter);
};

// ============================================================================
// Tamper-Evident Chain
// ============================================================================

/**
 * Blockchain-style tamper-evident log chain.
 */
class TamperEvidentChain {
public:
    struct ChainEntry {
        std::string eventId;
        std::string eventHash;
        std::string previousHash;
        std::string combinedHash;
        uint64_t timestamp;
        uint64_t sequenceNumber;
    };
    
    TamperEvidentChain();
    ~TamperEvidentChain();
    
    bool Initialize(const std::string& chainFile);
    void Shutdown();
    
    // Add event to chain
    ChainEntry AddEvent(const AuditEvent& event);
    
    // Verify chain integrity
    bool VerifyChain();
    std::vector<ChainEntry> DetectTampering();
    
    // Get chain info
    ChainEntry GetLatestEntry() const;
    std::optional<ChainEntry> GetEntry(const std::string& eventId);
    std::vector<ChainEntry> GetEntries(uint64_t startSeq, uint64_t endSeq);
    
    // Export/Import
    bool ExportChain(const std::string& path);
    bool ImportChain(const std::string& path);
    
private:
    std::string chainFile_;
    std::vector<ChainEntry> entries_;
    mutable std::mutex mutex_;
    
    std::string ComputeCombinedHash(const std::string& eventHash, 
                                     const std::string& previousHash);
    bool PersistEntry(const ChainEntry& entry);
    bool LoadChain();
};

// ============================================================================
// Compliance Framework
// ============================================================================

enum class ComplianceFramework {
    GDPR,       // General Data Protection Regulation
    HIPAA,      // Health Insurance Portability and Accountability Act
    SOX,        // Sarbanes-Oxley Act
    PCI_DSS,    // Payment Card Industry Data Security Standard
    ISO_27001,  // Information Security Management
    SOC2,       // Service Organization Control 2
    NIST_800_53,// NIST Security and Privacy Controls
    CCPA,       // California Consumer Privacy Act
    FISMA,      // Federal Information Security Management Act
    CUSTOM
};

std::string ComplianceFrameworkToString(ComplianceFramework framework);

struct ComplianceRequirement {
    ComplianceFramework framework;
    std::string requirementId;
    std::string description;
    std::set<AuditEventType> requiredEvents;
    uint64_t retentionPeriodDays;
    bool encryptionRequired;
    bool immutableRequired;
    std::string accessControlLevel;
};

class ComplianceManager {
public:
    ComplianceManager();
    ~ComplianceManager();
    
    bool Initialize(const std::vector<ComplianceFramework>& frameworks);
    void Shutdown();
    
    // Framework management
    void EnableFramework(ComplianceFramework framework);
    void DisableFramework(ComplianceFramework framework);
    std::set<ComplianceFramework> GetActiveFrameworks() const;
    
    // Requirements
    std::vector<ComplianceRequirement> GetRequirements(ComplianceFramework framework);
    bool CheckCompliance(const AuditEvent& event);
    std::vector<std::string> GetComplianceViolations(const AuditEvent& event);
    
    // Reporting
    struct ComplianceReport {
        ComplianceFramework framework;
        uint64_t generatedAt;
        std::string period;
        size_t totalEvents;
        size_t compliantEvents;
        size_t violations;
        std::vector<std::string> violationDetails;
        std::map<std::string, size_t> eventTypeCounts;
        bool overallCompliance;
    };
    
    ComplianceReport GenerateReport(ComplianceFramework framework,
                                     uint64_t startTime,
                                     uint64_t endTime);
    std::vector<ComplianceReport> GenerateAllReports(uint64_t startTime,
                                                      uint64_t endTime);
    
    // Export
    bool ExportReport(const ComplianceReport& report, const std::string& format,
                      const std::string& path);
    
private:
    std::set<ComplianceFramework> activeFrameworks_;
    std::map<ComplianceFramework, std::vector<ComplianceRequirement>> requirements_;
    mutable std::mutex mutex_;
    
    void LoadDefaultRequirements();
};

// ============================================================================
// Retention Policy
// ============================================================================

struct RetentionPolicy {
    std::string policyId;
    std::string name;
    std::string description;
    
    // Criteria
    std::set<AuditEventType> eventTypes;
    std::set<AuditSeverity> severities;
    std::set<std::string> complianceFrameworks;
    std::set<std::string> dataClassifications;
    
    // Retention rules
    uint64_t retentionDays;
    bool archiveBeforeDelete;
    std::string archiveLocation;
    
    // Actions
    bool notifyBeforeDeletion;
    uint64_t notifyDaysBefore;
    std::vector<std::string> notifyRecipients;
    
    bool enabled;
    uint64_t lastRun;
    uint64_t nextRun;
};

class RetentionManager {
public:
    RetentionManager();
    ~RetentionManager();
    
    bool Initialize(IAuditStorage* storage);
    void Shutdown();
    
    // Policy management
    bool CreatePolicy(const RetentionPolicy& policy);
    bool UpdatePolicy(const RetentionPolicy& policy);
    bool DeletePolicy(const std::string& policyId);
    std::optional<RetentionPolicy> GetPolicy(const std::string& policyId);
    std::vector<RetentionPolicy> GetAllPolicies();
    
    // Policy execution
    size_t ApplyPolicy(const RetentionPolicy& policy);
    size_t ApplyAllPolicies();
    
    // Scheduling
    void StartScheduler();
    void StopScheduler();
    void SchedulePolicy(const RetentionPolicy& policy);
    
    // Statistics
    struct RetentionStats {
        size_t totalEvents;
        size_t eventsArchived;
        size_t eventsDeleted;
        uint64_t storageSaved;
        std::map<std::string, size_t> policyStats;
    };
    RetentionStats GetStatistics() const;
    
private:
    IAuditStorage* storage_;
    std::map<std::string, RetentionPolicy> policies_;
    mutable std::mutex mutex_;
    bool running_;
    
    RetentionStats stats_;
};

// ============================================================================
// Real-time Audit Monitor
// ============================================================================

class AuditMonitor {
public:
    using AlertHandler = std::function<void(const AuditEvent&)>;
    using AnomalyDetector = std::function<bool(const std::vector<AuditEvent>&)>;
    
    struct AlertRule {
        std::string ruleId;
        std::string name;
        std::string description;
        AuditFilter filter;
        size_t threshold;
        uint64_t timeWindowMs;
        AuditSeverity alertSeverity;
        std::vector<std::string> alertChannels;
        bool enabled;
    };
    
    AuditMonitor();
    ~AuditMonitor();
    
    bool Initialize();
    void Shutdown();
    
    // Rule management
    bool AddAlertRule(const AlertRule& rule);
    bool RemoveAlertRule(const std::string& ruleId);
    std::vector<AlertRule> GetAlertRules();
    
    // Event processing
    void ProcessEvent(const AuditEvent& event);
    void ProcessEvents(const std::vector<AuditEvent>& events);
    
    // Handlers
    void SetAlertHandler(AlertHandler handler);
    void AddAnomalyDetector(AnomalyDetector detector);
    
    // Real-time analysis
    struct EventPattern {
        std::string patternId;
        std::vector<AuditEventType> sequence;
        uint64_t timeWindowMs;
        std::string description;
    };
    
    bool RegisterPattern(const EventPattern& pattern);
    std::vector<std::string> DetectPatterns(const std::vector<AuditEvent>& events);
    
private:
    std::vector<AlertRule> alertRules_;
    std::vector<AnomalyDetector> anomalyDetectors_;
    std::vector<EventPattern> patterns_;
    std::map<std::string, std::vector<AuditEvent>> eventWindows_;
    AlertHandler alertHandler_;
    mutable std::mutex mutex_;
    
    void CheckAlertRules(const AuditEvent& event);
    void CheckAnomalies(const AuditEvent& event);
};

// ============================================================================
// Audit Logger
// ============================================================================

class AuditLogger {
public:
    struct Config {
        std::map<std::string, std::string> storageConfig;
        std::string storageType = "file";  // "file", "database", "hybrid"
        
        bool enableTamperEvidence = true;
        std::string chainFile;
        
        bool enableEncryption = true;
        std::string encryptionKeyId;
        
        bool enableRealtimeMonitoring = true;
        bool enableComplianceChecking = true;
        bool enableRetention = true;
        
        std::vector<ComplianceFramework> complianceFrameworks;
        
        size_t batchSize = 100;
        uint64_t flushIntervalMs = 5000;
    };
    
    AuditLogger();
    ~AuditLogger();
    
    bool Initialize(const Config& config);
    void Shutdown();
    
    // Event logging
    bool LogEvent(const AuditEvent& event);
    bool LogEvent(AuditEventType type,
                   AuditSeverity severity,
                   const std::string& identityId,
                   const std::string& action,
                   bool success,
                   const std::map<std::string, std::string>& context = {});
    
    // Batch logging
    void LogEvents(const std::vector<AuditEvent>& events);
    void Flush();
    
    // Query
    std::vector<AuditEvent> QueryEvents(const AuditFilter& filter);
    size_t CountEvents(const AuditFilter& filter);
    
    // Export
    bool ExportEvents(const AuditFilter& filter, const std::string& format,
                      const std::string& path);
    
    // Compliance
    ComplianceManager* GetComplianceManager() { return complianceManager_.get(); }
    RetentionManager* GetRetentionManager() { return retentionManager_.get(); }
    AuditMonitor* GetMonitor() { return monitor_.get(); }
    
    // Integrity
    bool VerifyIntegrity();
    std::vector<std::string> GetIntegrityViolations();
    
    // Status
    std::string GetStatusJson() const;
    
    // Convenience methods for common events
    void LogAuthentication(const std::string& identityId, bool success,
                           const std::string& method, const std::string& ip);
    void LogAuthorization(const std::string& identityId, const std::string& resource,
                          const std::string& action, bool granted);
    void LogDataAccess(const std::string& identityId, const std::string& resourceType,
                       const std::string& resourceId, const std::string& action);
    void LogSecurityAlert(const std::string& identityId, const std::string& alertType,
                          const std::string& description, AuditSeverity severity);
    void LogConfigurationChange(const std::string& identityId, const std::string& component,
                                const std::string& change);
    
private:
    Config config_;
    std::unique_ptr<IAuditStorage> storage_;
    std::unique_ptr<TamperEvidentChain> chain_;
    std::unique_ptr<ComplianceManager> complianceManager_;
    std::unique_ptr<RetentionManager> retentionManager_;
    std::unique_ptr<AuditMonitor> monitor_;
    
    std::vector<AuditEvent> batchBuffer_;
    mutable std::mutex mutex_;
    
    bool initialized_;
    
    void ProcessBatch();
    AuditEvent EnrichEvent(AuditEvent event);
    bool PersistEvent(const AuditEvent& event);
};

// ============================================================================
// Global Audit Logger Access
// ============================================================================

class AuditLoggerProvider {
public:
    static AuditLoggerProvider& Instance();
    
    void SetLogger(std::shared_ptr<AuditLogger> logger);
    AuditLogger* GetLogger();
    
private:
    AuditLoggerProvider() = default;
    std::shared_ptr<AuditLogger> logger_;
    std::mutex mutex_;
};

// Convenience macro for logging
#define AUDIT_LOG(type, severity, identity, action, success, ...) \
    do { \
        auto logger = Security::AuditLoggerProvider::Instance().GetLogger(); \
        if (logger) { \
            logger->LogEvent(type, severity, identity, action, success, ##__VA_ARGS__); \
        } \
    } while(0)

} // namespace Security
