/**
 * AuditCompliance.hpp
 *
 * Phase S Batch 2/5: Audit & Compliance
 *
 * Comprehensive audit logging, compliance monitoring, and regulatory
 * reporting for enterprise governance.
 */

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace Governance {

// ============================================================================
// Forward Declarations
// ============================================================================

class AuditLogger;
class ComplianceMonitor;
class RegulatoryReporter;
class PolicyEnforcer;

// ============================================================================
// Audit Event Types
// ============================================================================

enum class AuditEventType {
    // Data Access
    DATA_READ,
    DATA_WRITE,
    DATA_DELETE,
    DATA_EXPORT,
    DATA_IMPORT,
    DATA_TRANSFORM,
    
    // Authentication
    USER_LOGIN,
    USER_LOGOUT,
    USER_AUTHENTICATION_FAILURE,
    PASSWORD_CHANGE,
    MFA_VERIFICATION,
    SESSION_EXPIRED,
    
    // Authorization
    PERMISSION_GRANTED,
    PERMISSION_REVOKED,
    ROLE_ASSIGNED,
    ROLE_REMOVED,
    ACCESS_DENIED,
    
    // System
    CONFIGURATION_CHANGE,
    SYSTEM_STARTUP,
    SYSTEM_SHUTDOWN,
    BACKUP_CREATED,
    RESTORE_PERFORMED,
    UPDATE_APPLIED,
    
    // Security
    SECURITY_ALERT,
    INTRUSION_DETECTED,
    POLICY_VIOLATION,
    ENCRYPTION_OPERATION,
    KEY_ROTATION,
    
    // Compliance
    POLICY_CHECK,
    COMPLIANCE_SCAN,
    VIOLATION_DETECTED,
    REMEDIATION_APPLIED
};

std::string AuditEventTypeToString(AuditEventType type);
AuditEventType AuditEventTypeFromString(const std::string& str);

// ============================================================================
// Audit Logger
// ============================================================================

class AuditLogger {
public:
    struct Config {
        std::string storagePath;
        size_t maxLogSize = 10 * 1024 * 1024 * 1024ULL; // 10GB
        uint32_t maxLogFiles = 10;
        bool encryptLogs = true;
        bool compressLogs = true;
        std::chrono::seconds retentionPeriod{7 * 24 * 60 * 60}; // 7 days
        bool immutableLogs = false;
        std::vector<AuditEventType> loggedEvents;
    };
    
    struct AuditEvent {
        std::string eventId;
        AuditEventType type;
        std::string severity; // info, warning, error, critical
        std::chrono::system_clock::time_point timestamp;
        std::string actorId;
        std::optional<std::string> actorIp;
        std::optional<std::string> sessionId;
        std::string resourceId;
        std::string resourceType;
        std::string action;
        std::optional<std::string> outcome;
        std::map<std::string, std::string> beforeState;
        std::map<std::string, std::string> afterState;
        std::map<std::string, std::string> metadata;
        std::optional<std::string> reason;
        std::optional<std::string> errorCode;
    };
    
    struct AuditQuery {
        std::optional<std::vector<AuditEventType>> types;
        std::optional<std::string> actorId;
        std::optional<std::string> resourceId;
        std::optional<std::chrono::system_clock::time_point> from;
        std::optional<std::chrono::system_clock::time_point> to;
        std::optional<std::string> severity;
        std::optional<std::map<std::string, std::string>> metadataFilter;
        uint32_t limit = 1000;
        uint32_t offset = 0;
    };
    
    explicit AuditLogger(const Config& config);
    ~AuditLogger();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Logging
    void Log(const AuditEvent& event);
    void Log(AuditEventType type,
             const std::string& actorId,
             const std::string& resourceId,
             const std::string& action);
    void LogAsync(const AuditEvent& event);
    
    // Querying
    std::vector<AuditEvent> Query(const AuditQuery& query) const;
    std::vector<AuditEvent> GetEventsForActor(const std::string& actorId,
                                               const std::chrono::system_clock::time_point& from,
                                               const std::chrono::system_clock::time_point& to) const;
    std::vector<AuditEvent> GetEventsForResource(const std::string& resourceId,
                                                const std::chrono::system_clock::time_point& from,
                                                const std::chrono::system_clock::time_point& to) const;
    
    // Aggregation
    std::map<AuditEventType, uint64_t> GetEventCounts(
        const std::chrono::system_clock::time_point& from,
        const std::chrono::system_clock::time_point& to) const;
    
    // Export
    std::string ExportToJson(const AuditQuery& query) const;
    std::string ExportToCsv(const AuditQuery& query) const;
    void ExportToSyslog(const AuditEvent& event) const;
    
    // Integrity
    std::string ComputeHash() const;
    bool VerifyIntegrity() const;
    void SignLog(const std::string& privateKey);
    bool VerifySignature(const std::string& publicKey) const;
    
    // Retention
    void ArchiveOldLogs(const std::chrono::system_clock::time_point& before);
    void PurgeOldLogs(const std::chrono::system_clock::time_point& before);
    
    // Statistics
    struct AuditStats {
        uint64_t totalEventsLogged;
        uint64_t eventsByType[25]; // One per AuditEventType
        uint64_t failedLogAttempts;
        size_t currentLogSize;
        uint32_t logFileCount;
        std::chrono::system_clock::time_point oldestEvent;
        std::chrono::system_clock::time_point newestEvent;
    };
    AuditStats GetStats() const;
    
    // Real-time monitoring
    using AuditEventHandler = std::function<void(const AuditEvent&)>;
    void SubscribeToEvents(AuditEventHandler handler);
    void SubscribeToEvents(AuditEventType type, AuditEventHandler handler);
    void SubscribeToSeverity(const std::string& severity, AuditEventHandler handler);
    
private:
    Config config_;
    bool initialized_;
    
    std::deque<AuditEvent> eventQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCv_;
    
    std::thread writerThread_;
    std::atomic<bool> stopWriter_;
    
    std::vector<std::pair<std::optional<AuditEventType>, AuditEventHandler>> subscribers_;
    mutable std::mutex subscribersMutex_;
    
    AuditStats stats_;
    mutable std::mutex statsMutex_;
    
    void WriterLoop();
    void FlushEvents();
    void WriteEvent(const AuditEvent& event);
    void NotifySubscribers(const AuditEvent& event);
    std::string SerializeEvent(const AuditEvent& event) const;
};

// ============================================================================
// Compliance Framework
// ============================================================================

enum class ComplianceFramework {
    SOC2,
    ISO27001,
    GDPR,
    HIPAA,
    PCI_DSS,
    NIST_CSF,
    CIS_CONTROLS,
    CUSTOM
};

std::string FrameworkToString(ComplianceFramework framework);
ComplianceFramework FrameworkFromString(const std::string& str);

// ============================================================================
// Compliance Monitor
// ============================================================================

class ComplianceMonitor {
public:
    struct ComplianceRule {
        std::string ruleId;
        std::string name;
        std::string description;
        ComplianceFramework framework;
        std::string controlId;
        std::string requirement;
        std::function<bool()> check;
        std::string severity;
        bool enabled;
        std::chrono::seconds checkInterval;
        std::optional<std::string> remediation;
    };
    
    struct ComplianceFinding {
        std::string findingId;
        std::string ruleId;
        ComplianceFramework framework;
        std::string severity;
        std::string status; // open, remediated, accepted_risk
        std::string description;
        std::chrono::system_clock::time_point detectedAt;
        std::optional<std::chrono::system_clock::time_point> remediatedAt;
        std::optional<std::string> remediationAction;
        std::map<std::string, std::string> evidence;
    };
    
    struct ComplianceScore {
        ComplianceFramework framework;
        double overallScore;
        uint32_t totalControls;
        uint32_t passedControls;
        uint32_t failedControls;
        uint32_t warningControls;
        std::chrono::system_clock::time_point calculatedAt;
    };
    
    explicit ComplianceMonitor(const std::string& storagePath);
    ~ComplianceMonitor();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Rule management
    void AddRule(const ComplianceRule& rule);
    void UpdateRule(const std::string& ruleId, const ComplianceRule& rule);
    void RemoveRule(const std::string& ruleId);
    void EnableRule(const std::string& ruleId);
    void DisableRule(const std::string& ruleId);
    std::vector<ComplianceRule> GetRules() const;
    std::vector<ComplianceRule> GetRulesForFramework(ComplianceFramework framework) const;
    
    // Compliance checking
    ComplianceFinding CheckRule(const std::string& ruleId);
    std::vector<ComplianceFinding> CheckAll();
    std::vector<ComplianceFinding> CheckFramework(ComplianceFramework framework);
    
    // Scheduled monitoring
    void StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const;
    void ScheduleCheck(const std::string& ruleId, std::chrono::seconds interval);
    
    // Findings management
    std::vector<ComplianceFinding> GetOpenFindings() const;
    std::vector<ComplianceFinding> GetFindingsForFramework(ComplianceFramework framework) const;
    void RemediateFinding(const std::string& findingId, const std::string& action);
    void AcceptRisk(const std::string& findingId, const std::string& justification);
    
    // Scoring
    ComplianceScore CalculateScore(ComplianceFramework framework) const;
    std::vector<ComplianceScore> CalculateAllScores() const;
    
    // Trends
    struct ComplianceTrend {
        ComplianceFramework framework;
        std::chrono::system_clock::time_point timestamp;
        double score;
        uint32_t openFindings;
    };
    std::vector<ComplianceTrend> GetTrends(ComplianceFramework framework,
                                          const std::chrono::system_clock::time_point& from,
                                          const std::chrono::system_clock::time_point& to) const;
    
    // Alerts
    using ComplianceAlertHandler = std::function<void(const ComplianceFinding&)>;
    void OnFindingDetected(ComplianceAlertHandler handler);
    void OnScoreBelowThreshold(std::function<void(ComplianceFramework, double)> handler);
    
    // Export
    std::string GenerateComplianceReport(ComplianceFramework framework) const;
    std::string GenerateEvidencePackage(ComplianceFramework framework) const;
    
private:
    std::string storagePath_;
    bool initialized_;
    bool monitoring_;
    
    std::map<std::string, ComplianceRule> rules_;
    mutable std::mutex rulesMutex_;
    
    std::map<std::string, ComplianceFinding> findings_;
    mutable std::mutex findingsMutex_;
    
    std::map<std::string, std::chrono::system_clock::time_point> lastChecks_;
    mutable std::mutex checksMutex_;
    
    std::thread monitorThread_;
    std::atomic<bool> stopMonitor_;
    
    ComplianceAlertHandler onFinding_;
    std::function<void(ComplianceFramework, double)> onBelowThreshold_;
    
    void MonitorLoop();
    void EvaluateRule(const ComplianceRule& rule);
    void RaiseFinding(const ComplianceFinding& finding);
    void CheckThresholds(ComplianceFramework framework, double score);
};

// ============================================================================
// Regulatory Reporter
// ============================================================================

class RegulatoryReporter {
public:
    struct ReportTemplate {
        std::string templateId;
        std::string name;
        ComplianceFramework framework;
        std::string description;
        std::vector<std::string> requiredDataSources;
        std::vector<std::string> sections;
        std::string format; // pdf, html, json
    };
    
    struct ReportSchedule {
        std::string scheduleId;
        std::string templateId;
        std::string name;
        std::string frequency; // daily, weekly, monthly, quarterly, annual
        std::optional<std::string> recipientEmail;
        std::optional<std::string> uploadEndpoint;
        bool enabled;
        std::chrono::system_clock::time_point lastRun;
        std::optional<std::chrono::system_clock::time_point> nextRun;
    };
    
    struct GeneratedReport {
        std::string reportId;
        std::string templateId;
        std::string name;
        ComplianceFramework framework;
        std::chrono::system_clock::time_point generatedAt;
        std::chrono::system_clock::time_point periodStart;
        std::chrono::system_clock::time_point periodEnd;
        std::string format;
        size_t fileSize;
        std::string checksum;
        std::optional<std::string> filePath;
        std::map<std::string, std::string> metadata;
    };
    
    explicit RegulatoryReporter(const std::string& storagePath);
    ~RegulatoryReporter();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Template management
    void AddTemplate(const ReportTemplate& tmpl);
    void UpdateTemplate(const std::string& templateId, const ReportTemplate& tmpl);
    void RemoveTemplate(const std::string& templateId);
    std::vector<ReportTemplate> GetTemplates() const;
    std::vector<ReportTemplate> GetTemplatesForFramework(ComplianceFramework framework) const;
    
    // Report generation
    GeneratedReport GenerateReport(const std::string& templateId,
                                   const std::chrono::system_clock::time_point& periodStart,
                                   const std::chrono::system_clock::time_point& periodEnd);
    std::future<GeneratedReport> GenerateReportAsync(const std::string& templateId,
                                                     const std::chrono::system_clock::time_point& periodStart,
                                                     const std::chrono::system_clock::time_point& periodEnd);
    
    // Scheduling
    void ScheduleReport(const ReportSchedule& schedule);
    void UpdateSchedule(const std::string& scheduleId, const ReportSchedule& schedule);
    void RemoveSchedule(const std::string& scheduleId);
    void EnableSchedule(const std::string& scheduleId);
    void DisableSchedule(const std::string& scheduleId);
    std::vector<ReportSchedule> GetSchedules() const;
    
    // Report management
    std::vector<GeneratedReport> GetReports() const;
    std::vector<GeneratedReport> GetReportsForFramework(ComplianceFramework framework) const;
    std::optional<GeneratedReport> GetReport(const std::string& reportId) const;
    bool DeleteReport(const std::string& reportId);
    std::optional<std::vector<uint8_t>> DownloadReport(const std::string& reportId) const;
    
    // Distribution
    void EmailReport(const std::string& reportId, const std::string& recipient);
    void UploadReport(const std::string& reportId, const std::string& endpoint);
    void ShareReport(const std::string& reportId, const std::vector<std::string>& users);
    
    // Validation
    bool ValidateReport(const std::string& reportId) const;
    std::vector<std::string> GetValidationErrors(const std::string& reportId) const;
    
private:
    std::string storagePath_;
    bool initialized_;
    
    std::map<std::string, ReportTemplate> templates_;
    mutable std::mutex templatesMutex_;
    
    std::map<std::string, ReportSchedule> schedules_;
    mutable std::mutex schedulesMutex_;
    
    std::map<std::string, GeneratedReport> reports_;
    mutable std::mutex reportsMutex_;
    
    std::thread schedulerThread_;
    std::atomic<bool> stopScheduler_;
    
    void SchedulerLoop();
    void ExecuteSchedule(const ReportSchedule& schedule);
    GeneratedReport GenerateReportInternal(const std::string& templateId,
                                          const std::chrono::system_clock::time_point& periodStart,
                                          const std::chrono::system_clock::time_point& periodEnd);
    std::string ComputeChecksum(const std::vector<uint8_t>& data) const;
};

// ============================================================================
// Policy Enforcer
// ============================================================================

class PolicyEnforcer {
public:
    struct Policy {
        std::string policyId;
        std::string name;
        std::string description;
        std::string type; // access, data, security, operational
        std::string condition; // Expression or rule
        std::string action; // allow, deny, audit, alert
        uint32_t priority;
        bool enabled;
        std::vector<std::string> appliesTo;
        std::chrono::system_clock::time_point createdAt;
        std::chrono::system_clock::time_point updatedAt;
    };
    
    struct PolicyViolation {
        std::string violationId;
        std::string policyId;
        std::string severity;
        std::string description;
        std::map<std::string, std::string> context;
        std::chrono::system_clock::time_point detectedAt;
        bool resolved;
        std::optional<std::chrono::system_clock::time_point> resolvedAt;
    };
    
    struct EnforcementResult {
        bool allowed;
        std::optional<std::string> policyId;
        std::optional<std::string> reason;
        bool audited;
        bool alerted;
    };
    
    explicit PolicyEnforcer(const std::string& storagePath);
    ~PolicyEnforcer();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Policy management
    void CreatePolicy(const Policy& policy);
    void UpdatePolicy(const std::string& policyId, const Policy& policy);
    void DeletePolicy(const std::string& policyId);
    void EnablePolicy(const std::string& policyId);
    void DisablePolicy(const std::string& policyId);
    std::optional<Policy> GetPolicy(const std::string& policyId) const;
    std::vector<Policy> GetPolicies() const;
    std::vector<Policy> GetPoliciesForType(const std::string& type) const;
    
    // Enforcement
    EnforcementResult Evaluate(const std::string& subject,
                               const std::string& resource,
                               const std::string& action,
                               const std::map<std::string, std::string>& context);
    
    // Violations
    void ReportViolation(const PolicyViolation& violation);
    std::vector<PolicyViolation> GetViolations() const;
    std::vector<PolicyViolation> GetOpenViolations() const;
    void ResolveViolation(const std::string& violationId, const std::string& resolution);
    
    // Bulk operations
    std::vector<EnforcementResult> EvaluateBatch(
        const std::vector<std::tuple<std::string, std::string, std::string, std::map<std::string, std::string>>>& requests);
    
    // Simulation
    EnforcementResult Simulate(const std::string& subject,
                              const std::string& resource,
                              const std::string& action,
                              const std::map<std::string, std::string>& context) const;
    
    // Statistics
    struct EnforcementStats {
        uint64_t totalEvaluations;
        uint64_t allowed;
        uint64_t denied;
        uint64_t violations;
        double averageEvaluationTimeMs;
    };
    EnforcementStats GetStats() const;
    
private:
    std::string storagePath_;
    bool initialized_;
    
    std::map<std::string, Policy> policies_;
    mutable std::mutex policiesMutex_;
    
    std::map<std::string, PolicyViolation> violations_;
    mutable std::mutex violationsMutex_;
    
    EnforcementStats stats_;
    mutable std::mutex statsMutex_;
    
    bool EvaluateCondition(const std::string& condition,
                          const std::map<std::string, std::string>& context);
    void ExecuteAction(const std::string& action,
                      const Policy& policy,
                      const std::map<std::string, std::string>& context);
};

// ============================================================================
// Governance Dashboard
// ============================================================================

struct GovernanceSummary {
    // Audit
    uint64_t totalAuditEvents;
    uint64_t auditEventsToday;
    std::chrono::system_clock::time_point lastAuditEvent;
    
    // Compliance
    std::map<ComplianceFramework, double> complianceScores;
    uint64_t openComplianceFindings;
    uint64_t criticalFindings;
    
    // Policies
    uint64_t totalPolicies;
    uint64_t enabledPolicies;
    uint64_t policyViolations;
    
    // Reports
    uint64_t reportsGenerated;
    std::chrono::system_clock::time_point lastReportGenerated;
    
    // Health
    bool auditSystemHealthy;
    bool complianceSystemHealthy;
    bool policySystemHealthy;
};

} // namespace Governance
