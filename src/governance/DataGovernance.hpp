/**
 * DataGovernance.hpp
 *
 * Phase S Batch 1/5: Data Governance
 *
 * Data classification, retention policies, lineage tracking,
 * and quality management for enterprise compliance.
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

class DataClassifier;
class RetentionManager;
class LineageTracker;
class QualityManager;

// ============================================================================
// Data Classification Levels
// ============================================================================

enum class ClassificationLevel {
    PUBLIC,           // No restrictions
    INTERNAL,         // Internal use only
    CONFIDENTIAL,     // Sensitive business data
    RESTRICTED,       // Highly sensitive data
    CRITICAL          // Critical business data
};

std::string ClassificationToString(ClassificationLevel level);
ClassificationLevel ClassificationFromString(const std::string& str);

// ============================================================================
// Data Classifier
// ============================================================================

class DataClassifier {
public:
    struct Config {
        bool enableAutoClassification = true;
        bool enableMLBasedClassification = false;
        std::chrono::seconds scanInterval{3600};
        uint32_t maxConcurrentScans = 5;
    };
    
    struct ClassificationRule {
        std::string ruleId;
        std::string name;
        std::string description;
        ClassificationLevel level;
        std::vector<std::string> patterns;  // Regex patterns
        std::vector<std::string> keywords;
        std::vector<std::string> fileExtensions;
        std::optional<std::string> contentType;
        uint32_t confidenceThreshold = 80;  // Percentage
        bool enabled = true;
    };
    
    struct ClassificationResult {
        std::string dataId;
        ClassificationLevel level;
        uint32_t confidence;
        std::string matchedRule;
        std::vector<std::string> matchedPatterns;
        std::chrono::system_clock::time_point classifiedAt;
        std::optional<std::string> classifiedBy;
        bool autoClassified;
    };
    
    explicit DataClassifier(const Config& config);
    
    // Rule management
    void AddRule(const ClassificationRule& rule);
    void UpdateRule(const std::string& ruleId, const ClassificationRule& rule);
    void RemoveRule(const std::string& ruleId);
    void EnableRule(const std::string& ruleId);
    void DisableRule(const std::string& ruleId);
    std::vector<ClassificationRule> GetRules() const;
    
    // Classification
    ClassificationResult Classify(const std::string& dataId,
                                   const std::vector<uint8_t>& content);
    ClassificationResult Classify(const std::string& dataId,
                                   const std::string& content);
    void ClassifyAsync(const std::string& dataId,
                       const std::vector<uint8_t>& content,
                       std::function<void(const ClassificationResult&)> callback);
    
    // Batch classification
    std::vector<ClassificationResult> ClassifyBatch(
        const std::vector<std::pair<std::string, std::vector<uint8_t>>>& items);
    
    // Manual classification
    void SetClassification(const std::string& dataId,
                          ClassificationLevel level,
                          const std::string& reason);
    
    // Reclassification
    void Reclassify(const std::string& dataId);
    void ReclassifyAll();
    
    // Scanning
    void StartScan(const std::string& path);
    void StopScan(const std::string& scanId);
    std::vector<std::string> GetActiveScans() const;
    
    // Statistics
    struct ClassifierStats {
        uint64_t itemsClassified;
        uint64_t autoClassified;
        uint64_t manuallyClassified;
        std::map<ClassificationLevel, uint64_t> byLevel;
        double averageConfidence;
        uint64_t reclassifications;
    };
    ClassifierStats GetStats() const;
    
private:
    Config config_;
    std::map<std::string, ClassificationRule> rules_;
    mutable std::mutex rulesMutex_;
    
    std::map<std::string, ClassificationResult> classifications_;
    mutable std::mutex classificationsMutex_;
    
    ClassifierStats stats_;
    mutable std::mutex statsMutex_;
    
    ClassificationResult ApplyRules(const std::string& dataId,
                                     const std::string& content);
    uint32_t CalculateConfidence(const std::vector<std::string>& matches,
                                  size_t totalPatterns) const;
};

// ============================================================================
// Retention Policy
// ============================================================================

class RetentionManager {
public:
    struct RetentionPolicy {
        std::string policyId;
        std::string name;
        std::string description;
        ClassificationLevel appliesTo;
        std::optional<std::string> dataType;
        std::optional<std::string> tenantId;
        
        // Retention rules
        std::chrono::days retentionPeriod{2555};  // 7 years default
        std::optional<std::chrono::days> archiveAfter;
        bool deleteAfterRetention = false;
        bool requireApprovalForDeletion = true;
        
        // Legal hold
        bool allowLegalHold = true;
        
        // Exceptions
        std::vector<std::string> exemptPaths;
        std::vector<std::string> exemptDataTypes;
        
        bool enabled = true;
        std::chrono::system_clock::time_point createdAt;
        std::chrono::system_clock::time_point updatedAt;
    };
    
    struct RetentionRecord {
        std::string dataId;
        std::string policyId;
        ClassificationLevel classification;
        std::chrono::system_clock::time_point createdAt;
        std::chrono::system_clock::time_point retentionExpiresAt;
        std::optional<std::chrono::system_clock::time_point> archivedAt;
        std::optional<std::chrono::system_clock::time_point> deletedAt;
        bool legalHold = false;
        std::optional<std::string> legalHoldReason;
        std::vector<std::string> tags;
    };
    
    explicit RetentionManager(const std::string& storagePath);
    ~RetentionManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Policy management
    void CreatePolicy(const RetentionPolicy& policy);
    void UpdatePolicy(const std::string& policyId, const RetentionPolicy& policy);
    void DeletePolicy(const std::string& policyId);
    std::optional<RetentionPolicy> GetPolicy(const std::string& policyId) const;
    std::vector<RetentionPolicy> GetPolicies() const;
    std::vector<RetentionPolicy> GetPoliciesForLevel(ClassificationLevel level) const;
    
    // Record management
    void RegisterData(const std::string& dataId,
                     const std::string& policyId,
                     ClassificationLevel classification);
    void UpdateRecord(const std::string& dataId, const RetentionRecord& record);
    std::optional<RetentionRecord> GetRecord(const std::string& dataId) const;
    
    // Legal hold
    void PlaceLegalHold(const std::string& dataId, const std::string& reason);
    void RemoveLegalHold(const std::string& dataId);
    bool IsUnderLegalHold(const std::string& dataId) const;
    std::vector<RetentionRecord> GetLegalHolds() const;
    
    // Retention actions
    std::vector<RetentionRecord> GetExpiredRecords() const;
    std::vector<RetentionRecord> GetRecordsForArchival() const;
    void ArchiveRecord(const std::string& dataId);
    void DeleteRecord(const std::string& dataId, bool force = false);
    
    // Policy enforcement
    void EnforcePolicies();
    void ScheduleEnforcement(std::chrono::hours interval);
    
    // Exceptions
    void GrantException(const std::string& dataId,
                       std::chrono::days extension,
                       const std::string& reason,
                       const std::string& approvedBy);
    
    // Compliance reporting
    struct RetentionReport {
        uint64_t totalRecords;
        uint64_t expiredRecords;
        uint64_t archivedRecords;
        uint64_t deletedRecords;
        uint64_t underLegalHold;
        std::map<std::string, uint64_t> byPolicy;
        std::chrono::system_clock::time_point generatedAt;
    };
    RetentionReport GenerateReport() const;
    
    // Export for audit
    std::string ExportRecords(const std::chrono::system_clock::time_point& from,
                             const std::chrono::system_clock::time_point& to) const;
    
private:
    std::string storagePath_;
    bool initialized_;
    
    std::map<std::string, RetentionPolicy> policies_;
    mutable std::mutex policiesMutex_;
    
    std::map<std::string, RetentionRecord> records_;
    mutable std::mutex recordsMutex_;
    
    std::thread enforcementThread_;
    std::atomic<bool> stopEnforcement_;
    
    void EnforcementLoop();
    void PersistRecords();
    void LoadRecords();
    RetentionPolicy FindApplicablePolicy(ClassificationLevel level,
                                         const std::optional<std::string>& dataType) const;
};

// ============================================================================
// Lineage Tracker
// ============================================================================

class LineageTracker {
public:
    enum class OperationType {
        CREATE,
        READ,
        UPDATE,
        DELETE,
        TRANSFORM,
        COPY,
        MOVE,
        MERGE,
        SPLIT,
        AGGREGATE,
        EXPORT,
        IMPORT
    };
    
    struct LineageNode {
        std::string nodeId;
        std::string dataId;
        std::string dataName;
        std::string dataType;
        std::optional<std::string> schema;
        std::chrono::system_clock::time_point createdAt;
        std::map<std::string, std::string> metadata;
    };
    
    struct LineageEdge {
        std::string edgeId;
        std::string sourceNodeId;
        std::string targetNodeId;
        OperationType operation;
        std::string operationDetails;
        std::chrono::system_clock::time_point timestamp;
        std::optional<std::string> userId;
        std::optional<std::string> processId;
        std::map<std::string, std::string> metadata;
    };
    
    struct DataLineage {
        LineageNode root;
        std::vector<LineageNode> upstream;   // Sources
        std::vector<LineageNode> downstream; // Destinations
        std::vector<LineageEdge> edges;
    };
    
    explicit LineageTracker(const std::string& storagePath);
    ~LineageTracker();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Node registration
    std::string RegisterNode(const LineageNode& node);
    void UpdateNode(const std::string& nodeId, const LineageNode& node);
    void RemoveNode(const std::string& nodeId);
    std::optional<LineageNode> GetNode(const std::string& nodeId) const;
    
    // Edge registration
    std::string RegisterEdge(const LineageEdge& edge);
    void RemoveEdge(const std::string& edgeId);
    std::vector<LineageEdge> GetEdgesForNode(const std::string& nodeId) const;
    
    // Lineage queries
    DataLineage GetLineage(const std::string& dataId) const;
    std::vector<LineageNode> GetUpstream(const std::string& dataId,
                                          uint32_t depth = 10) const;
    std::vector<LineageNode> GetDownstream(const std::string& dataId,
                                          uint32_t depth = 10) const;
    std::vector<LineageNode> GetImpact(const std::string& dataId) const;
    
    // Impact analysis
    std::vector<std::string> GetAffectedDatasets(const std::string& sourceId,
                                                   const std::chrono::system_clock::time_point& since) const;
    
    // Schema evolution
    void RecordSchemaChange(const std::string& dataId,
                           const std::string& oldSchema,
                           const std::string& newSchema,
                           const std::string& changeDescription);
    std::vector<std::pair<std::string, std::string>> GetSchemaHistory(const std::string& dataId) const;
    
    // Data quality lineage
    void RecordQualityMetric(const std::string& dataId,
                            const std::string& metricName,
                            double value,
                            const std::chrono::system_clock::time_point& timestamp);
    
    // Visualization
    std::string ExportToGraphviz(const std::string& dataId) const;
    std::string ExportToJSON(const std::string& dataId) const;
    
    // Statistics
    struct LineageStats {
        uint64_t totalNodes;
        uint64_t totalEdges;
        uint64_t operationsByType[12];  // One per OperationType
        std::chrono::system_clock::time_point oldestNode;
        std::chrono::system_clock::time_point newestNode;
    };
    LineageStats GetStats() const;
    
private:
    std::string storagePath_;
    bool initialized_;
    
    std::map<std::string, LineageNode> nodes_;
    mutable std::mutex nodesMutex_;
    
    std::map<std::string, LineageEdge> edges_;
    mutable std::mutex edgesMutex_;
    
    std::map<std::string, std::vector<std::string>> adjacencyList_;
    mutable std::mutex graphMutex_;
    
    void BuildGraph();
    void TraverseUpstream(const std::string& nodeId,
                         std::vector<LineageNode>& result,
                         uint32_t depth,
                         std::set<std::string>& visited) const;
    void TraverseDownstream(const std::string& nodeId,
                           std::vector<LineageNode>& result,
                           uint32_t depth,
                           std::set<std::string>& visited) const;
    void PersistGraph();
    void LoadGraph();
};

// ============================================================================
// Quality Manager
// ============================================================================

class QualityManager {
public:
    enum class QualityDimension {
        COMPLETENESS,
        ACCURACY,
        CONSISTENCY,
        TIMELINESS,
        VALIDITY,
        UNIQUENESS
    };
    
    struct QualityRule {
        std::string ruleId;
        std::string name;
        std::string description;
        QualityDimension dimension;
        std::string dataType;
        std::string expression;  // Validation expression
        double threshold;  // Minimum acceptable score (0-100)
        bool enabled = true;
        bool blocking = false;  // Block processing if failed
    };
    
    struct QualityScore {
        std::string dataId;
        std::chrono::system_clock::time_point timestamp;
        double overallScore;
        std::map<QualityDimension, double> dimensionScores;
        std::vector<std::string> failedRules;
        std::vector<std::string> warnings;
        bool passed;
    };
    
    struct QualityIssue {
        std::string issueId;
        std::string dataId;
        std::string ruleId;
        QualityDimension dimension;
        std::string description;
        std::string severity;  // critical, high, medium, low
        std::chrono::system_clock::time_point detectedAt;
        bool resolved;
        std::optional<std::chrono::system_clock::time_point> resolvedAt;
    };
    
    explicit QualityManager(const std::string& storagePath);
    ~QualityManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Rule management
    void AddRule(const QualityRule& rule);
    void UpdateRule(const std::string& ruleId, const QualityRule& rule);
    void RemoveRule(const std::string& ruleId);
    void EnableRule(const std::string& ruleId);
    void DisableRule(const std::string& ruleId);
    std::vector<QualityRule> GetRules() const;
    std::vector<QualityRule> GetRulesForDimension(QualityDimension dimension) const;
    
    // Quality assessment
    QualityScore AssessQuality(const std::string& dataId,
                              const std::map<std::string, std::any>& data);
    std::vector<QualityScore> AssessBatch(
        const std::vector<std::pair<std::string, std::map<std::string, std::any>>>& items);
    
    // Issue tracking
    std::string ReportIssue(const QualityIssue& issue);
    void ResolveIssue(const std::string& issueId);
    std::vector<QualityIssue> GetOpenIssues() const;
    std::vector<QualityIssue> GetIssuesForData(const std::string& dataId) const;
    
    // Monitoring
    void StartMonitoring(const std::string& dataId);
    void StopMonitoring(const std::string& dataId);
    std::vector<std::string> GetMonitoredDatasets() const;
    
    // Thresholds
    void SetThreshold(QualityDimension dimension, double threshold);
    double GetThreshold(QualityDimension dimension) const;
    
    // Reporting
    struct QualityReport {
        std::chrono::system_clock::time_point periodStart;
        std::chrono::system_clock::time_point periodEnd;
        double averageScore;
        std::map<QualityDimension, double> averageDimensionScores;
        uint64_t totalAssessments;
        uint64_t passedAssessments;
        uint64_t failedAssessments;
        uint64_t openIssues;
        std::vector<std::string> topIssues;
    };
    QualityReport GenerateReport(const std::chrono::system_clock::time_point& from,
                                const std::chrono::system_clock::time_point& to) const;
    
    // Alerts
    using QualityAlertHandler = std::function<void(const QualityIssue&)>;
    void OnQualityIssue(QualityAlertHandler handler);
    void OnScoreBelowThreshold(std::function<void(const std::string&, double)> handler);
    
private:
    std::string storagePath_;
    bool initialized_;
    
    std::map<std::string, QualityRule> rules_;
    mutable std::mutex rulesMutex_;
    
    std::map<std::string, QualityScore> scores_;
    mutable std::mutex scoresMutex_;
    
    std::map<std::string, QualityIssue> issues_;
    mutable std::mutex issuesMutex_;
    
    std::map<QualityDimension, double> thresholds_;
    mutable std::mutex thresholdsMutex_;
    
    std::set<std::string> monitoredDatasets_;
    mutable std::mutex monitoringMutex_;
    
    QualityAlertHandler onIssue_;
    std::function<void(const std::string&, double)> onBelowThreshold_;
    
    double EvaluateRule(const QualityRule& rule,
                       const std::map<std::string, std::any>& data);
    void RaiseIssue(const QualityIssue& issue);
    void CheckThresholds(const std::string& dataId, const QualityScore& score);
};

// ============================================================================
// Governance Manager
// ============================================================================

class GovernanceManager {
public:
    struct Config {
        std::string dataClassificationConfig;
        std::string retentionStoragePath;
        std::string lineageStoragePath;
        std::string qualityStoragePath;
        bool enableAutoEnforcement = true;
    };
    
    explicit GovernanceManager(const Config& config);
    ~GovernanceManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Component access
    DataClassifier* GetClassifier() { return classifier_.get(); }
    RetentionManager* GetRetentionManager() { return retention_.get(); }
    LineageTracker* GetLineageTracker() { return lineage_.get(); }
    QualityManager* GetQualityManager() { return quality_.get(); }
    
    // Unified data registration
    void RegisterData(const std::string& dataId,
                     const std::string& dataType,
                     const std::vector<uint8_t>& sample);
    
    // Compliance check
    struct ComplianceResult {
        bool compliant;
        std::vector<std::string> violations;
        std::vector<std::string> warnings;
        std::optional<std::string> requiredAction;
    };
    
    ComplianceResult CheckCompliance(const std::string& dataId) const;
    
    // Policy enforcement
    void EnforcePolicies();
    void EnforceForData(const std::string& dataId);
    
    // Audit
    struct AuditRecord {
        std::string recordId;
        std::string dataId;
        std::string action;
        std::string userId;
        std::chrono::system_clock::time_point timestamp;
        std::string result;
        std::map<std::string, std::string> details;
    };
    
    void LogAudit(const AuditRecord& record);
    std::vector<AuditRecord> GetAuditLog(const std::chrono::system_clock::time_point& from,
                                        const std::chrono::system_clock::time_point& to) const;
    
    // Dashboard
    struct GovernanceDashboard {
        uint64_t totalDatasets;
        uint64_t classifiedDatasets;
        std::map<ClassificationLevel, uint64_t> byClassification;
        uint64_t underRetentionPolicy;
        uint64_t underLegalHold;
        double averageQualityScore;
        uint64_t openQualityIssues;
        uint64_t lineageNodes;
        uint64_t lineageEdges;
    };
    GovernanceDashboard GetDashboard() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::unique_ptr<DataClassifier> classifier_;
    std::unique_ptr<RetentionManager> retention_;
    std::unique_ptr<LineageTracker> lineage_;
    std::unique_ptr<QualityManager> quality_;
    
    std::vector<AuditRecord> auditLog_;
    mutable std::mutex auditMutex_;
    
    void PersistAuditLog();
    void LoadAuditLog();
};

} // namespace Governance
