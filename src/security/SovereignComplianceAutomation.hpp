// Phase D.7 Batch 3/5: Compliance Automation
// SOC2, GDPR, HIPAA Controls and Evidence Collection
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>

namespace Sovereign {
namespace Security {

// ============================================================================
// Compliance Frameworks
// ============================================================================

enum class ComplianceFramework {
    SOC2 = 0,
    GDPR = 1,
    HIPAA = 2,
    PCI_DSS = 3,
    ISO27001 = 4,
    NIST = 5,
    CUSTOM = 6
};

enum class ControlStatus {
    NOT_IMPLEMENTED = 0,
    PARTIALLY_IMPLEMENTED = 1,
    IMPLEMENTED = 2,
    TESTED = 3,
    COMPLIANT = 4,
    NON_COMPLIANT = 5
};

struct ComplianceControl {
    std::string control_id;
    std::string framework;
    std::string category;
    std::string description;
    std::string implementation_details;
    ControlStatus status = ControlStatus::NOT_IMPLEMENTED;
    std::vector<std::string> evidence_requirements;
    std::vector<std::string> automated_checks;
    std::chrono::steady_clock::time_point last_tested;
    std::chrono::steady_clock::time_point next_due;
    std::string owner;
    int priority = 0;
};

struct ComplianceEvidence {
    std::string evidence_id;
    std::string control_id;
    std::string type;  // "log", "config", "scan", "manual", "test"
    std::string source;
    std::string data;
    std::string hash;
    std::chrono::steady_clock::time_point collected_at;
    std::string collected_by;
    int retention_days = 2555;  // 7 years default
    bool immutable = true;
};

// ============================================================================
// Control Assessment
// ============================================================================

class ControlAssessor {
public:
    struct Config {
        int assessment_interval_hours = 168;  // Weekly
        bool auto_remediate = false;
        int evidence_retention_days = 2555;
        bool require_manual_review = true;
    };
    
    struct AssessmentResult {
        std::string control_id;
        ControlStatus previous_status;
        ControlStatus new_status;
        bool status_changed = false;
        std::vector<std::string> findings;
        std::vector<std::string> evidence_ids;
        std::chrono::steady_clock::time_point assessed_at;
        std::string assessed_by;
        double compliance_score = 0.0;
    };
    
    explicit ControlAssessor(const Config& config);
    
    bool Initialize();
    
    // Control management
    bool RegisterControl(const ComplianceControl& control);
    bool UpdateControl(const std::string& control_id, const ComplianceControl& control);
    bool DeleteControl(const std::string& control_id);
    ComplianceControl GetControl(const std::string& control_id) const;
    std::vector<ComplianceControl> GetControls(ComplianceFramework framework) const;
    
    // Assessment
    AssessmentResult AssessControl(const std::string& control_id);
    std::vector<AssessmentResult> AssessAllControls();
    std::vector<AssessmentResult> AssessFramework(ComplianceFramework framework);
    
    // Evidence collection
    std::string CollectEvidence(const std::string& control_id, 
                                const std::string& evidence_type);
    bool ValidateEvidence(const std::string& evidence_id);
    ComplianceEvidence GetEvidence(const std::string& evidence_id) const;
    
    // Compliance scoring
    double CalculateComplianceScore(ComplianceFramework framework);
    std::map<std::string, double> CalculateCategoryScores(ComplianceFramework framework);
    
    // Reporting
    struct ComplianceReport {
        ComplianceFramework framework;
        double overall_score = 0.0;
        int total_controls = 0;
        int compliant_controls = 0;
        int non_compliant_controls = 0;
        int not_implemented = 0;
        std::vector<std::string> critical_findings;
        std::chrono::steady_clock::time_point generated_at;
    };
    
    ComplianceReport GenerateReport(ComplianceFramework framework);
    
private:
    Config config_;
    
    mutable std::mutex controls_mutex_;
    std::map<std::string, ComplianceControl> controls_;
    
    mutable std::mutex evidence_mutex_;
    std::map<std::string, ComplianceEvidence> evidence_;
    
    AssessmentResult RunAutomatedChecks(const ComplianceControl& control);
    std::string HashEvidence(const std::string& data);
};

// ============================================================================
// Policy Enforcer
// ============================================================================

class PolicyEnforcer {
public:
    struct Config {
        bool enforce_in_realtime = true;
        int violation_threshold = 3;
        bool auto_remediate = false;
        std::vector<std::string> exempt_services;
    };
    
    struct PolicyViolation {
        std::string violation_id;
        std::string policy_id;
        std::string resource_id;
        std::string violation_type;
        std::string description;
        std::map<std::string, std::string> details;
        std::chrono::steady_clock::time_point detected_at;
        bool remediated = false;
        std::chrono::steady_clock::time_point remediated_at;
        std::string remediation_action;
    };
    
    struct SecurityPolicy {
        std::string policy_id;
        std::string name;
        std::string description;
        std::string resource_type;
        std::map<std::string, std::string> required_settings;
        std::vector<std::string> forbidden_settings;
        bool enabled = true;
        int severity = 0;  // 0=info, 1=low, 2=medium, 3=high, 4=critical
    };
    
    explicit PolicyEnforcer(const Config& config);
    
    bool Initialize();
    
    // Policy management
    bool CreatePolicy(const SecurityPolicy& policy);
    bool UpdatePolicy(const std::string& policy_id, const SecurityPolicy& policy);
    bool DeletePolicy(const std::string& policy_id);
    std::vector<SecurityPolicy> GetPolicies() const;
    
    // Enforcement
    std::vector<PolicyViolation> EvaluateResource(const std::string& resource_id,
                                                   const std::map<std::string, std::string>& config);
    bool RemediateViolation(const std::string& violation_id);
    
    // Violation tracking
    std::vector<PolicyViolation> GetActiveViolations() const;
    std::vector<PolicyViolation> GetViolationHistory(int limit = 100) const;
    
private:
    Config config_;
    
    mutable std::mutex policies_mutex_;
    std::map<std::string, SecurityPolicy> policies_;
    
    mutable std::mutex violations_mutex_;
    std::vector<PolicyViolation> violations_;
    
    bool CheckPolicy(const SecurityPolicy& policy, 
                     const std::map<std::string, std::string>& config,
                     PolicyViolation& violation);
    bool ApplyRemediation(const PolicyViolation& violation);
};

// ============================================================================
// Data Classification
// ============================================================================

enum class DataClassification {
    PUBLIC = 0,
    INTERNAL = 1,
    CONFIDENTIAL = 2,
    RESTRICTED = 3
};

class DataClassifier {
public:
    struct Config {
        bool enable_auto_classification = true;
        int scan_interval_hours = 24;
        std::vector<std::string> pii_patterns;
        std::vector<std::string> phi_patterns;
        std::vector<std::string> pci_patterns;
    };
    
    struct ClassificationResult {
        std::string resource_id;
        DataClassification classification;
        double confidence = 0.0;
        std::vector<std::string> detected_patterns;
        std::vector<std::string> recommendations;
        std::chrono::steady_clock::time_point classified_at;
    };
    
    explicit DataClassifier(const Config& config);
    
    bool Initialize();
    
    // Classification
    ClassificationResult ClassifyData(const std::string& resource_id,
                                       const std::string& data);
    std::vector<ClassificationResult> ScanResources(const std::vector<std::string>& resource_ids);
    
    // Pattern management
    bool AddPattern(const std::string& pattern_type, const std::string& pattern);
    bool RemovePattern(const std::string& pattern_type, const std::string& pattern);
    
    // Retention policies
    struct RetentionPolicy {
        DataClassification classification;
        int retention_days = 2555;
        bool encryption_required = true;
        std::vector<std::string> allowed_regions;
        bool backup_required = true;
    };
    
    bool SetRetentionPolicy(const RetentionPolicy& policy);
    RetentionPolicy GetRetentionPolicy(DataClassification classification) const;
    
private:
    Config config_;
    
    std::map<DataClassification, RetentionPolicy> retention_policies_;
    mutable std::mutex policies_mutex_;
    
    bool MatchesPattern(const std::string& data, const std::string& pattern);
    DataClassification DetermineClassification(const std::vector<std::string>& matches);
};

// ============================================================================
// Compliance Runtime
// ============================================================================

class ComplianceRuntime {
public:
    struct Config {
        ControlAssessor::Config assessor;
        PolicyEnforcer::Config enforcer;
        DataClassifier::Config classifier;
        std::vector<ComplianceFramework> active_frameworks;
    };
    
    explicit ComplianceRuntime(const Config& config);
    ~ComplianceRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Framework management
    bool EnableFramework(ComplianceFramework framework);
    bool DisableFramework(ComplianceFramework framework);
    std::vector<ComplianceFramework> GetActiveFrameworks() const;
    
    // Control operations
    bool RegisterControl(const ComplianceControl& control);
    bool AssessControl(const std::string& control_id);
    std::vector<ControlAssessor::AssessmentResult> AssessAll();
    
    // Evidence
    std::string CollectEvidence(const std::string& control_id);
    std::vector<ComplianceEvidence> GetEvidenceForControl(const std::string& control_id) const;
    
    // Reporting
    ControlAssessor::ComplianceReport GenerateReport(ComplianceFramework framework);
    std::map<ComplianceFramework, ControlAssessor::ComplianceReport> GenerateAllReports();
    
    // Data protection
    DataClassifier::ClassificationResult ClassifyData(const std::string& resource_id,
                                                        const std::string& data);
    bool EnforceRetentionPolicy(const std::string& resource_id);
    
    // Access subsystems
    ControlAssessor* GetAssessor();
    PolicyEnforcer* GetEnforcer();
    DataClassifier* GetClassifier();
    
private:
    Config config_;
    std::unique_ptr<ControlAssessor> assessor_;
    std::unique_ptr<PolicyEnforcer> enforcer_;
    std::unique_ptr<DataClassifier> classifier_;
};

} // namespace Security
} // namespace Sovereign
