// Phase N.3/5: Compliance Framework
// RawrXD Compliance - GDPR, SOC2, HIPAA controls

#pragma once

#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Enterprise {

// Compliance frameworks
enum class ComplianceFramework {
    GDPR,           // EU General Data Protection Regulation
    SOC2_TYPE1,     // Service Organization Control 2 Type 1
    SOC2_TYPE2,     // Service Organization Control 2 Type 2
    HIPAA,          // Health Insurance Portability and Accountability Act
    PCI_DSS,        // Payment Card Industry Data Security Standard
    ISO27001,       // Information Security Management
    CCPA,           // California Consumer Privacy Act
    FEDRAMP,        // Federal Risk and Authorization Management Program
    CUSTOM          // Custom compliance requirements
};

// Control categories
enum class ControlCategory {
    ACCESS_CONTROL,
    AUDIT_LOGGING,
    DATA_PROTECTION,
    INCIDENT_RESPONSE,
    NETWORK_SECURITY,
    VULNERABILITY_MANAGEMENT,
    CONFIGURATION_MANAGEMENT,
    IDENTITY_MANAGEMENT,
    ENCRYPTION,
    RETENTION,
    MONITORING
};

// Control implementation status
enum class ControlStatus {
    NOT_IMPLEMENTED,
    PARTIALLY_IMPLEMENTED,
    IMPLEMENTED,
    NOT_APPLICABLE,
    COMPENSATING_CONTROL
};

// Compliance control definition
struct ComplianceControl {
    std::string control_id;              // e.g., "GDPR-32", "SOC2-CC6.1"
    ComplianceFramework framework;
    ControlCategory category;
    std::string title;
    std::string description;
    std::vector<std::string> requirements;
    ControlStatus status;
    std::string implementation_details;
    std::string evidence_location;
    std::chrono::system_clock::time_point last_assessed;
    std::chrono::system_clock::time_point next_assessment;
    std::string responsible_party;
    std::vector<std::string> related_controls;
};

// Data classification levels
enum class DataClassification {
    PUBLIC,         // No restrictions
    INTERNAL,       // Internal use only
    CONFIDENTIAL,   // Sensitive business data
    RESTRICTED,     // Highly sensitive (PII, PHI, financial)
    CRITICAL        // Critical business data
};

// Data subject rights (GDPR)
enum class DataSubjectRight {
    ACCESS,         // Right to access personal data
    RECTIFICATION,  // Right to correct inaccurate data
    ERASURE,        // Right to be forgotten
    PORTABILITY,    // Right to data portability
    RESTRICTION,    // Right to restrict processing
    OBJECTION,      // Right to object to processing
    AUTOMATED_DECISIONING  // Right related to automated decision-making
};

// Data subject request
struct DataSubjectRequest {
    std::string request_id;
    std::string tenant_id;
    std::string user_id;
    DataSubjectRight right;
    std::string description;
    std::chrono::system_clock::time_point submitted_at;
    std::chrono::system_clock::time_point deadline;  // Usually 30 days
    std::string status;  // pending, in_progress, completed, rejected
    std::string result;
    std::string handled_by;
    std::chrono::system_clock::time_point completed_at;
};

// Privacy policy configuration
struct PrivacyPolicy {
    std::string version;
    std::string effective_date;
    std::string jurisdiction;
    std::vector<std::string> data_collected;
    std::vector<std::string> data_usage;
    std::vector<std::string> data_recipients;
    std::vector<std::string> retention_periods;
    std::vector<std::string> user_rights;
    std::string dpo_contact;
    std::string supervisory_authority;
};

// Consent record
struct ConsentRecord {
    std::string consent_id;
    std::string tenant_id;
    std::string user_id;
    std::string purpose;
    std::string mechanism;  // checkbox, explicit, implicit
    std::chrono::system_clock::time_point granted_at;
    std::chrono::system_clock::time_point expires_at;
    bool withdrawn;
    std::chrono::system_clock::time_point withdrawn_at;
    std::string ip_address;
    std::string user_agent;
    std::string privacy_policy_version;
};

// Compliance manager
class ComplianceManager {
public:
    ComplianceManager();
    ~ComplianceManager();
    
    // Initialization
    bool Initialize(const std::string& config_path);
    void Shutdown();
    
    // Framework management
    bool EnableFramework(ComplianceFramework framework);
    bool DisableFramework(ComplianceFramework framework);
    bool IsFrameworkEnabled(ComplianceFramework framework) const;
    std::vector<ComplianceFramework> GetEnabledFrameworks() const;
    
    // Control management
    bool AddControl(const ComplianceControl& control);
    bool UpdateControl(const std::string& control_id, const ComplianceControl& control);
    bool RemoveControl(const std::string& control_id);
    std::optional<ComplianceControl> GetControl(const std::string& control_id) const;
    std::vector<ComplianceControl> GetControls(ComplianceFramework framework) const;
    std::vector<ComplianceControl> GetControls(ControlCategory category) const;
    
    // Control assessment
    bool AssessControl(const std::string& control_id, ControlStatus status,
                       const std::string& evidence);
    std::vector<ComplianceControl> GetOverdueControls() const;
    std::vector<ComplianceControl> GetFailedControls() const;
    
    // Data classification
    bool ClassifyData(const std::string& data_id, DataClassification classification);
    DataClassification GetDataClassification(const std::string& data_id) const;
    bool ApplyDataProtection(const std::string& data_id, DataClassification classification);
    
    // Data subject rights
    std::string SubmitDataSubjectRequest(const DataSubjectRequest& request);
    bool ProcessDataSubjectRequest(const std::string& request_id);
    std::optional<DataSubjectRequest> GetDataSubjectRequest(const std::string& request_id) const;
    std::vector<DataSubjectRequest> GetPendingDataSubjectRequests() const;
    bool FulfillAccessRequest(const std::string& request_id, std::string& output_path);
    bool FulfillErasureRequest(const std::string& request_id);
    bool FulfillPortabilityRequest(const std::string& request_id, std::string& output_path);
    
    // Consent management
    bool RecordConsent(const ConsentRecord& consent);
    bool WithdrawConsent(const std::string& consent_id);
    bool HasValidConsent(const std::string& user_id, const std::string& purpose) const;
    std::vector<ConsentRecord> GetUserConsents(const std::string& user_id) const;
    
    // Privacy policy
    bool SetPrivacyPolicy(const PrivacyPolicy& policy);
    PrivacyPolicy GetPrivacyPolicy() const;
    bool ValidatePrivacyPolicy() const;
    
    // Reporting
    struct ComplianceReport {
        std::chrono::system_clock::time_point generated_at;
        std::vector<ComplianceFramework> frameworks;
        uint32_t total_controls;
        uint32_t implemented_controls;
        uint32_t partially_implemented_controls;
        uint32_t failed_controls;
        float compliance_score;
        std::vector<std::string> gaps;
        std::vector<std::string> recommendations;
    };
    ComplianceReport GenerateReport(
        const std::vector<ComplianceFramework>& frameworks) const;
    
    // Evidence collection
    bool CollectEvidence(const std::string& control_id, const std::string& evidence_path);
    std::vector<std::string> GetEvidence(const std::string& control_id) const;
    
    // Automated compliance checks
    bool RunAutomatedChecks();
    std::vector<std::string> GetComplianceViolations() const;
    
    // Export for auditors
    bool ExportForAudit(const std::string& output_path,
                         const std::vector<ComplianceFramework>& frameworks);
    
private:
    std::unordered_map<std::string, ComplianceControl> controls_;
    std::unordered_map<ComplianceFramework, bool> enabled_frameworks_;
    std::unordered_map<std::string, DataClassification> data_classifications_;
    std::unordered_map<std::string, DataSubjectRequest> data_subject_requests_;
    std::unordered_map<std::string, ConsentRecord> consent_records_;
    PrivacyPolicy privacy_policy_;
    mutable std::shared_mutex mutex_;
    bool initialized_ = false;
    
    bool ValidateControl(const ComplianceControl& control) const;
    std::string GenerateControlId(ComplianceFramework framework, uint32_t number);
};

// Data protection utilities
namespace DataProtection {
    // PII detection
    bool ContainsPII(const std::string& text);
    std::vector<std::string> ExtractPII(const std::string& text);
    std::string MaskPII(const std::string& text);
    
    // Encryption
    std::string EncryptField(const std::string& plaintext, const std::string& key);
    std::string DecryptField(const std::string& ciphertext, const std::string& key);
    
    // Tokenization
    std::string Tokenize(const std::string& sensitive_data, const std::string& token_vault);
    std::string Detokenize(const std::string& token, const std::string& token_vault);
    
    // Anonymization
    std::string Anonymize(const std::string& data, DataClassification classification);
    
    // Retention
    bool ShouldDelete(const std::chrono::system_clock::time_point& created_at,
                      const std::chrono::hours& retention_period);
}

// Retention policy
struct RetentionPolicy {
    DataClassification classification;
    std::chrono::hours retention_period;
    std::chrono::hours archive_after;
    bool auto_delete;
    bool require_approval_for_deletion;
    std::vector<std::string> legal_holds;
};

// Retention manager
class RetentionManager {
public:
    bool Initialize(const std::vector<RetentionPolicy>& policies);
    
    bool SetPolicy(DataClassification classification, const RetentionPolicy& policy);
    std::optional<RetentionPolicy> GetPolicy(DataClassification classification) const;
    
    bool ApplyRetention(const std::string& data_id, DataClassification classification);
    bool ArchiveData(const std::string& data_id);
    bool DeleteData(const std::string& data_id);
    
    std::vector<std::string> GetExpiredData() const;
    std::vector<std::string> GetDataForArchival() const;
    
    // Legal hold
    bool PlaceLegalHold(const std::string& data_id, const std::string& reason);
    bool RemoveLegalHold(const std::string& data_id);
    bool IsUnderLegalHold(const std::string& data_id) const;
    
private:
    std::unordered_map<DataClassification, RetentionPolicy> policies_;
    std::unordered_map<std::string, std::vector<std::string>> legal_holds_;
};

// Breach notification
struct BreachNotification {
    std::string breach_id;
    std::chrono::system_clock::time_point detected_at;
    std::chrono::system_clock::time_point occurred_at;
    std::string description;
    DataClassification data_classification;
    uint32_t affected_users;
    std::vector<std::string> affected_tenants;
    std::string severity;
    bool notified_authorities;
    std::chrono::system_clock::time_point authority_notification_time;
    bool notified_users;
    std::chrono::system_clock::time_point user_notification_time;
    std::string remediation_actions;
};

class BreachNotificationManager {
public:
    bool RecordBreach(const BreachNotification& breach);
    bool NotifyAuthorities(const std::string& breach_id);
    bool NotifyUsers(const std::string& breach_id);
    
    // GDPR: 72 hours to notify authorities
    std::vector<BreachNotification> GetPendingAuthorityNotifications() const;
    
    // Check notification requirements
    bool RequiresAuthorityNotification(const BreachNotification& breach) const;
    bool RequiresUserNotification(const BreachNotification& breach) const;
    
private:
    std::unordered_map<std::string, BreachNotification> breaches_;
};

// Global compliance configuration
extern std::unique_ptr<ComplianceManager> g_compliance_manager;
extern std::unique_ptr<RetentionManager> g_retention_manager;
extern std::unique_ptr<BreachNotificationManager> g_breach_manager;

// Initialize compliance
bool InitializeCompliance(const std::string& config_path);
void ShutdownCompliance();
bool IsComplianceEnabled();

// Framework-specific helpers
namespace GDPR {
    bool ValidateDataProcessing(const std::string& purpose, const std::string& legal_basis);
    bool RequiresDPO();
    std::string GeneratePrivacyNotice();
}

namespace SOC2 {
    bool ValidateTrustServiceCriteria(ControlCategory category);
    std::vector<std::string> GetRequiredEvidence(ControlCategory category);
}

namespace HIPAA {
    bool IsPHI(const std::string& data);
    bool ValidateSafeguards(ControlCategory category);
}

} // namespace Enterprise
} // namespace RawrXD
