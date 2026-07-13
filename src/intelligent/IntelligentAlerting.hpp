// Phase Q.3/5: Intelligent Alerting System
// RawrXD Intelligent Alerting - Smart notification and escalation

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>

namespace RawrXD {
namespace Intelligent {

// Alert severity levels
enum class AlertSeverity {
    INFO,       // Informational
    WARNING,    // Attention needed
    ERROR,      // Action required
    CRITICAL,   // Immediate action required
    EMERGENCY   // System-wide impact
};

// Alert status
enum class AlertStatus {
    NEW,        // Just created
    ACKNOWLEDGED,  // Someone acknowledged
    IN_PROGRESS,   // Being worked on
    RESOLVED,      // Issue fixed
    SUPPRESSED,    // Silenced temporarily
    ESCALATED      // Escalated to higher level
};

// Alert channel types
enum class AlertChannel {
    EMAIL,
    SMS,
    SLACK,
    PAGERDUTY,
    WEBHOOK,
    IN_APP,
    MOBILE_PUSH,
    PHONE_CALL,
    CUSTOM
};

// Alert definition
struct Alert {
    std::string id;
    std::string title;
    std::string description;
    
    AlertSeverity severity;
    AlertStatus status;
    
    // Source
    std::string source;           // Component that generated
    std::string resource_id;      // Affected resource
    std::string anomaly_id;       // Related anomaly
    std::string remediation_id;   // Related remediation
    
    // Context
    std::unordered_map<std::string, std::string> labels;
    std::unordered_map<std::string, std::string> annotations;
    std::vector<std::string> related_alerts;
    
    // Timing
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point acknowledged_at;
    std::chrono::system_clock::time_point resolved_at;
    std::chrono::system_clock::time_point last_updated;
    
    // Acknowledgment
    std::string acknowledged_by;
    std::string resolution_notes;
    
    // Routing
    std::vector<std::string> assigned_teams;
    std::vector<std::string> assigned_users;
    
    // Suppression
    bool is_suppressed;
    std::chrono::system_clock::time_point suppressed_until;
    std::string suppression_reason;
};

// Alert rule
struct AlertRule {
    std::string id;
    std::string name;
    std::string description;
    
    // Conditions
    std::string condition_query;  // Query language for conditions
    std::vector<std::string> required_labels;
    std::vector<std::string> excluded_labels;
    
    // Severity mapping
    std::unordered_map<std::string, AlertSeverity> severity_conditions;
    
    // Routing
    std::vector<std::string> notify_teams;
    std::vector<std::string> notify_users;
    std::vector<AlertChannel> channels;
    
    // Timing
    std::chrono::seconds evaluation_interval;
    std::chrono::seconds cooldown_period;  // Don't re-alert
    uint32_t max_alerts_per_hour;
    
    // Grouping
    bool group_alerts;
    std::string group_by;  // Field to group by
    std::chrono::seconds group_window;
    
    // Escalation
    std::string escalation_policy_id;
    
    // State
    bool enabled;
    std::chrono::system_clock::time_point last_evaluated;
    uint32_t alert_count;
};

// Notification template
struct NotificationTemplate {
    std::string id;
    std::string name;
    AlertChannel channel;
    
    // Template content
    std::string subject_template;
    std::string body_template;
    std::unordered_map<std::string, std::string> channel_specific;
    
    // Formatting
    bool include_context;
    bool include_runbook_links;
    bool include_dashboard_links;
    uint32_t max_related_alerts;
};

// Escalation policy
struct EscalationPolicy {
    std::string id;
    std::string name;
    std::string description;
    
    struct EscalationLevel {
        uint32_t level;
        std::chrono::minutes delay;  // Time before escalating
        std::vector<std::string> notify_teams;
        std::vector<std::string> notify_users;
        std::vector<AlertChannel> channels;
        bool require_acknowledgment;
        std::chrono::minutes acknowledgment_timeout;
    };
    
    std::vector<EscalationLevel> levels;
    bool repeat_escalation;  // Repeat from level 1 if no response
    uint32_t max_repeats;
    
    // Auto-escalation
    bool auto_escalate_on_no_ack;
    std::chrono::minutes auto_escalate_delay;
};

// Alert correlation
struct CorrelationRule {
    std::string id;
    std::string name;
    std::string description;
    
    // Pattern matching
    std::vector<std::string> alert_patterns;  // Regex patterns
    std::vector<std::string> required_labels;
    
    // Time window
    std::chrono::seconds time_window;
    uint32_t min_alert_count;
    
    // Correlation type
    enum class CorrelationType {
        ROOT_CAUSE,      // Identify root cause
        SYMPTOM,         // Group symptoms
        CASCADE,         // Cascade failure
        FLAPPING,        // Flapping detection
        NOISE            // Noise reduction
    } type;
    
    // Actions
    bool suppress_duplicates;
    bool create_parent_alert;
    bool auto_resolve_related;
    std::string parent_alert_template;
};

// Alert correlation result
struct CorrelationResult {
    std::string correlation_id;
    CorrelationRule::CorrelationType type;
    std::vector<std::string> correlated_alert_ids;
    std::string root_cause_alert_id;
    std::string parent_alert_id;
    double confidence;
    std::vector<std::string> insights;
};

// Alert fatigue detection
struct AlertFatigueMetrics {
    std::string user_id;
    uint32_t alerts_per_hour;
    uint32_t acknowledged_per_hour;
    uint32_t resolved_per_hour;
    double acknowledgment_rate;
    double average_response_time_minutes;
    uint32_t missed_alerts;
    
    enum class FatigueLevel {
        NONE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    } fatigue_level;
    
    std::vector<std::string> recommendations;
};

// Intelligent alerting manager interface
class IIntelligentAlertingManager {
public:
    virtual ~IIntelligentAlertingManager() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Alert management
    virtual std::string CreateAlert(const Alert& alert) = 0;
    virtual bool UpdateAlert(const Alert& alert) = 0;
    virtual bool AcknowledgeAlert(const std::string& alert_id, 
                                   const std::string& user_id) = 0;
    virtual bool ResolveAlert(const std::string& alert_id,
                              const std::string& user_id,
                              const std::string& notes) = 0;
    virtual bool SuppressAlert(const std::string& alert_id,
                               const std::chrono::seconds& duration,
                               const std::string& reason) = 0;
    virtual bool DeleteAlert(const std::string& alert_id) = 0;
    
    // Alert queries
    virtual std::optional<Alert> GetAlert(const std::string& alert_id) = 0;
    virtual std::vector<Alert> QueryAlerts(const std::string& query,
                                           AlertStatus status = AlertStatus::NEW,
                                           AlertSeverity min_severity = AlertSeverity::INFO,
                                           std::chrono::hours lookback = std::chrono::hours(24)) = 0;
    virtual std::vector<Alert> GetActiveAlerts(const std::string& resource_id = "") = 0;
    virtual std::vector<Alert> GetAlertsForUser(const std::string& user_id) = 0;
    
    // Rule management
    virtual std::string CreateAlertRule(const AlertRule& rule) = 0;
    virtual bool UpdateAlertRule(const AlertRule& rule) = 0;
    virtual bool DeleteAlertRule(const std::string& rule_id) = 0;
    virtual std::optional<AlertRule> GetAlertRule(const std::string& rule_id) = 0;
    virtual std::vector<AlertRule> ListAlertRules() = 0;
    virtual bool EnableAlertRule(const std::string& rule_id) = 0;
    virtual bool DisableAlertRule(const std::string& rule_id) = 0;
    
    // Template management
    virtual std::string CreateTemplate(const NotificationTemplate& tmpl) = 0;
    virtual bool UpdateTemplate(const NotificationTemplate& tmpl) = 0;
    virtual bool DeleteTemplate(const std::string& template_id) = 0;
    virtual std::optional<NotificationTemplate> GetTemplate(const std::string& template_id) = 0;
    virtual std::vector<NotificationTemplate> ListTemplates() = 0;
    
    // Escalation policies
    virtual std::string CreateEscalationPolicy(const EscalationPolicy& policy) = 0;
    virtual bool UpdateEscalationPolicy(const EscalationPolicy& policy) = 0;
    virtual bool DeleteEscalationPolicy(const std::string& policy_id) = 0;
    virtual std::optional<EscalationPolicy> GetEscalationPolicy(const std::string& policy_id) = 0;
    virtual std::vector<EscalationPolicy> ListEscalationPolicies() = 0;
    
    // Correlation
    virtual std::string CreateCorrelationRule(const CorrelationRule& rule) = 0;
    virtual bool UpdateCorrelationRule(const CorrelationRule& rule) = 0;
    virtual bool DeleteCorrelationRule(const std::string& rule_id) = 0;
    virtual std::vector<CorrelationResult> CorrelateAlerts(
        const std::vector<std::string>& alert_ids) = 0;
    virtual std::vector<CorrelationResult> GetCorrelations(
        const std::string& alert_id) = 0;
    
    // Notification
    virtual bool SendNotification(const Alert& alert,
                                   const NotificationTemplate& tmpl) = 0;
    virtual bool TestNotificationChannel(AlertChannel channel,
                                          const std::string& test_address) = 0;
    
    // Alert fatigue
    virtual AlertFatigueMetrics GetUserFatigueMetrics(const std::string& user_id,
                                                       std::chrono::hours lookback = std::chrono::hours(168)) = 0;
    virtual std::vector<std::string> GetFatigueRecommendations(
        const std::string& user_id) = 0;
    virtual bool EnableSmartGrouping(const std::string& user_id) = 0;
    
    // Statistics
    virtual struct AlertingStatistics {
        uint32_t total_alerts;
        uint32_t active_alerts;
        uint32_t acknowledged_alerts;
        uint32_t resolved_alerts;
        double average_acknowledgment_time_minutes;
        double average_resolution_time_minutes;
        uint32_t escalated_alerts;
        uint32_t suppressed_alerts;
        std::unordered_map<AlertSeverity, uint32_t> alerts_by_severity;
        std::unordered_map<std::string, uint32_t> alerts_by_source;
    } GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) = 0;
};

// Local alerting manager
class LocalIntelligentAlertingManager : public IIntelligentAlertingManager {
public:
    LocalIntelligentAlertingManager();
    ~LocalIntelligentAlertingManager() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreateAlert(const Alert& alert) override;
    bool UpdateAlert(const Alert& alert) override;
    bool AcknowledgeAlert(const std::string& alert_id, 
                          const std::string& user_id) override;
    bool ResolveAlert(const std::string& alert_id,
                      const std::string& user_id,
                      const std::string& notes) override;
    bool SuppressAlert(const std::string& alert_id,
                       const std::chrono::seconds& duration,
                       const std::string& reason) override;
    bool DeleteAlert(const std::string& alert_id) override;
    
    std::optional<Alert> GetAlert(const std::string& alert_id) override;
    std::vector<Alert> QueryAlerts(const std::string& query,
                                   AlertStatus status = AlertStatus::NEW,
                                   AlertSeverity min_severity = AlertSeverity::INFO,
                                   std::chrono::hours lookback = std::chrono::hours(24)) override;
    std::vector<Alert> GetActiveAlerts(const std::string& resource_id = "") override;
    std::vector<Alert> GetAlertsForUser(const std::string& user_id) override;
    
    std::string CreateAlertRule(const AlertRule& rule) override;
    bool UpdateAlertRule(const AlertRule& rule) override;
    bool DeleteAlertRule(const std::string& rule_id) override;
    std::optional<AlertRule> GetAlertRule(const std::string& rule_id) override;
    std::vector<AlertRule> ListAlertRules() override;
    bool EnableAlertRule(const std::string& rule_id) override;
    bool DisableAlertRule(const std::string& rule_id) override;
    
    std::string CreateTemplate(const NotificationTemplate& tmpl) override;
    bool UpdateTemplate(const NotificationTemplate& tmpl) override;
    bool DeleteTemplate(const std::string& template_id) override;
    std::optional<NotificationTemplate> GetTemplate(const std::string& template_id) override;
    std::vector<NotificationTemplate> ListTemplates() override;
    
    std::string CreateEscalationPolicy(const EscalationPolicy& policy) override;
    bool UpdateEscalationPolicy(const EscalationPolicy& policy) override;
    bool DeleteEscalationPolicy(const std::string& policy_id) override;
    std::optional<EscalationPolicy> GetEscalationPolicy(const std::string& policy_id) override;
    std::vector<EscalationPolicy> ListEscalationPolicies() override;
    
    std::string CreateCorrelationRule(const CorrelationRule& rule) override;
    bool UpdateCorrelationRule(const CorrelationRule& rule) override;
    bool DeleteCorrelationRule(const std::string& rule_id) override;
    std::vector<CorrelationResult> CorrelateAlerts(
        const std::vector<std::string>& alert_ids) override;
    std::vector<CorrelationResult> GetCorrelations(
        const std::string& alert_id) override;
    
    bool SendNotification(const Alert& alert,
                          const NotificationTemplate& tmpl) override;
    bool TestNotificationChannel(AlertChannel channel,
                                 const std::string& test_address) override;
    
    AlertFatigueMetrics GetUserFatigueMetrics(const std::string& user_id,
                                               std::chrono::hours lookback = std::chrono::hours(168)) override;
    std::vector<std::string> GetFatigueRecommendations(
        const std::string& user_id) override;
    bool EnableSmartGrouping(const std::string& user_id) override;
    
    AlertingStatistics GetStatistics(std::chrono::hours lookback = std::chrono::hours(168)) override;
    
private:
    std::unordered_map<std::string, Alert> alerts_;
    std::unordered_map<std::string, AlertRule> rules_;
    std::unordered_map<std::string, NotificationTemplate> templates_;
    std::unordered_map<std::string, EscalationPolicy> escalation_policies_;
    std::unordered_map<std::string, CorrelationRule> correlation_rules_;
    bool initialized_ = false;
    
    bool EvaluateRule(const AlertRule& rule, const Alert& alert);
    std::string RenderTemplate(const std::string& tmpl, const Alert& alert);
    void ProcessEscalation(const Alert& alert);
    void ApplyCorrelation(const CorrelationResult& correlation);
};

// Alert deduplication
class AlertDeduplicator {
public:
    struct DeduplicationKey {
        std::string source;
        std::string resource_id;
        AlertSeverity severity;
        std::string fingerprint;  // Hash of alert content
        
        bool operator==(const DeduplicationKey& other) const;
    };
    
    struct DeduplicationEntry {
        DeduplicationKey key;
        std::string original_alert_id;
        std::chrono::system_clock::time_point first_seen;
        std::chrono::system_clock::time_point last_seen;
        uint32_t duplicate_count;
    };
    
    bool IsDuplicate(const Alert& alert, std::chrono::seconds window);
    std::optional<std::string> GetOriginalAlertId(const Alert& alert);
    void RecordAlert(const Alert& alert);
    void CleanupOldEntries(std::chrono::hours max_age);
    
private:
    std::unordered_map<DeduplicationKey, DeduplicationEntry> entries_;
};

// Global alerting manager
extern std::unique_ptr<IIntelligentAlertingManager> g_alerting_manager;

// Initialize alerting
bool InitializeIntelligentAlerting(const std::string& config_path);
void ShutdownIntelligentAlerting();
bool IsIntelligentAlertingEnabled();

} // namespace Intelligent
} // namespace RawrXD
