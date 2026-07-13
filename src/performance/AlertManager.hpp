// RawrXD Alert Manager
// Phase P.3: Alert management and notification system
// Real-time alerting with multi-channel notifications

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

namespace RawrXD {
namespace Performance {

// Forward declarations
class ObservabilityPlatform;

// Alert severity levels
enum class AlertSeverity {
    INFO = 0,
    WARNING = 1,
    CRITICAL = 2
};

// Alert status
enum class AlertStatus {
    FIRING,
    ACKNOWLEDGED,
    RESOLVED,
    SILENCED
};

// Alert rule - defines when to trigger alerts
struct AlertRule {
    std::string id;
    std::string name;
    std::string description;
    
    // Condition
    std::string metric;
    std::string condition;  // >, <, >=, <=, ==, !=
    double threshold;
    uint32_t durationSeconds;  // How long condition must persist
    
    // Severity
    AlertSeverity severity;
    
    // Labels for filtering
    std::map<std::string, std::string> labels;
    
    // Actions
    bool sendEmail = false;
    bool sendSlack = false;
    bool sendPagerDuty = false;
    bool autoScale = false;
    bool autoTune = false;
    
    // Notification targets
    std::vector<std::string> emailAddresses;
    std::vector<std::string> slackChannels;
    std::string pagerDutyServiceKey;
    
    // Rate limiting
    uint32_t cooldownMinutes = 15;
    uint32_t maxAlertsPerHour = 10;
    
    // Enabled
    bool enabled = true;
};

// Alert instance
struct Alert {
    std::string id;
    std::string ruleId;
    std::string ruleName;
    AlertSeverity severity;
    AlertStatus status;
    
    // Timing
    std::chrono::steady_clock::time_point firedAt;
    std::chrono::steady_clock::time_point acknowledgedAt;
    std::chrono::steady_clock::time_point resolvedAt;
    std::chrono::steady_clock::time_point silencedUntil;
    
    // Details
    std::string summary;
    std::string description;
    double currentValue;
    double threshold;
    std::map<std::string, std::string> labels;
    std::map<std::string, std::string> annotations;
    
    // Actions taken
    std::vector<std::string> actionsTaken;
    
    Alert() : severity(AlertSeverity::INFO), status(AlertStatus::FIRING),
              currentValue(0.0), threshold(0.0) {}
};

// Notification channel configuration
struct NotificationConfig {
    // Email
    struct EmailConfig {
        bool enabled = false;
        std::string smtpServer;
        uint32_t smtpPort = 587;
        std::string username;
        std::string password;
        std::string fromAddress;
        bool useTLS = true;
    } email;
    
    // Slack
    struct SlackConfig {
        bool enabled = false;
        std::string webhookUrl;
        std::string defaultChannel;
        std::string username = "RawrXD Alert";
        std::string iconEmoji = ":warning:";
    } slack;
    
    // PagerDuty
    struct PagerDutyConfig {
        bool enabled = false;
        std::string serviceKey;
        std::string severityMapping;  // critical->critical, warning->warning, etc.
    } pagerDuty;
    
    // Webhook
    struct WebhookConfig {
        bool enabled = false;
        std::string url;
        std::map<std::string, std::string> headers;
    } webhook;
};

// Alert manager configuration
struct AlertManagerConfig {
    // Evaluation
    uint32_t evaluationIntervalSeconds = 30;
    uint32_t maxAlertHistory = 10000;
    
    // Grouping
    bool groupAlerts = true;
    std::vector<std::string> groupByLabels;  // e.g., ["severity", "service"]
    uint32_t groupWaitSeconds = 30;
    uint32_t groupIntervalSeconds = 300;
    
    // Inhibition
    bool inhibitAlerts = true;  // Suppress lower severity if higher exists
    
    // Silence
    uint32_t defaultSilenceDurationMinutes = 60;
    
    // Notification
    NotificationConfig notification;
};

// Alert manager
class AlertManager {
public:
    AlertManager(ObservabilityPlatform* observability);
    ~AlertManager();
    
    // Lifecycle
    bool initialize(const AlertManagerConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Rule management
    std::string createRule(const AlertRule& rule);
    bool updateRule(const std::string& ruleId, const AlertRule& rule);
    bool deleteRule(const std::string& ruleId);
    AlertRule getRule(const std::string& ruleId) const;
    std::vector<AlertRule> getAllRules() const;
    std::vector<AlertRule> getRulesForMetric(const std::string& metric) const;
    bool enableRule(const std::string& ruleId);
    bool disableRule(const std::string& ruleId);
    
    // Alert management
    std::vector<Alert> getActiveAlerts() const;
    std::vector<Alert> getAlertsBySeverity(AlertSeverity severity) const;
    std::vector<Alert> getAlertHistory(uint32_t hours) const;
    Alert getAlert(const std::string& alertId) const;
    
    bool acknowledgeAlert(const std::string& alertId, const std::string& user);
    bool resolveAlert(const std::string& alertId, const std::string& comment);
    bool silenceAlert(const std::string& alertId, uint32_t durationMinutes);
    bool unsilenceAlert(const std::string& alertId);
    
    // Bulk operations
    bool acknowledgeAll(const std::vector<std::string>& alertIds, const std::string& user);
    bool resolveAll(const std::vector<std::string>& alertIds, const std::string& comment);
    bool silenceAll(const std::vector<std::string>& alertIds, uint32_t durationMinutes);
    
    // Silence management
    struct Silence {
        std::string id;
        std::vector<std::pair<std::string, std::string>> matchers;  // label matchers
        std::chrono::steady_clock::time_point startsAt;
        std::chrono::steady_clock::time_point endsAt;
        std::string createdBy;
        std::string comment;
    };
    std::string createSilence(const Silence& silence);
    bool deleteSilence(const std::string& silenceId);
    std::vector<Silence> getActiveSilences() const;
    bool isAlertSilenced(const Alert& alert) const;
    
    // Notification testing
    bool testEmailNotification(const std::string& address);
    bool testSlackNotification(const std::string& channel);
    bool testPagerDutyNotification();
    
    // Statistics
    struct AlertStats {
        uint64_t totalAlerts;
        uint64_t firingAlerts;
        uint64_t acknowledgedAlerts;
        uint64_t resolvedAlerts;
        uint64_t silencedAlerts;
        
        std::map<AlertSeverity, uint64_t> alertsBySeverity;
        std::map<std::string, uint64_t> alertsByRule;
        std::map<std::string, uint64_t> alertsByMetric;
        
        double avgResolutionTimeMinutes;
        double avgAcknowledgmentTimeMinutes;
    };
    AlertStats getStats() const;
    
    // Configuration
    AlertManagerConfig getConfig() const { return config_; }
    bool updateConfig(const AlertManagerConfig& config);
    
    // Callbacks
    using AlertCallback = std::function<void(const Alert&)>;
    void setAlertCallback(AlertCallback callback);
    
private:
    // Internal methods
    void evaluationLoop();
    void notificationLoop();
    void cleanupLoop();
    
    void evaluateRule(const AlertRule& rule);
    bool checkCondition(const AlertRule& rule, double value);
    void fireAlert(const AlertRule& rule, double value);
    void sendNotification(const Alert& alert);
    void sendEmail(const Alert& alert);
    void sendSlack(const Alert& alert);
    void sendPagerDuty(const Alert& alert);
    void sendWebhook(const Alert& alert);
    
    std::string generateAlertId();
    std::string generateSilenceId();
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread evalThread_;
    std::thread notifyThread_;
    std::thread cleanupThread_;
    mutable std::mutex mutex_;
    
    // Dependencies
    ObservabilityPlatform* observability_;
    
    // Configuration
    AlertManagerConfig config_;
    
    // State
    std::map<std::string, AlertRule> rules_;
    std::map<std::string, Alert> alerts_;
    std::map<std::string, Silence> silences_;
    
    // Rate limiting
    std::map<std::string, std::chrono::steady_clock::time_point> lastAlertTime_;
    std::map<std::string, uint32_t> alertCountPerHour_;
    
    // Notification queue
    std::queue<Alert> notificationQueue_;
    std::mutex notifyMutex_;
    std::condition_variable notifyCv_;
    
    // Callbacks
    AlertCallback alertCallback_;
    
    // Statistics
    std::atomic<uint64_t> totalAlerts_{0};
    std::atomic<uint64_t> totalNotifications_{0};
    
    // ID counters
    std::atomic<uint64_t> alertIdCounter_{0};
    std::atomic<uint64_t> silenceIdCounter_{0};
};

// Alert template manager
class AlertTemplateManager {
public:
    // Template management
    void addTemplate(const std::string& name, const std::string& templateStr);
    void removeTemplate(const std::string& name);
    std::string getTemplate(const std::string& name) const;
    
    // Rendering
    std::string render(const std::string& templateName, const Alert& alert) const;
    std::string renderSubject(const std::string& templateName, const Alert& alert) const;
    
    // Default templates
    static std::string getDefaultEmailTemplate();
    static std::string getDefaultSlackTemplate();
    static std::string getDefaultPagerDutyTemplate();
    
private:
    std::map<std::string, std::string> templates_;
    mutable std::mutex mutex_;
};

} // namespace Performance
} // namespace RawrXD
