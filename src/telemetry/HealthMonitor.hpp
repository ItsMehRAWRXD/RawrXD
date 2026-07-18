/**
 * HealthMonitor.hpp
 *
 * Phase F Batch 3/5: Health Monitoring & Alerting
 *
 * Comprehensive health monitoring with configurable checks and alerting.
 * Supports multiple severity levels and notification channels.
 */

#pragma once

#include "MetricsCollector.hpp"
#include <functional>
#include <queue>
#include <set>

namespace Telemetry {

// ============================================================================
// Health Status
// ============================================================================

enum class HealthStatus {
    HEALTHY,     // All checks passing
    DEGRADED,    // Some checks warning
    UNHEALTHY    // Critical checks failing
};

std::string HealthStatusToString(HealthStatus status);

// ============================================================================
// Check Severity
// ============================================================================

enum class CheckSeverity {
    INFO,        // Informational only
    WARNING,     // Warning, non-critical
    CRITICAL     // Critical, affects health
};

// ============================================================================
// Check Result
// ============================================================================

/**
 * Result of a health check.
 */
struct CheckResult {
    std::string checkId;
    std::string name;
    CheckSeverity severity;
    bool passed;
    std::string message;
    std::string details;
    uint64_t timestamp;
    uint64_t durationMs;
    std::map<std::string, std::string> metadata;
    
    std::string ToJson() const;
};

// ============================================================================
// Health Check
// ============================================================================

/**
 * Base class for health checks.
 */
class HealthCheck {
public:
    using Ptr = std::shared_ptr<HealthCheck>;
    
    struct Config {
        std::string id;
        std::string name;
        CheckSeverity severity = CheckSeverity::WARNING;
        uint64_t intervalMs = 60000;      // Check interval
        uint64_t timeoutMs = 10000;       // Check timeout
        uint32_t maxRetries = 3;          // Max retries on failure
        bool enabled = true;              // Whether check is enabled
    };
    
    explicit HealthCheck(const Config& config);
    virtual ~HealthCheck() = default;
    
    // Execute check
    CheckResult Execute();
    
    // Get config
    const Config& GetConfig() const { return config_; }
    std::string GetId() const { return config_.id; }
    std::string GetName() const { return config_.name; }
    bool IsEnabled() const { return config_.enabled; }
    void SetEnabled(bool enabled) { config_.enabled = enabled; }
    
    // Last result
    std::optional<CheckResult> GetLastResult() const;
    uint64_t GetLastExecutionTime() const { return lastExecutionTime_; }
    
protected:
    virtual CheckResult DoCheck() = 0;
    
private:
    Config config_;
    std::optional<CheckResult> lastResult_;
    uint64_t lastExecutionTime_ = 0;
    mutable std::mutex mutex_;
};

// ============================================================================
// Built-in Health Checks
// ============================================================================

/**
 * Check if service is responding.
 */
class LivenessCheck : public HealthCheck {
public:
    explicit LivenessCheck(const Config& config);
    
protected:
    CheckResult DoCheck() override;
};

/**
 * Check if service is ready to accept traffic.
 */
class ReadinessCheck : public HealthCheck {
public:
    explicit ReadinessCheck(const Config& config);
    
    void AddDependency(std::function<bool()> check);
    
protected:
    CheckResult DoCheck() override;
    
private:
    std::vector<std::function<bool()>> dependencies_;
    mutable std::mutex mutex_;
};

/**
 * Check system resources.
 */
class ResourceCheck : public HealthCheck {
public:
    struct Thresholds {
        double cpuWarning = 70.0;      // CPU %
        double cpuCritical = 90.0;
        double memoryWarning = 80.0;  // Memory %
        double memoryCritical = 95.0;
        double diskWarning = 85.0;    // Disk %
        double diskCritical = 95.0;
    };
    
    ResourceCheck(const Config& config, const Thresholds& thresholds);
    
protected:
    CheckResult DoCheck() override;
    
private:
    Thresholds thresholds_;
    
    double GetCPUUsage();
    double GetMemoryUsage();
    double GetDiskUsage();
};

/**
 * Check dependency availability.
 */
class DependencyCheck : public HealthCheck {
public:
    using CheckFunc = std::function<std::pair<bool, std::string>()>;
    
    DependencyCheck(const Config& config, CheckFunc check);
    
protected:
    CheckResult DoCheck() override;
    
private:
    CheckFunc checkFunc_;
};

/**
 * Check custom metric threshold.
 */
class MetricThresholdCheck : public HealthCheck {
public:
    enum class Comparison {
        GREATER_THAN,
        LESS_THAN,
        EQUAL_TO,
        NOT_EQUAL
    };
    
    MetricThresholdCheck(
        const Config& config,
        MetricsRegistry* registry,
        const std::string& metricName,
        Comparison comparison,
        double threshold
    );
    
protected:
    CheckResult DoCheck() override;
    
private:
    MetricsRegistry* registry_;
    std::string metricName_;
    Comparison comparison_;
    double threshold_;
};

// ============================================================================
// Health Monitor
// ============================================================================

/**
 * Monitors health of the system.
 */
class HealthMonitor {
public:
    struct Config {
        uint64_t checkIntervalMs = 30000;      // Global check interval
        uint64_t startupDelayMs = 10000;     // Delay before first check
        bool failFast = false;               // Fail on first critical error
    };
    
    explicit HealthMonitor(const Config& config = Config{});
    ~HealthMonitor();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Register checks
    void RegisterCheck(HealthCheck::Ptr check);
    void UnregisterCheck(const std::string& checkId);
    
    // Get checks
    std::vector<HealthCheck::Ptr> GetChecks() const;
    std::optional<HealthCheck::Ptr> GetCheck(const std::string& checkId);
    
    // Health status
    HealthStatus GetHealthStatus() const;
    bool IsHealthy() const { return GetHealthStatus() == HealthStatus::HEALTHY; }
    bool IsReady() const;
    
    // Check results
    std::vector<CheckResult> GetAllResults() const;
    std::vector<CheckResult> GetFailedResults() const;
    std::optional<CheckResult> GetResult(const std::string& checkId) const;
    
    // Force check
    void ForceCheck(const std::string& checkId);
    void ForceCheckAll();
    
    // Status
    std::string GetStatusJson() const;
    
    // Callbacks
    using HealthChangeCallback = std::function<void(HealthStatus oldStatus, HealthStatus newStatus)>;
    using CheckFailureCallback = std::function<void(const CheckResult& result)>;
    
    void OnHealthChange(HealthChangeCallback callback);
    void OnCheckFailure(CheckFailureCallback callback);
    
private:
    Config config_;
    
    std::map<std::string, HealthCheck::Ptr> checks_;
    mutable std::mutex checksMutex_;
    
    std::map<std::string, CheckResult> results_;
    mutable std::mutex resultsMutex_;
    
    std::atomic<bool> running_{false};
    std::thread monitorThread_;
    
    HealthStatus currentStatus_ = HealthStatus::HEALTHY;
    mutable std::mutex statusMutex_;
    
    HealthChangeCallback healthChangeCallback_;
    CheckFailureCallback checkFailureCallback_;
    std::mutex callbackMutex_;
    
    // Monitor loop
    void MonitorLoop();
    
    // Internal methods
    void ExecuteCheck(HealthCheck::Ptr check);
    void UpdateHealthStatus();
    void NotifyHealthChange(HealthStatus oldStatus, HealthStatus newStatus);
    void NotifyCheckFailure(const CheckResult& result);
};

// ============================================================================
// Alert
// ============================================================================

/**
 * Represents an alert.
 */
struct Alert {
    std::string alertId;
    std::string name;
    std::string description;
    CheckSeverity severity;
    std::string source;           // Component that triggered
    uint64_t timestamp;
    uint64_t resolvedTimestamp;
    bool resolved;
    std::map<std::string, std::string> labels;
    std::map<std::string, std::string> annotations;
    
    std::string ToJson() const;
};

// ============================================================================
// Alert Rule
// ============================================================================

/**
 * Rule for generating alerts.
 */
class AlertRule {
public:
    struct Config {
        std::string id;
        std::string name;
        std::string description;
        CheckSeverity severity = CheckSeverity::WARNING;
        uint64_t durationMs = 0;          // Duration condition must be true
        uint64_t evaluationIntervalMs = 60000;
        std::string condition;            // Query expression
        std::map<std::string, std::string> labels;
        std::map<std::string, std::string> annotations;
    };
    
    explicit AlertRule(const Config& config);
    
    // Evaluate rule
    bool Evaluate(MetricsRegistry* registry);
    
    // Get config
    const Config& GetConfig() const { return config_; }
    
    // State
    bool IsFiring() const { return firing_; }
    uint64_t GetFiringSince() const { return firingSince_; }
    
private:
    Config config_;
    bool firing_ = false;
    uint64_t firingSince_ = 0;
    mutable std::mutex mutex_;
};

// ============================================================================
// Alert Manager
// ============================================================================

/**
 * Manages alerts and notifications.
 */
class AlertManager {
public:
    struct Config {
        uint64_t evaluationIntervalMs = 60000;
        uint64_t groupIntervalMs = 300000;       // Group alerts
        uint64_t repeatIntervalMs = 14400000;     // Repeat firing alerts
        bool resolveTimeout = true;
        uint64_t resolveTimeoutMs = 300000;
    };
    
    explicit AlertManager(const Config& config = Config{});
    ~AlertManager();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Rules
    void AddRule(std::shared_ptr<AlertRule> rule);
    void RemoveRule(const std::string& ruleId);
    std::vector<std::shared_ptr<AlertRule>> GetRules() const;
    
    // Alerts
    std::vector<Alert> GetActiveAlerts() const;
    std::vector<Alert> GetAlertHistory() const;
    void ResolveAlert(const std::string& alertId);
    
    // Silences
    void AddSilence(const std::string& matcher, uint64_t durationMs);
    bool IsSilenced(const Alert& alert) const;
    
    // Notification channels
    using NotificationHandler = std::function<void(const Alert&)>;
    void AddNotificationChannel(const std::string& name, NotificationHandler handler);
    void RemoveNotificationChannel(const std::string& name);
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    
    std::vector<std::shared_ptr<AlertRule>> rules_;
    mutable std::mutex rulesMutex_;
    
    std::map<std::string, Alert> activeAlerts_;
    std::vector<Alert> alertHistory_;
    mutable std::mutex alertsMutex_;
    
    std::map<std::string, NotificationHandler> channels_;
    mutable std::mutex channelsMutex_;
    
    std::vector<std::pair<std::string, uint64_t>> silences_; // matcher -> expires
    mutable std::mutex silencesMutex_;
    
    std::atomic<bool> running_{false};
    std::thread evaluationThread_;
    
    // Evaluation loop
    void EvaluationLoop();
    
    // Internal methods
    void EvaluateRules();
    void SendNotifications(const Alert& alert);
    bool ShouldNotify(const Alert& alert);
    void CleanupSilences();
    void CleanupResolvedAlerts();
};

// ============================================================================
// Notification Channels
// ============================================================================

/**
 * Built-in notification channel implementations.
 */
class NotificationChannels {
public:
    // Log alerts to file
    static AlertManager::NotificationHandler FileChannel(const std::string& filepath);
    
    // HTTP webhook
    static AlertManager::NotificationHandler WebhookChannel(const std::string& url);
    
    // Email (SMTP)
    static AlertManager::NotificationHandler EmailChannel(
        const std::string& smtpServer,
        const std::string& from,
        const std::vector<std::string>& to
    );
    
    // Slack
    static AlertManager::NotificationHandler SlackChannel(const std::string& webhookUrl);
    
    // PagerDuty
    static AlertManager::NotificationHandler PagerDutyChannel(const std::string& integrationKey);
    
    // Composite (multiple channels)
    static AlertManager::NotificationHandler CompositeChannel(
        const std::vector<AlertManager::NotificationHandler>& channels
    );
};

// ============================================================================
// Health API
// ============================================================================

/**
 * High-level health monitoring API.
 */
class Health {
public:
    // Initialize with default configuration
    static bool Initialize();
    static bool Initialize(const HealthMonitor::Config& monitorConfig,
                           const AlertManager::Config& alertConfig);
    static void Shutdown();
    
    // Access components
    static HealthMonitor* GetMonitor();
    static AlertManager* GetAlertManager();
    
    // Quick checks
    static bool IsHealthy();
    static bool IsReady();
    static HealthStatus GetStatus();
    
    // Register built-in checks
    static void RegisterLivenessCheck();
    static void RegisterReadinessCheck();
    static void RegisterResourceCheck(const ResourceCheck::Thresholds& thresholds);
    
    // Create alerts
    static void Alert(const std::string& name, const std::string& description,
                      CheckSeverity severity);
    
private:
    static std::unique_ptr<HealthMonitor> monitor_;
    static std::unique_ptr<AlertManager> alertManager_;
    static std::mutex mutex_;
};

} // namespace Telemetry
