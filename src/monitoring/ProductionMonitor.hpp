// RawrXD Production Monitor
// Phase V.1: Real-time production monitoring and alerting
// Tracks system health, performance metrics, and business metrics in production

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <atomic>
#include <queue>

namespace RawrXD {
namespace Monitoring {

// Metric types
enum class MetricType {
    COUNTER,      // Monotonically increasing (e.g., requests served)
    GAUGE,        // Point-in-time value (e.g., memory usage)
    HISTOGRAM,    // Distribution of values (e.g., request latency)
    SUMMARY       // Calculated summary (e.g., percentiles)
};

// Metric value
struct MetricValue {
    double value;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> labels;
    
    MetricValue(double v = 0.0) : value(v), timestamp(std::chrono::system_clock::now()) {}
};

// Metric definition
struct MetricDefinition {
    std::string name;
    std::string description;
    MetricType type;
    std::vector<std::string> labelNames;
    std::map<std::string, std::string> defaultLabels;
    std::chrono::seconds retentionPeriod{3600};  // 1 hour default
};

// Time series data
struct TimeSeries {
    MetricDefinition definition;
    std::vector<MetricValue> values;
    std::mutex mutex;
    
    void addValue(const MetricValue& value);
    std::vector<MetricValue> getRange(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) const;
    double getLatest() const;
    double getAverage(std::chrono::seconds window) const;
    double getPercentile(double percentile, std::chrono::seconds window) const;
};

// Alert severity
enum class AlertSeverity {
    INFO,
    WARNING,
    CRITICAL,
    EMERGENCY
};

// Alert definition
struct AlertRule {
    std::string name;
    std::string description;
    std::string metricQuery;  // e.g., "cpu_usage > 80"
    AlertSeverity severity;
    std::chrono::seconds duration;  // How long condition must persist
    std::chrono::seconds cooldown;  // Minimum time between alerts
    std::vector<std::string> notificationChannels;
    bool enabled{true};
};

// Alert instance
struct Alert {
    std::string id;
    std::string ruleName;
    AlertSeverity severity;
    std::string message;
    std::map<std::string, std::string> labels;
    std::chrono::system_clock::time_point firedAt;
    std::chrono::system_clock::time_point resolvedAt;
    bool isResolved{false};
    int notificationCount{0};
};

// Dashboard panel
struct DashboardPanel {
    std::string title;
    std::string type;  // "graph", "singlestat", "table", "heatmap"
    std::vector<std::string> metricQueries;
    std::map<std::string, std::string> options;
    std::chrono::seconds refreshInterval{30};
};

// Dashboard
struct Dashboard {
    std::string name;
    std::string title;
    std::vector<DashboardPanel> panels;
    std::chrono::seconds refreshInterval{30};
    std::map<std::string, std::string> variables;  // Template variables
};

// SLO (Service Level Objective)
struct SLODefinition {
    std::string name;
    std::string description;
    std::string metricQuery;
    double target;  // e.g., 0.99 for 99%
    std::chrono::seconds evaluationWindow{86400};  // 24 hours
    std::vector<std::string> alertRules;
};

// SLO status
struct SLOStatus {
    std::string sloName;
    double currentValue;
    double targetValue;
    double errorBudgetRemaining;  // Percentage
    bool isBreaching;
    std::chrono::system_clock::time_point lastEvaluated;
};

// Production monitor
class ProductionMonitor {
public:
    ProductionMonitor();
    ~ProductionMonitor();
    
    // Initialization
    bool initialize(const std::string& configPath);
    bool shutdown();
    bool isRunning() const { return running_; }
    
    // Metric registration
    void registerMetric(const MetricDefinition& definition);
    void unregisterMetric(const std::string& name);
    bool hasMetric(const std::string& name) const;
    std::vector<MetricDefinition> getRegisteredMetrics() const;
    
    // Metric recording
    void recordCounter(const std::string& name, double increment = 1.0, 
                      const std::map<std::string, std::string>& labels = {});
    void recordGauge(const std::string& name, double value,
                    const std::map<std::string, std::string>& labels = {});
    void recordHistogram(const std::string& name, double value,
                        const std::map<std::string, std::string>& labels = {});
    void recordSummary(const std::string& name, double value,
                      const std::map<std::string, std::string>& labels = {});
    
    // Metric queries
    double getMetricValue(const std::string& name, 
                         const std::map<std::string, std::string>& labels = {}) const;
    std::vector<MetricValue> getMetricHistory(
        const std::string& name,
        std::chrono::seconds duration,
        const std::map<std::string, std::string>& labels = {}) const;
    std::map<std::string, double> getMetricAggregates(
        const std::string& name,
        std::chrono::seconds duration) const;
    
    // Alert management
    void addAlertRule(const AlertRule& rule);
    void removeAlertRule(const std::string& name);
    std::vector<AlertRule> getAlertRules() const;
    std::vector<Alert> getActiveAlerts() const;
    std::vector<Alert> getAlertHistory(std::chrono::hours duration = std::chrono::hours{24}) const;
    bool acknowledgeAlert(const std::string& alertId);
    bool resolveAlert(const std::string& alertId);
    
    // Dashboard management
    void createDashboard(const Dashboard& dashboard);
    void updateDashboard(const std::string& name, const Dashboard& dashboard);
    void deleteDashboard(const std::string& name);
    Dashboard getDashboard(const std::string& name) const;
    std::vector<std::string> listDashboards() const;
    std::string renderDashboard(const std::string& name) const;  // Returns JSON
    
    // SLO management
    void defineSLO(const SLODefinition& slo);
    void removeSLO(const std::string& name);
    SLOStatus evaluateSLO(const std::string& name) const;
    std::vector<SLOStatus> getAllSLOStatuses() const;
    
    // Export formats
    bool exportToPrometheus(const std::string& outputPath) const;
    bool exportToJSON(const std::string& outputPath, std::chrono::seconds duration = std::chrono::seconds{3600}) const;
    bool exportToCSV(const std::string& outputPath, std::chrono::seconds duration = std::chrono::seconds{3600}) const;
    
    // Real-time streaming
    using MetricCallback = std::function<void(const std::string& name, const MetricValue& value)>;
    using AlertCallback = std::function<void(const Alert& alert)>;
    void subscribeToMetric(const std::string& name, MetricCallback callback);
    void subscribeToAlerts(AlertCallback callback);
    void unsubscribeAll();
    
    // Health check
    struct HealthStatus {
        bool isHealthy;
        std::string status;  // "healthy", "degraded", "unhealthy"
        std::vector<std::string> issues;
        std::chrono::system_clock::time_point checkedAt;
    };
    HealthStatus getHealthStatus() const;
    
    // Statistics
    struct MonitorStats {
        uint64_t metricsRecorded;
        uint64_t alertsFired;
        uint64_t alertsResolved;
        uint32_t activeAlertCount;
        uint32_t registeredMetricCount;
        std::chrono::seconds uptime;
    };
    MonitorStats getStats() const;

private:
    void evaluateAlertRules();
    void cleanupOldData();
    void notifyMetricSubscribers(const std::string& name, const MetricValue& value);
    void notifyAlertSubscribers(const Alert& alert);
    std::string generateAlertId() const;
    bool evaluateCondition(const std::string& query) const;
    
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<TimeSeries>> metrics_;
    std::map<std::string, AlertRule> alertRules_;
    std::map<std::string, Alert> activeAlerts_;
    std::vector<Alert> alertHistory_;
    std::map<std::string, Dashboard> dashboards_;
    std::map<std::string, SLODefinition> slos_;
    std::map<std::string, std::vector<MetricCallback>> metricSubscribers_;
    std::vector<AlertCallback> alertSubscribers_;
    
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> metricsRecorded_{0};
    std::atomic<uint64_t> alertsFired_{0};
    std::atomic<uint64_t> alertsResolved_{0};
    std::chrono::steady_clock::time_point startTime_;
    
    std::thread evaluationThread_;
    std::thread cleanupThread_;
};

// Metric builder for fluent API
class MetricBuilder {
public:
    MetricBuilder(ProductionMonitor* monitor, const std::string& name);
    
    MetricBuilder& withLabel(const std::string& key, const std::string& value);
    MetricBuilder& increment(double amount = 1.0);
    MetricBuilder& set(double value);
    MetricBuilder& observe(double value);
    
private:
    ProductionMonitor* monitor_;
    std::string name_;
    std::map<std::string, std::string> labels_;
};

// Alert builder for fluent API
class AlertBuilder {
public:
    AlertBuilder(ProductionMonitor* monitor);
    
    AlertBuilder& withName(const std::string& name);
    AlertBuilder& withDescription(const std::string& description);
    AlertBuilder& withQuery(const std::string& query);
    AlertBuilder& withSeverity(AlertSeverity severity);
    AlertBuilder& withDuration(std::chrono::seconds duration);
    AlertBuilder& withCooldown(std::chrono::seconds cooldown);
    AlertBuilder& notifyOn(const std::vector<std::string>& channels);
    
    bool create();
    
private:
    ProductionMonitor* monitor_;
    AlertRule rule_;
};

} // namespace Monitoring
} // namespace RawrXD
