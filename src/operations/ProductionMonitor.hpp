// Phase X.2/5: Production Monitoring & Alerting
// RawrXD Production Monitor - Real-time system health and performance monitoring

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <variant>

namespace RawrXD {
namespace Operations {

// Metric types
enum class MetricType {
    COUNTER,        // Monotonically increasing
    GAUGE,          // Can go up or down
    HISTOGRAM,      // Distribution of values
    SUMMARY         // Calculated summary (percentiles)
};

// Alert severity
enum class AlertSeverity {
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

// Alert state
enum class AlertState {
    PENDING,
    FIRING,
    RESOLVED,
    SILENCED
};

// Metric value
struct MetricValue {
    std::string name;
    MetricType type;
    std::variant<int64_t, double, std::string> value;
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, std::string> labels;
};

// Time series data point
struct TimeSeriesPoint {
    std::chrono::system_clock::time_point timestamp;
    double value;
};

// Time series
struct TimeSeries {
    std::string metric_name;
    std::unordered_map<std::string, std::string> labels;
    std::vector<TimeSeriesPoint> points;
    
    // Statistics
    double min_value;
    double max_value;
    double avg_value;
    double std_dev;
};

// Alert rule
struct AlertRule {
    std::string rule_id;
    std::string name;
    std::string description;
    AlertSeverity severity;
    
    // Condition
    std::string metric_name;
    std::string condition;  // ">", "<", "==", "!=", "range"
    double threshold;
    double threshold_min;   // For range conditions
    double threshold_max;   // For range conditions
    std::chrono::seconds duration;  // How long condition must persist
    
    // Labels filter
    std::unordered_map<std::string, std::string> label_filters;
    
    // Notification
    std::vector<std::string> notification_channels;
    std::string runbook_url;
    bool auto_resolve;
    
    // State
    bool is_enabled;
    std::chrono::system_clock::time_point last_evaluated;
};

// Alert instance
struct AlertInstance {
    std::string alert_id;
    std::string rule_id;
    std::string rule_name;
    AlertSeverity severity;
    AlertState state;
    
    // Context
    std::string metric_name;
    double metric_value;
    std::unordered_map<std::string, std::string> labels;
    std::string summary;
    std::string description;
    
    // Timeline
    std::chrono::system_clock::time_point fired_at;
    std::chrono::system_clock::time_point resolved_at;
    std::chrono::system_clock::time_point last_notified;
    
    // Resolution
    std::string resolution_notes;
};

// Dashboard panel
struct DashboardPanel {
    std::string panel_id;
    std::string name;
    std::string type;  // "graph", "singlestat", "table", "heatmap"
    
    // Query
    std::string metric_query;
    std::chrono::seconds time_range;
    std::chrono::seconds refresh_interval;
    
    // Visualization
    std::string title;
    std::string unit;
    std::vector<std::string> thresholds;  // Color thresholds
    
    // Layout
    uint32_t grid_x;
    uint32_t grid_y;
    uint32_t width;
    uint32_t height;
};

// Dashboard
struct MonitoringDashboard {
    std::string dashboard_id;
    std::string name;
    std::string description;
    
    // Panels
    std::vector<DashboardPanel> panels;
    
    // Settings
    std::chrono::seconds default_time_range;
    std::chrono::seconds auto_refresh;
    std::vector<std::string> tags;
};

// System health snapshot
struct SystemHealthSnapshot {
    std::chrono::system_clock::time_point timestamp;
    
    // Overall status
    std::string overall_status;  // "healthy", "degraded", "critical"
    double health_score;  // 0-100
    
    // Component health
    std::unordered_map<std::string, std::string> component_status;
    
    // Key metrics
    double cpu_percent;
    double memory_percent;
    double disk_percent;
    uint64_t network_bytes_per_sec;
    
    // Application metrics
    double inference_latency_p99;
    double tokens_per_second;
    uint32_t active_sessions;
    uint32_t queue_depth;
    double error_rate_percent;
};

// Production monitor interface
class IProductionMonitor {
public:
    virtual ~IProductionMonitor() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Metric collection
    virtual void RecordCounter(const std::string& name, int64_t value,
                                const std::unordered_map<std::string, std::string>& labels = {}) = 0;
    virtual void RecordGauge(const std::string& name, double value,
                              const std::unordered_map<std::string, std::string>& labels = {}) = 0;
    virtual void RecordHistogram(const std::string& name, double value,
                                  const std::unordered_map<std::string, std::string>& labels = {}) = 0;
    virtual void RecordTiming(const std::string& name, std::chrono::milliseconds duration,
                               const std::unordered_map<std::string, std::string>& labels = {}) = 0;
    
    // Metric queries
    virtual std::optional<TimeSeries> QueryMetric(const std::string& name,
                                                      std::chrono::seconds range = std::chrono::seconds(3600)) = 0;
    virtual std::vector<TimeSeries> QueryMetrics(const std::vector<std::string>& names,
                                                    std::chrono::seconds range = std::chrono::seconds(3600)) = 0;
    virtual std::vector<MetricValue> GetCurrentMetrics() = 0;
    
    // Alert rules
    virtual std::string CreateAlertRule(const AlertRule& rule) = 0;
    virtual bool UpdateAlertRule(const AlertRule& rule) = 0;
    virtual bool DeleteAlertRule(const std::string& rule_id) = 0;
    virtual std::optional<AlertRule> GetAlertRule(const std::string& rule_id) = 0;
    virtual std::vector<AlertRule> ListAlertRules() = 0;
    virtual bool EnableAlertRule(const std::string& rule_id) = 0;
    virtual bool DisableAlertRule(const std::string& rule_id) = 0;
    
    // Alert instances
    virtual std::vector<AlertInstance> GetActiveAlerts() = 0;
    virtual std::vector<AlertInstance> GetAlertHistory(std::chrono::hours range = std::chrono::hours(24)) = 0;
    virtual bool AcknowledgeAlert(const std::string& alert_id, const std::string& user) = 0;
    virtual bool ResolveAlert(const std::string& alert_id, const std::string& notes) = 0;
    virtual bool SilenceAlert(const std::string& alert_id, std::chrono::minutes duration) = 0;
    
    // Dashboards
    virtual std::string CreateDashboard(const MonitoringDashboard& dashboard) = 0;
    virtual bool UpdateDashboard(const MonitoringDashboard& dashboard) = 0;
    virtual bool DeleteDashboard(const std::string& dashboard_id) = 0;
    virtual std::optional<MonitoringDashboard> GetDashboard(const std::string& dashboard_id) = 0;
    virtual std::vector<MonitoringDashboard> ListDashboards() = 0;
    virtual std::string RenderDashboard(const std::string& dashboard_id) = 0;
    
    // Health checks
    virtual SystemHealthSnapshot GetSystemHealth() = 0;
    virtual std::vector<SystemHealthSnapshot> GetHealthHistory(std::chrono::hours range = std::chrono::hours(24)) = 0;
    virtual bool RunHealthCheck(const std::string& component) = 0;
    
    // Notifications
    virtual void RegisterNotificationChannel(const std::string& channel_id,
                                               const std::string& channel_type,
                                               const std::unordered_map<std::string, std::string>& config) = 0;
    virtual bool SendNotification(const std::string& channel_id, const std::string& message) = 0;
    
    // Export
    virtual bool ExportMetrics(const std::string& format, const std::string& destination) = 0;
    virtual std::string GenerateReport(std::chrono::hours range = std::chrono::hours(24)) = 0;
    
    // Statistics
    virtual struct MonitorStatistics {
        uint64_t metrics_collected_24h;
        uint64_t alerts_fired_24h;
        uint64_t alerts_resolved_24h;
        uint32_t active_alert_rules;
        uint32_t active_alerts;
        double average_resolution_time_minutes;
        double false_positive_rate;
    } GetStatistics() = 0;
};

// Local production monitor implementation
class LocalProductionMonitor : public IProductionMonitor {
public:
    LocalProductionMonitor();
    ~LocalProductionMonitor() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    void RecordCounter(const std::string& name, int64_t value,
                        const std::unordered_map<std::string, std::string>& labels = {}) override;
    void RecordGauge(const std::string& name, double value,
                      const std::unordered_map<std::string, std::string>& labels = {}) override;
    void RecordHistogram(const std::string& name, double value,
                          const std::unordered_map<std::string, std::string>& labels = {}) override;
    void RecordTiming(const std::string& name, std::chrono::milliseconds duration,
                       const std::unordered_map<std::string, std::string>& labels = {}) override;
    
    std::optional<TimeSeries> QueryMetric(const std::string& name,
                                              std::chrono::seconds range = std::chrono::seconds(3600)) override;
    std::vector<TimeSeries> QueryMetrics(const std::vector<std::string>& names,
                                            std::chrono::seconds range = std::chrono::seconds(3600)) override;
    std::vector<MetricValue> GetCurrentMetrics() override;
    
    std::string CreateAlertRule(const AlertRule& rule) override;
    bool UpdateAlertRule(const AlertRule& rule) override;
    bool DeleteAlertRule(const std::string& rule_id) override;
    std::optional<AlertRule> GetAlertRule(const std::string& rule_id) override;
    std::vector<AlertRule> ListAlertRules() override;
    bool EnableAlertRule(const std::string& rule_id) override;
    bool DisableAlertRule(const std::string& rule_id) override;
    
    std::vector<AlertInstance> GetActiveAlerts() override;
    std::vector<AlertInstance> GetAlertHistory(std::chrono::hours range = std::chrono::hours(24)) override;
    bool AcknowledgeAlert(const std::string& alert_id, const std::string& user) override;
    bool ResolveAlert(const std::string& alert_id, const std::string& notes) override;
    bool SilenceAlert(const std::string& alert_id, std::chrono::minutes duration) override;
    
    std::string CreateDashboard(const MonitoringDashboard& dashboard) override;
    bool UpdateDashboard(const MonitoringDashboard& dashboard) override;
    bool DeleteDashboard(const std::string& dashboard_id) override;
    std::optional<MonitoringDashboard> GetDashboard(const std::string& dashboard_id) override;
    std::vector<MonitoringDashboard> ListDashboards() override;
    std::string RenderDashboard(const std::string& dashboard_id) override;
    
    SystemHealthSnapshot GetSystemHealth() override;
    std::vector<SystemHealthSnapshot> GetHealthHistory(std::chrono::hours range = std::chrono::hours(24)) override;
    bool RunHealthCheck(const std::string& component) override;
    
    void RegisterNotificationChannel(const std::string& channel_id,
                                       const std::string& channel_type,
                                       const std::unordered_map<std::string, std::string>& config) override;
    bool SendNotification(const std::string& channel_id, const std::string& message) override;
    
    bool ExportMetrics(const std::string& format, const std::string& destination) override;
    std::string GenerateReport(std::chrono::hours range = std::chrono::hours(24)) override;
    
    MonitorStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, TimeSeries> metrics_;
    std::unordered_map<std::string, AlertRule> alert_rules_;
    std::unordered_map<std::string, AlertInstance> active_alerts_;
    std::vector<AlertInstance> alert_history_;
    std::unordered_map<std::string, MonitoringDashboard> dashboards_;
    std::vector<SystemHealthSnapshot> health_history_;
    bool initialized_ = false;
    
    void EvaluateAlertRules();
    bool CheckAlertCondition(const AlertRule& rule, const MetricValue& metric);
    void FireAlert(const AlertRule& rule, const MetricValue& metric);
    std::string GenerateAlertId();
    void PruneOldData();
};

// Global production monitor
extern std::unique_ptr<IProductionMonitor> g_production_monitor;

// Initialize production monitor
bool InitializeProductionMonitor(const std::string& config_path);
void ShutdownProductionMonitor();
bool IsProductionMonitorEnabled();

// Convenience macros for metric recording
#define RAWRXD_RECORD_COUNTER(name, value, ...) \
    if (RawrXD::Operations::g_production_monitor) { \
        RawrXD::Operations::g_production_monitor->RecordCounter(name, value, ##__VA_ARGS__); \
    }

#define RAWRXD_RECORD_GAUGE(name, value, ...) \
    if (RawrXD::Operations::g_production_monitor) { \
        RawrXD::Operations::g_production_monitor->RecordGauge(name, value, ##__VA_ARGS__); \
    }

#define RAWRXD_RECORD_TIMING(name, duration, ...) \
    if (RawrXD::Operations::g_production_monitor) { \
        RawrXD::Operations::g_production_monitor->RecordTiming(name, duration, ##__VA_ARGS__); \
    }

} // namespace Operations
} // namespace RawrXD
