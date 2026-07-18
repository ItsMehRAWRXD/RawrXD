// Phase D.14 Batch 5/5: Edge Monitoring
// Monitor edge devices and deployments
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Edge {

// Forward declarations
struct EdgeMetric;
struct AlertRule;
struct HealthStatus;

// ============================================================================
// Edge Monitoring Types
// ============================================================================

enum class MetricType {
    COUNTER = 0,
    GAUGE = 1,
    HISTOGRAM = 2,
    SUMMARY = 3
};

enum class AlertSeverity {
    INFO = 0,
    WARNING = 1,
    ERROR = 2,
    CRITICAL = 3
};

enum class AlertState {
    PENDING = 0,
    FIRING = 1,
    RESOLVED = 2,
    SILENCED = 3
};

enum class HealthState {
    HEALTHY = 0,
    DEGRADED = 1,
    UNHEALTHY = 2,
    UNKNOWN = 3
};

struct EdgeMetric {
    std::string name;
    std::string description;
    MetricType type;
    std::map<std::string, std::string> labels;
    double value;
    std::chrono::steady_clock::time_point timestamp;
    std::vector<double> buckets;  // For histogram
    std::map<double, double> quantiles;  // For summary
};

struct AlertRule {
    std::string rule_id;
    std::string name;
    std::string expression;
    std::chrono::seconds duration;
    AlertSeverity severity;
    std::map<std::string, std::string> labels;
    std::string summary;
    std::string description;
    bool enabled;
};

struct AlertInstance {
    std::string alert_id;
    std::string rule_id;
    std::map<std::string, std::string> labels;
    AlertState state;
    AlertSeverity severity;
    std::chrono::steady_clock::time_point fired_at;
    std::chrono::steady_clock::time_point resolved_at;
    std::string value;
    std::vector<std::string> notifications_sent;
};

struct HealthStatus {
    std::string component_id;
    std::string component_name;
    HealthState state;
    std::string message;
    std::chrono::steady_clock::time_point checked_at;
    std::chrono::steady_clock::time_point last_healthy_at;
    std::map<std::string, std::any> details;
};

struct DeviceMetrics {
    std::string device_id;
    double cpu_percent;
    double memory_percent;
    double disk_percent;
    double network_in_mbps;
    double network_out_mbps;
    double temperature_celsius;
    double power_consumption_watts;
    int active_connections;
    double inference_latency_ms;
    int inference_throughput;
    std::chrono::steady_clock::time_point timestamp;
};

// ============================================================================
// Metrics Collector
// ============================================================================

class MetricsCollector {
public:
    struct Config {
        std::chrono::seconds collection_interval{15};
        int retention_hours = 24;
        std::string storage_backend;  // prometheus, influxdb, timescaledb
        bool enable_remote_write = true;
        std::string remote_endpoint;
    };
    
    explicit MetricsCollector(const Config& config);
    ~MetricsCollector();
    
    bool Initialize();
    void Shutdown();
    
    // Metric registration
    void RegisterCounter(const std::string& name, const std::string& description,
                         const std::vector<std::string>& label_names);
    void RegisterGauge(const std::string& name, const std::string& description,
                       const std::vector<std::string>& label_names);
    void RegisterHistogram(const std::string& name, const std::string& description,
                           const std::vector<std::string>& label_names,
                           const std::vector<double>& buckets);
    void RegisterSummary(const std::string& name, const std::string& description,
                         const std::vector<std::string>& label_names,
                         const std::vector<double>& quantiles);
    
    // Metric updates
    void IncrementCounter(const std::string& name,
                          const std::map<std::string, std::string>& labels = {},
                          double value = 1.0);
    void SetGauge(const std::string& name,
                  const std::map<std::string, std::string>& labels,
                  double value);
    void ObserveHistogram(const std::string& name,
                          const std::map<std::string, std::string>& labels,
                          double value);
    void ObserveSummary(const std::string& name,
                        const std::map<std::string, std::string>& labels,
                        double value);
    
    // Queries
    std::vector<EdgeMetric> GetMetrics(const std::string& name = "") const;
    std::vector<EdgeMetric> GetMetricsForDevice(const std::string& device_id) const;
    std::vector<EdgeMetric> QueryRange(const std::string& query,
                                       const std::chrono::steady_clock::time_point& start,
                                       const std::chrono::steady_clock::time_point& end) const;
    
    // Export
    std::string ExportToPrometheus() const;
    std::string ExportToJSON() const;
    bool WriteToRemote();
    
private:
    Config config_;
    std::map<std::string, EdgeMetric> metrics_;
    std::map<std::string, std::vector<EdgeMetric>> metric_history_;
    mutable std::mutex metrics_mutex_;
    std::thread collection_thread_;
    std::atomic<bool> running_{false};
    
    void CollectionLoop();
    void CollectSystemMetrics();
    void CollectDeviceMetrics();
    void CleanupOldMetrics();
};

// ============================================================================
// Alert Manager
// ============================================================================

class AlertManager {
public:
    struct Config {
        std::chrono::seconds evaluation_interval{30};
        int max_alerts = 1000;
        std::chrono::hours alert_retention{168};  // 7 days
        bool enable_deduplication = true;
        std::chrono::minutes group_wait{1};
        std::chrono::minutes group_interval{5};
        std::chrono::minutes repeat_interval{4};
    };
    
    struct NotificationChannel {
        std::string name;
        std::string type;  // webhook, email, slack, pagerduty
        std::map<std::string, std::string> config;
        bool enabled;
    };
    
    explicit AlertManager(const Config& config);
    ~AlertManager();
    
    bool Initialize();
    void Shutdown();
    
    // Rule management
    std::string CreateRule(const AlertRule& rule);
    bool UpdateRule(const std::string& rule_id, const AlertRule& rule);
    bool DeleteRule(const std::string& rule_id);
    AlertRule GetRule(const std::string& rule_id) const;
    std::vector<AlertRule> GetAllRules() const;
    bool EnableRule(const std::string& rule_id);
    bool DisableRule(const std::string& rule_id);
    
    // Evaluation
    void EvaluateRules();
    bool EvaluateRule(const AlertRule& rule);
    
    // Alert instances
    std::vector<AlertInstance> GetActiveAlerts() const;
    std::vector<AlertInstance> GetAlertsForDevice(const std::string& device_id) const;
    bool SilenceAlert(const std::string& alert_id, const std::chrono::minutes& duration);
    bool AcknowledgeAlert(const std::string& alert_id, const std::string& user);
    bool ResolveAlert(const std::string& alert_id);
    
    // Notifications
    void AddNotificationChannel(const NotificationChannel& channel);
    bool RemoveNotificationChannel(const std::string& name);
    bool SendNotification(const AlertInstance& alert);
    
private:
    Config config_;
    std::map<std::string, AlertRule> rules_;
    std::map<std::string, AlertInstance> alerts_;
    std::vector<NotificationChannel> channels_;
    mutable std::mutex alerts_mutex_;
    std::thread evaluation_thread_;
    std::atomic<bool> running_{false};
    
    void EvaluationLoop();
    bool ShouldNotify(const AlertInstance& alert, const NotificationChannel& channel);
    bool SendWebhook(const AlertInstance& alert, const std::string& url);
    bool SendEmail(const AlertInstance& alert, const std::vector<std::string>& recipients);
    bool SendSlack(const AlertInstance& alert, const std::string& webhook_url);
};

// ============================================================================
// Health Checker
// ============================================================================

class HealthChecker {
public:
    struct Config {
        std::chrono::seconds check_interval{30};
        int timeout_seconds = 10;
        int unhealthy_threshold = 3;
        int healthy_threshold = 2;
    };
    
    struct HealthCheck {
        std::string check_id;
        std::string component_id;
        std::string component_name;
        std::function<HealthStatus()> check_function;
        std::chrono::seconds interval;
        HealthStatus last_result;
        int consecutive_failures = 0;
        int consecutive_successes = 0;
    };
    
    explicit HealthChecker(const Config& config);
    ~HealthChecker();
    
    bool Initialize();
    void Shutdown();
    
    // Health check registration
    std::string RegisterCheck(const std::string& component_id,
                               const std::string& component_name,
                               std::function<HealthStatus()> check_function,
                               std::chrono::seconds interval);
    bool UnregisterCheck(const std::string& check_id);
    
    // Health queries
    HealthStatus GetHealth(const std::string& component_id) const;
    std::vector<HealthStatus> GetAllHealth() const;
    std::vector<HealthStatus> GetUnhealthy() const;
    bool IsHealthy(const std::string& component_id = "") const;
    
    // Manual checks
    HealthStatus RunCheck(const std::string& check_id);
    std::vector<HealthStatus> RunAllChecks();
    
private:
    Config config_;
    std::map<std::string, HealthCheck> checks_;
    mutable std::mutex checks_mutex_;
    std::thread checker_thread_;
    std::atomic<bool> running_{false};
    
    void CheckerLoop();
    HealthStatus EvaluateCheck(HealthCheck& check);
};

// ============================================================================
// Device Monitor
// ============================================================================

class DeviceMonitor {
public:
    struct Config {
        std::chrono::seconds metrics_interval{30};
        std::chrono::seconds health_interval{60};
        bool enable_predictive_maintenance = true;
        int anomaly_window_size = 100;
        float anomaly_threshold = 3.0f;
    };
    
    struct DeviceHealth {
        std::string device_id;
        HealthState overall_state;
        std::map<std::string, HealthState> component_health;
        std::vector<std::string> active_alerts;
        std::chrono::steady_clock::time_point last_check;
        double health_score;  // 0-100
    };
    
    explicit DeviceMonitor(const Config& config);
    ~DeviceMonitor();
    
    bool Initialize();
    void Shutdown();
    
    // Device monitoring
    bool StartMonitoringDevice(const std::string& device_id);
    bool StopMonitoringDevice(const std::string& device_id);
    bool IsMonitoringDevice(const std::string& device_id) const;
    
    // Metrics collection
    DeviceMetrics CollectDeviceMetrics(const std::string& device_id);
    std::vector<DeviceMetrics> GetMetricsHistory(const std::string& device_id,
                                                  const std::chrono::hours& window) const;
    
    // Health assessment
    DeviceHealth AssessDeviceHealth(const std::string& device_id);
    std::vector<DeviceHealth> GetAllDeviceHealth() const;
    std::vector<std::string> GetUnhealthyDevices() const;
    
    // Predictive maintenance
    std::map<std::string, double> PredictFailures(const std::string& device_id);
    std::chrono::hours EstimateRemainingLife(const std::string& device_id,
                                              const std::string& component);
    std::vector<std::string> RecommendMaintenance(const std::string& device_id);
    
    // Anomaly detection
    bool DetectAnomaly(const std::string& device_id, const DeviceMetrics& metrics);
    std::vector<DeviceMetrics> GetAnomalies(const std::string& device_id,
                                            const std::chrono::days& window) const;
    
private:
    Config config_;
    std::set<std::string> monitored_devices_;
    std::map<std::string, std::vector<DeviceMetrics>> metrics_history_;
    mutable std::mutex monitor_mutex_;
    std::thread monitor_thread_;
    std::atomic<bool> running_{false};
    
    void MonitorLoop();
    void CollectMetricsForDevice(const std::string& device_id);
    HealthState AssessComponent(const std::string& device_id,
                                 const std::string& component,
                                 const DeviceMetrics& metrics);
    double ComputeHealthScore(const DeviceHealth& health);
};

// ============================================================================
// Log Aggregator
// ============================================================================

class LogAggregator {
public:
    struct Config {
        int batch_size = 1000;
        std::chrono::seconds flush_interval{5};
        int retention_days = 30;
        std::string storage_backend;  // elasticsearch, loki, local
        std::vector<std::string> log_sources;
    };
    
    struct LogEntry {
        std::string timestamp;
        std::string level;  // DEBUG, INFO, WARN, ERROR, FATAL
        std::string source;
        std::string device_id;
        std::string message;
        std::map<std::string, std::string> labels;
        std::map<std::string, std::any> fields;
    };
    
    explicit LogAggregator(const Config& config);
    ~LogAggregator();
    
    bool Initialize();
    void Shutdown();
    
    // Log ingestion
    bool IngestLog(const LogEntry& entry);
    bool IngestLogs(const std::vector<LogEntry>& entries);
    bool IngestFromDevice(const std::string& device_id, const std::string& log_data);
    
    // Queries
    std::vector<LogEntry> QueryLogs(const std::string& query,
                                    const std::chrono::steady_clock::time_point& start,
                                    const std::chrono::steady_clock::time_point& end,
                                    int limit = 100) const;
    std::vector<LogEntry> GetLogsForDevice(const std::string& device_id,
                                           const std::chrono::hours& window) const;
    std::vector<LogEntry> GetLogsByLevel(const std::string& level,
                                         const std::chrono::hours& window) const;
    
    // Analysis
    std::map<std::string, int> GetErrorCounts(const std::chrono::hours& window) const;
    std::vector<std::string> ExtractPatterns(const std::chrono::hours& window) const;
    bool DetectLogAnomalies(const std::chrono::hours& window);
    
private:
    Config config_;
    std::queue<LogEntry> log_queue_;
    mutable std::mutex queue_mutex_;
    std::thread aggregation_thread_;
    std::atomic<bool> running_{false};
    
    void AggregationLoop();
    bool FlushBatch(const std::vector<LogEntry>& batch);
    void CleanupOldLogs();
};

// ============================================================================
// Edge Monitoring Runtime
// ============================================================================

class EdgeMonitoringRuntime {
public:
    struct Config {
        MetricsCollector::Config metrics;
        AlertManager::Config alerts;
        HealthChecker::Config health;
        DeviceMonitor::Config device_monitor;
        LogAggregator::Config logs;
    };
    
    explicit EdgeMonitoringRuntime(const Config& config);
    ~EdgeMonitoringRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    MetricsCollector* GetMetricsCollector();
    AlertManager* GetAlertManager();
    HealthChecker* GetHealthChecker();
    DeviceMonitor* GetDeviceMonitor();
    LogAggregator* GetLogAggregator();
    
    // High-level API
    bool MonitorDevice(const std::string& device_id);
    bool UnmonitorDevice(const std::string& device_id);
    
    HealthStatus CheckDeviceHealth(const std::string& device_id);
    std::vector<AlertInstance> GetDeviceAlerts(const std::string& device_id) const;
    
    void CreateAlertRule(const std::string& name,
                         const std::string& expression,
                         AlertSeverity severity);
    
    // Dashboard data
    struct DashboardData {
        int total_devices;
        int online_devices;
        int unhealthy_devices;
        int active_alerts;
        std::vector<DeviceHealth> device_health_summary;
        std::vector<EdgeMetric> key_metrics;
        std::map<std::string, int> alert_counts_by_severity;
    };
    DashboardData GetDashboardData() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<MetricsCollector> metrics_collector_;
    std::unique_ptr<AlertManager> alert_manager_;
    std::unique_ptr<HealthChecker> health_checker_;
    std::unique_ptr<DeviceMonitor> device_monitor_;
    std::unique_ptr<LogAggregator> log_aggregator_;
};

} // namespace Edge
} // namespace Sovereign
