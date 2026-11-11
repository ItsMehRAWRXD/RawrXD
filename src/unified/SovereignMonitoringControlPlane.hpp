// Phase D.9 Batch 4/5: Monitoring & Control Plane
// Centralized monitoring and control for the entire system
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <queue>

namespace Sovereign {
namespace Unified {

// ============================================================================
// Metric Types
// ============================================================================

enum class MetricType {
    COUNTER = 0,
    GAUGE = 1,
    HISTOGRAM = 2,
    SUMMARY = 3
};

struct MetricValue {
    std::string name;
    MetricType type;
    double value = 0.0;
    std::map<std::string, std::string> labels;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, double> buckets;  // For histograms
    double sum = 0.0;  // For histograms/summaries
    uint64_t count = 0;  // For histograms/summaries
};

// ============================================================================
// Metric Collector
// ============================================================================

class MetricCollector {
public:
    struct Config {
        std::string service_name;
        std::string instance_id;
        int flush_interval_seconds = 60;
        size_t max_metrics = 10000;
        bool enable_prometheus = true;
        bool enable_influxdb = false;
        std::string influxdb_url;
    };
    
    explicit MetricCollector(const Config& config);
    ~MetricCollector();
    
    bool Initialize();
    void Shutdown();
    
    // Counter operations
    void Counter(const std::string& name, double value = 1.0,
                 const std::map<std::string, std::string>& labels = {});
    void Increment(const std::string& name,
                   const std::map<std::string, std::string>& labels = {});
    
    // Gauge operations
    void Gauge(const std::string& name, double value,
               const std::map<std::string, std::string>& labels = {});
    void Set(const std::string& name, double value,
             const std::map<std::string, std::string>& labels = {});
    void Add(const std::string& name, double delta,
             const std::map<std::string, std::string>& labels = {});
    void Subtract(const std::string& name, double delta,
                  const std::map<std::string, std::string>& labels = {});
    
    // Histogram operations
    void Histogram(const std::string& name, double value,
                   const std::map<std::string, std::string>& labels = {});
    void Observe(const std::string& name, double value,
                 const std::map<std::string, std::string>& labels = {});
    void DefineHistogramBuckets(const std::string& name,
                                 const std::vector<double>& buckets);
    
    // Timer
    class Timer {
    public:
        Timer(MetricCollector* collector, const std::string& name,
              const std::map<std::string, std::string>& labels);
        ~Timer();
        void Stop();
    private:
        MetricCollector* collector_;
        std::string name_;
        std::map<std::string, std::string> labels_;
        std::chrono::steady_clock::time_point start_;
        bool stopped_ = false;
    };
    
    std::unique_ptr<Timer> StartTimer(const std::string& name,
                                         const std::map<std::string, std::string>& labels = {});
    
    // Query
    std::vector<MetricValue> GetMetrics(const std::string& pattern = "*");
    double GetValue(const std::string& name,
                    const std::map<std::string, std::string>& labels = {});
    
    // Export
    std::string ExportPrometheus();
    std::string ExportJSON();
    std::string ExportInfluxDBLineProtocol();
    bool PushToGateway(const std::string& gateway_url);
    bool WriteToInfluxDB(const std::string& database);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, std::vector<MetricValue>> metrics_;
    std::map<std::string, std::vector<double>> histogram_buckets_;
    std::mutex metrics_mutex_;
    
    std::thread flush_thread_;
    
    void FlushLoop();
    void CleanupOldMetrics();
};

// ============================================================================
// Health Monitor
// ============================================================================

enum class HealthStatus {
    UNKNOWN = 0,
    HEALTHY = 1,
    DEGRADED = 2,
    UNHEALTHY = 3
};

struct HealthCheck {
    std::string name;
    std::function<HealthStatus()> check;
    std::chrono::seconds interval{30};
    std::chrono::seconds timeout{5};
    int failure_threshold = 3;
    std::vector<std::string> tags;
};

struct HealthResult {
    std::string check_name;
    HealthStatus status;
    std::string message;
    std::chrono::steady_clock::time_point checked_at;
    std::chrono::milliseconds duration{0};
    std::map<std::string, std::string> details;
};

class HealthMonitor {
public:
    struct Config {
        std::chrono::seconds check_interval{30};
        int max_concurrent_checks = 10;
        bool enable_detailed_logging = true;
    };
    
    explicit HealthMonitor(const Config& config);
    ~HealthMonitor();
    
    bool Initialize();
    void Shutdown();
    
    // Health check registration
    bool RegisterCheck(const HealthCheck& check);
    bool UnregisterCheck(const std::string& name);
    
    // Manual checks
    HealthResult RunCheck(const std::string& name);
    std::vector<HealthResult> RunAllChecks();
    
    // Status
    HealthStatus GetOverallStatus() const;
    std::map<std::string, HealthStatus> GetAllStatuses() const;
    std::vector<std::string> GetFailingChecks() const;
    
    // Events
    using HealthChangeHandler = std::function<void(const std::string& check_name,
                                                      HealthStatus old_status,
                                                      HealthStatus new_status)>;
    void OnHealthChange(HealthChangeHandler handler);
    
    // Built-in checks
    void RegisterHTTPCheck(const std::string& name, const std::string& url,
                           int expected_status = 200);
    void RegisterTCPCheck(const std::string& name, const std::string& host, int port);
    void RegisterDiskCheck(const std::string& name, const std::string& path,
                           double max_usage_percent = 90.0);
    void RegisterMemoryCheck(const std::string& name, double max_usage_percent = 90.0);
    void RegisterCustomCheck(const std::string& name, std::function<HealthStatus()> check);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, HealthCheck> checks_;
    std::map<std::string, HealthResult> results_;
    std::map<std::string, int> failure_counts_;
    mutable std::mutex checks_mutex_;
    
    std::thread monitor_thread_;
    std::vector<HealthChangeHandler> change_handlers_;
    std::mutex handlers_mutex_;
    
    void MonitorLoop();
    void RunCheckInternal(const HealthCheck& check);
    void NotifyHealthChange(const std::string& name, HealthStatus old_status,
                            HealthStatus new_status);
};

// ============================================================================
// Alert Manager
// ============================================================================

enum class AlertSeverity {
    INFO = 0,
    WARNING = 1,
    CRITICAL = 2,
    EMERGENCY = 3
};

struct AlertRule {
    std::string id;
    std::string name;
    std::string condition;  // PromQL-like expression
    std::chrono::seconds for_duration{0};
    AlertSeverity severity = AlertSeverity::WARNING;
    std::map<std::string, std::string> labels;
    std::map<std::string, std::string> annotations;
    std::vector<std::string> receivers;
    bool enabled = true;
};

struct Alert {
    std::string id;
    std::string rule_id;
    AlertSeverity severity;
    std::string status;  // firing, resolved
    std::map<std::string, std::string> labels;
    std::map<std::string, std::string> annotations;
    std::chrono::steady_clock::time_point starts_at;
    std::chrono::steady_clock::time_point ends_at;
    int firing_count = 0;
};

class AlertManager {
public:
    struct Config {
        std::string alertmanager_url;
        int evaluation_interval_seconds = 15;
        int group_wait_seconds = 30;
        int group_interval_seconds = 300;
        int repeat_interval_seconds = 14400;
        std::string default_receiver = "default";
    };
    
    explicit AlertManager(const Config& config);
    ~AlertManager();
    
    bool Initialize();
    void Shutdown();
    
    // Rule management
    bool AddRule(const AlertRule& rule);
    bool RemoveRule(const std::string& rule_id);
    bool UpdateRule(const std::string& rule_id, const AlertRule& rule);
    std::vector<AlertRule> GetRules() const;
    
    // Alert handling
    void FireAlert(const Alert& alert);
    void ResolveAlert(const std::string& alert_id);
    std::vector<Alert> GetActiveAlerts() const;
    std::vector<Alert> GetAlertHistory(std::chrono::hours duration = std::chrono::hours(24)) const;
    
    // Receivers
    void AddEmailReceiver(const std::string& name, const std::vector<std::string>& to,
                          const std::string& smtp_server);
    void AddSlackReceiver(const std::string& name, const std::string& webhook_url,
                          const std::string& channel);
    void AddPagerDutyReceiver(const std::string& name, const std::string& service_key);
    void AddWebhookReceiver(const std::string& name, const std::string& url,
                            const std::map<std::string, std::string>& headers = {});
    void AddOpsGenieReceiver(const std::string& name, const std::string& api_key);
    
    // Silences
    bool SilenceAlert(const std::string& matcher, std::chrono::hours duration,
                      const std::string& comment);
    bool UnsilenceAlert(const std::string& silence_id);
    std::vector<std::string> GetSilences() const;
    
    // Notification
    void NotifyReceivers(const Alert& alert);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, AlertRule> rules_;
    std::map<std::string, Alert> active_alerts_;
    std::vector<Alert> alert_history_;
    mutable std::mutex alerts_mutex_;
    
    struct Receiver {
        std::string type;  // email, slack, pagerduty, webhook, opsgenie
        std::map<std::string, std::string> config;
    };
    std::map<std::string, Receiver> receivers_;
    
    std::thread evaluation_thread_;
    
    void EvaluationLoop();
    bool EvaluateRule(const AlertRule& rule);
    void SendNotification(const std::string& receiver_type, const Receiver& receiver,
                          const Alert& alert);
};

// ============================================================================
// Control Plane
// ============================================================================

enum class OperationType {
    DEPLOY = 0,
    SCALE = 1,
    UPDATE = 2,
    ROLLBACK = 3,
    RESTART = 4,
    DELETE = 5,
    CONFIGURE = 6,
    BACKUP = 7,
    RESTORE = 8
};

enum class OperationStatus {
    PENDING = 0,
    RUNNING = 1,
    COMPLETED = 2,
    FAILED = 3,
    CANCELLED = 4,
    TIMEOUT = 5
};

struct Operation {
    std::string id;
    OperationType type;
    std::string target;  // service, deployment, node
    std::map<std::string, std::string> parameters;
    OperationStatus status = OperationStatus::PENDING;
    std::string error_message;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;
    int progress_percent = 0;
    std::vector<std::string> logs;
    std::string initiated_by;
};

class ControlPlane {
public:
    struct Config {
        int max_concurrent_operations = 10;
        std::chrono::seconds operation_timeout{300};
        bool enable_audit_log = true;
        std::string audit_log_path;
    };
    
    explicit ControlPlane(const Config& config);
    ~ControlPlane();
    
    bool Initialize();
    void Shutdown();
    
    // Operations
    std::string SubmitOperation(const Operation& operation);
    bool CancelOperation(const std::string& operation_id);
    Operation GetOperation(const std::string& operation_id) const;
    std::vector<Operation> GetOperations(OperationStatus status = OperationStatus::PENDING) const;
    std::vector<Operation> GetOperationHistory(int limit = 100) const;
    
    // Deployment operations
    std::string DeployService(const std::string& service_name,
                              const std::string& version,
                              const std::map<std::string, std::string>& config);
    std::string ScaleService(const std::string& service_name, int replicas);
    std::string UpdateService(const std::string& service_name,
                               const std::map<std::string, std::string& config);
    std::string RollbackService(const std::string& service_name, const std::string& version);
    std::string RestartService(const std::string& service_name);
    std::string DeleteService(const std::string& service_name);
    
    // Configuration operations
    std::string UpdateConfiguration(const std::string& component,
                                     const std::map<std::string, std::string>& config);
    std::string RollbackConfiguration(const std::string& component, int version);
    
    // Backup/Restore
    std::string CreateBackup(const std::string& target, const std::string& destination);
    std::string RestoreFromBackup(const std::string& backup_id, const std::string& target);
    
    // Events
    using OperationUpdateHandler = std::function<void(const Operation& operation)>;
    void OnOperationUpdate(OperationUpdateHandler handler);
    
    // Audit
    std::vector<std::string> GetAuditLog(std::chrono::hours duration = std::chrono::hours(24)) const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, Operation> operations_;
    std::vector<Operation> operation_history_;
    mutable std::mutex operations_mutex_;
    
    std::queue<std::string> pending_operations_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    std::vector<std::thread> worker_threads_;
    std::vector<OperationUpdateHandler> update_handlers_;
    std::mutex handlers_mutex_;
    
    std::vector<std::string> audit_log_;
    mutable std::mutex audit_mutex_;
    
    void WorkerLoop();
    void ExecuteOperation(Operation& operation);
    void UpdateOperationStatus(const std::string& operation_id, OperationStatus status);
    void LogAudit(const std::string& action, const std::string& target,
                  const std::string& user);
    void NotifyOperationUpdate(const Operation& operation);
};

// ============================================================================
// Dashboard API
// ============================================================================

struct DashboardWidget {
    std::string id;
    std::string type;  // chart, metric, table, log, alert
    std::string title;
    std::map<std::string, std::string> config;
    std::chrono::seconds refresh_interval{30};
};

struct Dashboard {
    std::string id;
    std::string name;
    std::string description;
    std::vector<DashboardWidget> widgets;
    std::map<std::string, std::string> layout;
    std::vector<std::string> viewers;
    std::vector<std::string> editors;
};

class DashboardAPI {
public:
    struct Config {
        int max_dashboards = 100;
        int max_widgets_per_dashboard = 20;
        bool enable_realtime = true;
    };
    
    explicit DashboardAPI(const Config& config);
    
    // Dashboard management
    bool CreateDashboard(const Dashboard& dashboard);
    bool UpdateDashboard(const std::string& dashboard_id, const Dashboard& dashboard);
    bool DeleteDashboard(const std::string& dashboard_id);
    Dashboard GetDashboard(const std::string& dashboard_id) const;
    std::vector<Dashboard> ListDashboards() const;
    
    // Widget operations
    bool AddWidget(const std::string& dashboard_id, const DashboardWidget& widget);
    bool UpdateWidget(const std::string& dashboard_id, const std::string& widget_id,
                      const DashboardWidget& widget);
    bool RemoveWidget(const std::string& dashboard_id, const std::string& widget_id);
    
    // Data queries
    std::map<std::string, std::any> QueryWidgetData(const std::string& dashboard_id,
                                                       const std::string& widget_id,
                                                       const std::map<std::string, std::string>& params);
    
    // Real-time updates
    using DataUpdateHandler = std::function<void(const std::string& widget_id,
                                                   const std::map<std::string, std::any>& data)>;
    void SubscribeToUpdates(const std::string& dashboard_id, DataUpdateHandler handler);
    void UnsubscribeFromUpdates(const std::string& dashboard_id);
    
private:
    Config config_;
    std::map<std::string, Dashboard> dashboards_;
    mutable std::mutex dashboards_mutex_;
};

// ============================================================================
// Monitoring & Control Plane Runtime
// ============================================================================

class MonitoringControlPlaneRuntime {
public:
    struct Config {
        MetricCollector::Config metrics;
        HealthMonitor::Config health;
        AlertManager::Config alerts;
        ControlPlane::Config control;
        DashboardAPI::Config dashboard;
    };
    
    explicit MonitoringControlPlaneRuntime(const Config& config);
    ~MonitoringControlPlaneRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    MetricCollector* GetMetricCollector();
    HealthMonitor* GetHealthMonitor();
    AlertManager* GetAlertManager();
    ControlPlane* GetControlPlane();
    DashboardAPI* GetDashboardAPI();
    
    // Unified operations
    std::map<std::string, std::any> GetSystemStatus();
    bool ExecuteOperation(const std::string& operation_type,
                          const std::map<std::string, std::string>& params);
    
    // Health
    bool IsHealthy() const;
    std::map<std::string, HealthStatus> GetSubsystemHealth() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<MetricCollector> metrics_;
    std::unique_ptr<HealthMonitor> health_;
    std::unique_ptr<AlertManager> alerts_;
    std::unique_ptr<ControlPlane> control_;
    std::unique_ptr<DashboardAPI> dashboard_;
};

} // namespace Unified
} // namespace Sovereign
