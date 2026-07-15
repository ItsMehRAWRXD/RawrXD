/**
 * OperationsMaintenance.hpp
 *
 * Phase K Batch 5/5: Operations & Maintenance
 *
 * Operational tooling for monitoring, alerting, incident management,
 * and maintenance automation.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>

namespace Deployment {

// ============================================================================
// Forward Declarations
// ============================================================================

class IncidentManager;
class MaintenanceWindow;
class RunbookLibrary;
class OperationalDashboard;

// ============================================================================
// Incident Severity
// ============================================================================

enum class IncidentSeverity {
    CRITICAL,    // Service down, data loss
    HIGH,        // Major functionality impaired
    MEDIUM,      // Partial functionality affected
    LOW,         // Minor issue, workaround available
    INFO         // Informational, no impact
};

std::string IncidentSeverityToString(IncidentSeverity severity);

// ============================================================================
// Incident Status
// ============================================================================

enum class IncidentStatus {
    DETECTED,
    ACKNOWLEDGED,
    INVESTIGATING,
    IDENTIFIED,
    MITIGATING,
    RESOLVED,
    POST_MORTEM,
    CLOSED
};

// ============================================================================
// Incident
// ============================================================================

/**
 * Incident record.
 */
struct Incident {
    std::string id;
    std::string title;
    std::string description;
    IncidentSeverity severity;
    IncidentStatus status;
    std::string service;
    std::vector<std::string> affectedServices;
    std::string detectedBy;
    std::chrono::system_clock::time_point detectedAt;
    std::chrono::system_clock::time_point acknowledgedAt;
    std::chrono::system_clock::time_point resolvedAt;
    std::string acknowledgedBy;
    std::string resolvedBy;
    std::string rootCause;
    std::string resolution;
    std::vector<std::map<std::string, std::string>> timeline;
    std::vector<std::string> responders;
    std::vector<std::string> communications;
    std::string postMortemUrl;
    bool customerFacing;
    std::optional<std::string> parentIncident;
};

// ============================================================================
// Incident Manager
// ============================================================================

/**
 * Incident management system.
 */
class IncidentManager {
public:
    struct Config {
        std::string pagerDutyKey;
        std::string opsgenieKey;
        std::string slackWebhook;
        std::string emailFrom;
        std::string escalationPolicy;
        uint32_t autoEscalationMinutes;
        bool autoCreatePostMortem;
    };
    
    struct Alert {
        std::string id;
        std::string name;
        std::string description;
        IncidentSeverity severity;
        std::map<std::string, std::string> labels;
        std::chrono::system_clock::time_point firedAt;
        std::optional<std::chrono::system_clock::time_point> resolvedAt;
        std::string source;
        std::string query;
        double value;
        double threshold;
    };
    
    explicit IncidentManager(const Config& config);
    
    // Incident lifecycle
    std::string CreateIncident(const Incident& incident);
    bool UpdateIncident(const std::string& id, const Incident& incident);
    bool AcknowledgeIncident(const std::string& id, const std::string& user);
    bool ResolveIncident(const std::string& id, const std::string& user,
                         const std::string& resolution);
    bool CloseIncident(const std::string& id);
    bool ReopenIncident(const std::string& id);
    
    // Queries
    std::optional<Incident> GetIncident(const std::string& id) const;
    std::vector<Incident> GetOpenIncidents() const;
    std::vector<Incident> GetIncidentsByService(const std::string& service) const;
    std::vector<Incident> GetIncidentsBySeverity(IncidentSeverity severity) const;
    std::vector<Incident> GetIncidentsByStatus(IncidentStatus status) const;
    std::vector<Incident> GetIncidents(
        std::chrono::system_clock::time_point from,
        std::chrono::system_clock::time_point to) const;
    
    // Alerts
    void ReceiveAlert(const Alert& alert);
    void ResolveAlert(const std::string& alertId);
    std::vector<Alert> GetActiveAlerts() const;
    
    // Notifications
    void NotifyPagerDuty(const Incident& incident);
    void NotifyOpsgenie(const Incident& incident);
    void NotifySlack(const Incident& incident);
    void NotifyEmail(const Incident& incident, const std::vector<std::string>& recipients);
    void NotifySMS(const Incident& incident, const std::vector<std::string>& phoneNumbers);
    
    // Escalation
    void EscalateIncident(const std::string& id);
    void SetEscalationPolicy(const std::string& incidentId, const std::string& policy);
    
    // Post-mortem
    bool CreatePostMortem(const std::string& incidentId);
    std::string GeneratePostMortemTemplate(const Incident& incident);
    
    // Metrics
    struct Metrics {
        uint32_t totalIncidents;
        uint32_t openIncidents;
        uint32_t resolvedIncidents;
        double mttr;  // Mean Time To Resolution
        double mtbf;  // Mean Time Between Failures
        std::map<IncidentSeverity, uint32_t> incidentsBySeverity;
        std::map<std::string, uint32_t> incidentsByService;
    };
    Metrics GetMetrics(std::chrono::system_clock::time_point since) const;
    
    // SLA
    struct SLAMetrics {
        double availability;
        double uptimePercentage;
        uint32_t breaches;
        std::chrono::seconds totalDowntime;
    };
    SLAMetrics CalculateSLA(const std::string& service,
                           std::chrono::system_clock::time_point from,
                           std::chrono::system_clock::time_point to) const;
    
private:
    Config config_;
    std::map<std::string, Incident> incidents_;
    std::map<std::string, Alert> alerts_;
    mutable std::mutex mutex_;
    
    std::string GenerateIncidentId();
    void StartEscalationTimer(const std::string& incidentId);
};

// ============================================================================
// Maintenance Window
// ============================================================================

/**
 * Maintenance window management.
 */
class MaintenanceWindow {
public:
    struct Window {
        std::string id;
        std::string name;
        std::string description;
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
        std::vector<std::string> affectedServices;
        std::vector<std::string> affectedRegions;
        std::string createdBy;
        std::vector<std::string> approvers;
        bool approved;
        std::string status;  // scheduled, in_progress, completed, cancelled
        std::string changeTicket;
        std::vector<std::string> notifications;
        bool customerFacing;
        std::string communicationTemplate;
    };
    
    struct RecurringWindow {
        std::string id;
        std::string name;
        std::string cronExpression;
        std::chrono::minutes duration;
        std::vector<std::string> affectedServices;
        std::string timezone;
    };
    
    MaintenanceWindow();
    
    // Window management
    std::string ScheduleWindow(const Window& window);
    bool UpdateWindow(const std::string& id, const Window& window);
    bool CancelWindow(const std::string& id, const std::string& reason);
    bool ApproveWindow(const std::string& id, const std::string& approver);
    
    // Recurring windows
    std::string CreateRecurringWindow(const RecurringWindow& window);
    bool UpdateRecurringWindow(const std::string& id, const RecurringWindow& window);
    bool DeleteRecurringWindow(const std::string& id);
    
    // Queries
    std::optional<Window> GetWindow(const std::string& id) const;
    std::vector<Window> GetUpcomingWindows() const;
    std::vector<Window> GetActiveWindows() const;
    std::vector<Window> GetWindowsForService(const std::string& service) const;
    std::vector<Window> GetWindows(
        std::chrono::system_clock::time_point from,
        std::chrono::system_clock::time_point to) const;
    
    // Conflict detection
    std::vector<Window> FindConflicts(const Window& window) const;
    bool HasActiveMaintenance(const std::string& service) const;
    
    // Notifications
    void NotifyStakeholders(const Window& window);
    void NotifyCustomers(const Window& window);
    void SendReminder(const std::string& windowId, std::chrono::minutes before);
    
    // Calendar integration
    bool ExportToICal(const std::string& windowId, const std::string& outputPath);
    bool SyncToCalendar(const std::string& windowId, const std::string& calendarId);
    
private:
    std::map<std::string, Window> windows_;
    std::map<std::string, RecurringWindow> recurringWindows_;
    mutable std::mutex mutex_;
    
    std::string GenerateWindowId();
    void ScheduleNotifications(const Window& window);
};

// ============================================================================
// Runbook
// ============================================================================

/**
 * Operational runbook.
 */
struct Runbook {
    std::string id;
    std::string title;
    std::string description;
    std::string category;
    std::vector<std::string> tags;
    std::vector<std::string> relatedAlerts;
    std::vector<std::string> relatedServices;
    
    struct Step {
        int number;
        std::string title;
        std::string description;
        std::string command;
        std::string expectedOutput;
        std::string validationCommand;
        bool automated;
        bool requiresApproval;
        std::vector<std::string> approvers;
        uint32_t timeoutSeconds;
        bool rollbackOnFailure;
        std::string rollbackCommand;
    };
    std::vector<Step> steps;
    
    // Metadata
    std::string createdBy;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    std::string lastExecutedBy;
    std::chrono::system_clock::time_point lastExecutedAt;
    uint32_t executionCount;
    double successRate;
    bool isActive;
};

// ============================================================================
// Runbook Library
// ============================================================================

/**
 * Runbook management library.
 */
class RunbookLibrary {
public:
    RunbookLibrary();
    
    // CRUD
    void AddRunbook(const Runbook& runbook);
    bool UpdateRunbook(const std::string& id, const Runbook& runbook);
    bool DeleteRunbook(const std::string& id);
    std::optional<Runbook> GetRunbook(const std::string& id) const;
    
    // Search
    std::vector<Runbook> GetRunbooks() const;
    std::vector<Runbook> GetRunbooksByCategory(const std::string& category) const;
    std::vector<Runbook> GetRunbooksByTag(const std::string& tag) const;
    std::vector<Runbook> GetRunbooksByService(const std::string& service) const;
    std::vector<Runbook> Search(const std::string& query) const;
    std::optional<Runbook> FindForAlert(const std::string& alertName) const;
    
    // Execution
    struct ExecutionResult {
        std::string runbookId;
        std::string executionId;
        bool success;
        std::string errorMessage;
        std::vector<std::pair<int, bool>> stepResults;
        std::chrono::seconds duration;
        std::string executedBy;
        std::chrono::system_clock::time_point executedAt;
        std::string output;
    };
    
    ExecutionResult Execute(const std::string& runbookId,
                            const std::map<std::string, std::string>& variables);
    ExecutionResult ExecuteStep(const std::string& runbookId, int stepNumber);
    bool ApproveStep(const std::string& executionId, int stepNumber,
                     const std::string& approver);
    bool Rollback(const std::string& executionId);
    
    // History
    std::vector<ExecutionResult> GetExecutionHistory(const std::string& runbookId) const;
    std::optional<ExecutionResult> GetExecution(const std::string& executionId) const;
    
    // Import/Export
    bool ImportFromMarkdown(const std::string& filePath);
    bool ExportToMarkdown(const std::string& runbookId, const std::string& filePath);
    bool ExportToConfluence(const std::string& runbookId, const std::string& spaceKey);
    
private:
    std::map<std::string, Runbook> runbooks_;
    std::map<std::string, ExecutionResult> executions_;
    mutable std::mutex mutex_;
    
    std::string GenerateExecutionId();
    bool ExecuteCommand(const std::string& command, std::string& output,
                        uint32_t timeoutSeconds);
};

// ============================================================================
// Operational Dashboard
// ============================================================================

/**
 * Operational dashboard for monitoring and control.
 */
class OperationalDashboard {
public:
    struct SystemHealth {
        std::string service;
        std::string status;  // healthy, degraded, unhealthy
        double availability;
        std::chrono::seconds latency;
        uint32_t errorRate;
        std::chrono::system_clock::time_point lastChecked;
        std::optional<std::string> incidentId;
    };
    
    struct Metric {
        std::string name;
        double value;
        std::string unit;
        std::chrono::system_clock::time_point timestamp;
        std::map<std::string, std::string> labels;
    };
    
    struct Widget {
        std::string id;
        std::string type;  // chart, table, number, status, log
        std::string title;
        std::string query;
        std::map<std::string, std::string> config;
        uint32_t refreshInterval;
    };
    
    OperationalDashboard();
    
    // Health monitoring
    void UpdateServiceHealth(const SystemHealth& health);
    std::vector<SystemHealth> GetSystemHealth() const;
    std::vector<SystemHealth> GetUnhealthyServices() const;
    
    // Metrics
    void IngestMetric(const Metric& metric);
    std::vector<Metric> QueryMetrics(const std::string& query,
                                        std::chrono::system_clock::time_point from,
                                        std::chrono::system_clock::time_point to);
    
    // Widgets
    void AddWidget(const Widget& widget);
    void RemoveWidget(const std::string& id);
    std::vector<Widget> GetWidgets() const;
    std::string RenderWidget(const std::string& id);
    
    // Dashboards
    struct Dashboard {
        std::string id;
        std::string name;
        std::vector<Widget> widgets;
        std::map<std::string, std::string> filters;
        std::string timeRange;
    };
    
    void CreateDashboard(const Dashboard& dashboard);
    void UpdateDashboard(const std::string& id, const Dashboard& dashboard);
    void DeleteDashboard(const std::string& id);
    std::optional<Dashboard> GetDashboard(const std::string& id) const;
    std::vector<Dashboard> GetDashboards() const;
    
    // Real-time updates
    using UpdateCallback = std::function<void(const std::string& type,
                                               const std::map<std::string, std::string>&)>;
    void Subscribe(UpdateCallback callback);
    void Unsubscribe();
    
    // Actions
    bool ExecuteAction(const std::string& actionId,
                       const std::map<std::string, std::string>& params);
    std::vector<std::map<std::string, std::string>> GetAvailableActions() const;
    
    // Export
    std::string ExportDashboard(const std::string& id, const std::string& format);
    
private:
    std::map<std::string, SystemHealth> healthData_;
    std::vector<Metric> metrics_;
    std::map<std::string, Widget> widgets_;
    std::map<std::string, Dashboard> dashboards_;
    std::vector<UpdateCallback> subscribers_;
    mutable std::mutex mutex_;
    
    void NotifySubscribers(const std::string& type,
                           const std::map<std::string, std::string>& data);
};

// ============================================================================
// Backup Manager
// ============================================================================

/**
 * Backup and restore management.
 */
class BackupManager {
public:
    struct BackupConfig {
        std::string name;
        std::string type;  // database, filesystem, object-storage
        std::string source;
        std::string destination;
        std::string schedule;  // cron expression
        uint32_t retentionDays;
        bool compression;
        bool encryption;
        std::string encryptionKey;
        std::map<std::string, std::string> options;
    };
    
    struct Backup {
        std::string id;
        std::string configName;
        std::string status;  // pending, running, completed, failed
        std::chrono::system_clock::time_point startedAt;
        std::optional<std::chrono::system_clock::time_point> completedAt;
        uint64_t size;
        std::string checksum;
        std::optional<std::string> errorMessage;
        bool verified;
    };
    
    explicit BackupManager(const std::string& storagePath);
    
    // Configuration
    void AddBackupConfig(const BackupConfig& config);
    void RemoveBackupConfig(const std::string& name);
    std::vector<BackupConfig> GetBackupConfigs() const;
    
    // Execution
    std::string ExecuteBackup(const std::string& configName);
    bool RestoreBackup(const std::string& backupId, const std::string& destination);
    bool VerifyBackup(const std::string& backupId);
    bool DeleteBackup(const std::string& backupId);
    
    // Scheduling
    void ScheduleBackup(const std::string& configName);
    void UnscheduleBackup(const std::string& configName);
    
    // Queries
    std::vector<Backup> GetBackups(const std::string& configName) const;
    std::optional<Backup> GetBackup(const std::string& backupId) const;
    std::vector<Backup> GetRecentBackups(uint32_t count) const;
    
    // Retention
    void ApplyRetentionPolicy(const std::string& configName);
    void ApplyAllRetentionPolicies();
    
    // Replication
    bool ReplicateBackup(const std::string& backupId, const std::string& destination);
    
private:
    std::string storagePath_;
    std::map<std::string, BackupConfig> configs_;
    std::map<std::string, Backup> backups_;
    mutable std::mutex mutex_;
    
    std::string GenerateBackupId();
    bool ExecuteDatabaseBackup(const BackupConfig& config, Backup& backup);
    bool ExecuteFilesystemBackup(const BackupConfig& config, Backup& backup);
    bool ExecuteObjectStorageBackup(const BackupConfig& config, Backup& backup);
};

// ============================================================================
// Log Management
// ============================================================================

/**
 * Centralized log management.
 */
class LogManager {
public:
    struct LogEntry {
        std::chrono::system_clock::time_point timestamp;
        std::string level;
        std::string service;
        std::string message;
        std::map<std::string, std::string> fields;
        std::string traceId;
        std::string spanId;
    };
    
    struct LogQuery {
        std::optional<std::string> service;
        std::optional<std::string> level;
        std::optional<std::string> messageContains;
        std::optional<std::chrono::system_clock::time_point> from;
        std::optional<std::chrono::system_clock::time_point> to;
        std::optional<std::string> traceId;
        std::map<std::string, std::string> fields;
        uint32_t limit;
    };
    
    explicit LogManager(const std::string& storagePath);
    
    // Ingestion
    void IngestLog(const LogEntry& entry);
    void IngestLogs(const std::vector<LogEntry>& entries);
    
    // Query
    std::vector<LogEntry> Query(const LogQuery& query);
    std::vector<LogEntry> Search(const std::string& query);
    std::vector<LogEntry> GetTrace(const std::string& traceId);
    
    // Aggregation
    std::map<std::string, uint64_t> GetLogCountsByService(
        std::chrono::system_clock::time_point from,
        std::chrono::system_clock::time_point to);
    std::map<std::string, uint64_t> GetLogCountsByLevel(
        std::chrono::system_clock::time_point from,
        std::chrono::system_clock::time_point to);
    
    // Export
    bool ExportToFile(const LogQuery& query, const std::string& filePath);
    bool ExportToElasticsearch(const LogQuery& query, const std::string& esUrl);
    
    // Retention
    void SetRetentionPolicy(uint32_t days);
    void ApplyRetentionPolicy();
    
private:
    std::string storagePath_;
    std::vector<LogEntry> logs_;
    mutable std::mutex mutex_;
    uint32_t retentionDays_;
    
    bool MatchesQuery(const LogEntry& entry, const LogQuery& query);
};

// ============================================================================
// Capacity Planning
// ============================================================================

/**
 * Capacity planning and forecasting.
 */
class CapacityPlanner {
public:
    struct ResourceUsage {
        std::string resource;
        std::string service;
        double currentUsage;
        double capacity;
        double utilizationPercent;
        std::chrono::system_clock::time_point timestamp;
    };
    
    struct Forecast {
        std::string resource;
        std::vector<std::pair<std::chrono::system_clock::time_point, double>> predictions;
        std::chrono::system_clock::time_point predictedExhaustion;
        double confidence;
    };
    
    struct Recommendation {
        std::string resource;
        std::string action;  // scale_up, scale_out, optimize, alert
        std::string reason;
        double currentCapacity;
        double recommendedCapacity;
        std::chrono::system_clock::time_point recommendedBy;
        double estimatedCost;
    };
    
    CapacityPlanner();
    
    // Data collection
    void RecordUsage(const ResourceUsage& usage);
    std::vector<ResourceUsage> GetUsageHistory(const std::string& resource,
                                                  std::chrono::hours duration);
    
    // Forecasting
    Forecast ForecastUsage(const std::string& resource,
                             std::chrono::hours horizon);
    std::vector<Forecast> ForecastAll(std::chrono::hours horizon);
    
    // Recommendations
    std::vector<Recommendation> GetRecommendations();
    std::vector<Recommendation> GetUrgentRecommendations();
    
    // Scenarios
    struct Scenario {
        std::string name;
        double growthRate;
        uint32_t newUsers;
        std::vector<std::string> newServices;
        std::chrono::system_clock::time_point startDate;
    };
    std::vector<Forecast> SimulateScenario(const Scenario& scenario);
    
    // Reporting
    std::string GenerateCapacityReport();
    bool ExportToFile(const std::string& filePath);
    
private:
    std::vector<ResourceUsage> usageHistory_;
    mutable std::mutex mutex_;
    
    double PredictUsage(const std::string& resource,
                        std::chrono::system_clock::time_point time);
    std::vector<Recommendation> AnalyzeCapacity();
};

} // namespace Deployment
