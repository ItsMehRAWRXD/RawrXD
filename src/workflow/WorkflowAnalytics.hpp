/**
 * WorkflowAnalytics.hpp
 *
 * Phase O Batch 5/5: Workflow Monitoring & Analytics
 *
 * Workflow monitoring, metrics collection, and analytics for
 * business process optimization.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace Workflow {

// ============================================================================
// Forward Declarations
// ============================================================================

class WorkflowMetric;
class WorkflowMonitor;
class WorkflowAnalytics;
class ProcessMining;

// ============================================================================
// Metric Types
// ============================================================================

enum class MetricType {
    COUNTER,
    GAUGE,
    HISTOGRAM,
    SUMMARY,
    TIMER
};

// ============================================================================
// Workflow Metric
// ============================================================================

/**
 * Workflow metric data point.
 */
class WorkflowMetric {
public:
    struct Config {
        std::string name;
        MetricType type;
        std::string description;
        std::map<std::string, std::string> labels;
        std::chrono::system_clock::time_point timestamp;
        double value;
        std::optional<std::string> unit;
    };
    
    explicit WorkflowMetric(const Config& config);
    
    // Factory methods
    static WorkflowMetric Counter(const std::string& name,
                                   double value,
                                   const std::map<std::string, std::string>& labels = {});
    static WorkflowMetric Gauge(const std::string& name,
                                double value,
                                const std::map<std::string, std::string>& labels = {});
    static WorkflowMetric Timer(const std::string& name,
                                std::chrono::milliseconds duration,
                                const std::map<std::string, std::string>& labels = {});
    static WorkflowMetric Histogram(const std::string& name,
                                     double value,
                                     const std::vector<double>& buckets,
                                     const std::map<std::string, std::string>& labels = {});
    
    // Accessors
    const std::string& GetName() const { return config_.name; }
    MetricType GetType() const { return config_.type; }
    double GetValue() const { return config_.value; }
    const std::map<std::string, std::string>& GetLabels() const { return config_.labels; }
    std::chrono::system_clock::time_point GetTimestamp() const { return config_.timestamp; }
    
    // Serialization
    std::string ToPrometheusFormat() const;
    std::string ToJson() const;
    std::string ToInfluxLineProtocol() const;
    
private:
    Config config_;
};

// ============================================================================
// Workflow Event
// ============================================================================

/**
 * Workflow event for monitoring.
 */
struct WorkflowEvent {
    enum class Type {
        WORKFLOW_STARTED,
        WORKFLOW_COMPLETED,
        WORKFLOW_FAILED,
        WORKFLOW_CANCELLED,
        ACTIVITY_STARTED,
        ACTIVITY_COMPLETED,
        ACTIVITY_FAILED,
        ACTIVITY_SKIPPED,
        TASK_CREATED,
        TASK_ASSIGNED,
        TASK_COMPLETED,
        TASK_ESCALATED,
        GATEWAY_ENTERED,
        GATEWAY_EXITED,
        TIMER_FIRED,
        ERROR_OCCURRED
    };
    
    std::string eventId;
    Type type;
    std::string workflowId;
    std::string instanceId;
    std::optional<std::string> activityId;
    std::optional<std::string> taskId;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::any> data;
    std::optional<std::string> userId;
    std::optional<std::string> error;
};

// ============================================================================
// Metric Collector
// ============================================================================

/**
 * Metric collection interface.
 */
class MetricCollector {
public:
    virtual ~MetricCollector() = default;
    
    virtual void Collect(const WorkflowMetric& metric) = 0;
    virtual void Collect(const std::vector<WorkflowMetric>& metrics) = 0;
    virtual void Flush() = 0;
    virtual std::string GetName() const = 0;
};

/**
 * In-memory metric collector.
 */
class InMemoryCollector : public MetricCollector {
public:
    void Collect(const WorkflowMetric& metric) override;
    void Collect(const std::vector<WorkflowMetric>& metrics) override;
    void Flush() override;
    std::string GetName() const override { return "InMemory"; }
    
    std::vector<WorkflowMetric> GetMetrics() const;
    std::vector<WorkflowMetric> GetMetrics(const std::string& name) const;
    void Clear();
    
private:
    std::vector<WorkflowMetric> metrics_;
    mutable std::mutex mutex_;
};

/**
 * Prometheus metric collector.
 */
class PrometheusCollector : public MetricCollector {
public:
    struct Config {
        std::string endpoint;
        uint16_t port;
        std::string jobName;
        std::chrono::seconds pushInterval;
    };
    
    explicit PrometheusCollector(const Config& config);
    
    void Collect(const WorkflowMetric& metric) override;
    void Collect(const std::vector<WorkflowMetric>& metrics) override;
    void Flush() override;
    std::string GetName() const override { return "Prometheus"; }
    
private:
    Config config_;
    std::vector<WorkflowMetric> buffer_;
    mutable std::mutex mutex_;
    
    std::thread pushThread_;
    std::atomic<bool> stopPush_;
    
    void PushLoop();
    void PushMetrics();
};

/**
 * InfluxDB metric collector.
 */
class InfluxDBCollector : public MetricCollector {
public:
    struct Config {
        std::string url;
        std::string database;
        std::optional<std::string> username;
        std::optional<std::string> password;
        std::chrono::seconds batchSize;
        std::chrono::seconds flushInterval;
    };
    
    explicit InfluxDBCollector(const Config& config);
    
    void Collect(const WorkflowMetric& metric) override;
    void Collect(const std::vector<WorkflowMetric>& metrics) override;
    void Flush() override;
    std::string GetName() const override { return "InfluxDB"; }
    
private:
    Config config_;
    std::vector<WorkflowMetric> buffer_;
    mutable std::mutex mutex_;
    
    std::thread flushThread_;
    std::atomic<bool> stopFlush_;
    
    void FlushLoop();
    void WriteToInflux(const std::vector<WorkflowMetric>& metrics);
};

// ============================================================================
// Workflow Monitor
// ============================================================================

/**
 * Workflow monitoring system.
 */
class WorkflowMonitor {
public:
    struct Config {
        std::vector<std::shared_ptr<MetricCollector>> collectors;
        bool enableTracing;
        bool enableAlerting;
        std::chrono::seconds metricInterval;
    };
    
    struct Alert {
        enum class Severity {
            INFO,
            WARNING,
            ERROR,
            CRITICAL
        };
        
        std::string alertId;
        std::string name;
        Severity severity;
        std::string message;
        std::map<std::string, std::string> labels;
        std::chrono::system_clock::time_point timestamp;
        std::optional<std::chrono::system_clock::time_point> resolvedAt;
    };
    
    struct AlertRule {
        std::string name;
        std::string metricName;
        std::string condition;  // >, <, ==, !=
        double threshold;
        std::chrono::seconds duration;
        Alert::Severity severity;
        std::string message;
        std::map<std::string, std::string> labels;
    };
    
    explicit WorkflowMonitor(const Config& config);
    ~WorkflowMonitor();
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Metric recording
    void RecordMetric(const WorkflowMetric& metric);
    void RecordCounter(const std::string& name,
                       double value,
                       const std::map<std::string, std::string>& labels = {});
    void RecordGauge(const std::string& name,
                     double value,
                     const std::map<std::string, std::string>& labels = {});
    void RecordTimer(const std::string& name,
                     std::chrono::milliseconds duration,
                     const std::map<std::string, std::string>& labels = {});
    void RecordHistogram(const std::string& name,
                         double value,
                         const std::vector<double>& buckets,
                         const std::map<std::string, std::string>& labels = {});
    
    // Event recording
    void RecordEvent(const WorkflowEvent& event);
    void RecordWorkflowStart(const std::string& workflowId,
                              const std::string& instanceId);
    void RecordWorkflowComplete(const std::string& workflowId,
                                 const std::string& instanceId,
                                 std::chrono::milliseconds duration);
    void RecordWorkflowFailure(const std::string& workflowId,
                                const std::string& instanceId,
                                const std::string& error);
    void RecordActivityStart(const std::string& workflowId,
                              const std::string& instanceId,
                              const std::string& activityId);
    void RecordActivityComplete(const std::string& workflowId,
                                 const std::string& instanceId,
                                 const std::string& activityId,
                                 std::chrono::milliseconds duration);
    void RecordActivityFailure(const std::string& workflowId,
                                const std::string& instanceId,
                                const std::string& activityId,
                                const std::string& error);
    
    // Alert rules
    void AddAlertRule(const AlertRule& rule);
    void RemoveAlertRule(const std::string& name);
    std::vector<AlertRule> GetAlertRules() const;
    
    // Alert handling
    using AlertHandler = std::function<void(const Alert&)>;
    void SetAlertHandler(AlertHandler handler);
    std::vector<Alert> GetActiveAlerts() const;
    void ResolveAlert(const std::string& alertId);
    
    // Health check
    bool HealthCheck() const;
    
private:
    Config config_;
    std::atomic<bool> running_;
    
    std::vector<AlertRule> alertRules_;
    std::vector<Alert> activeAlerts_;
    AlertHandler alertHandler_;
    mutable std::mutex alertMutex_;
    
    std::thread monitorThread_;
    
    void MonitorLoop();
    void CheckAlertRules();
    void FireAlert(const AlertRule& rule, const WorkflowMetric& metric);
    bool EvaluateCondition(const std::string& condition, double value, double threshold);
};

// ============================================================================
// Workflow Analytics
// ============================================================================

/**
 * Workflow analytics and reporting.
 */
class WorkflowAnalytics {
public:
    struct WorkflowStats {
        std::string workflowId;
        uint64_t totalInstances;
        uint64_t completedInstances;
        uint64_t failedInstances;
        uint64_t cancelledInstances;
        double completionRate;
        double failureRate;
        std::chrono::milliseconds averageDuration;
        std::chrono::milliseconds p50Duration;
        std::chrono::milliseconds p95Duration;
        std::chrono::milliseconds p99Duration;
        std::map<std::string, uint64_t> instancesByStatus;
    };
    
    struct ActivityStats {
        std::string activityId;
        std::string workflowId;
        uint64_t totalExecutions;
        uint64_t successfulExecutions;
        uint64_t failedExecutions;
        double successRate;
        std::chrono::milliseconds averageDuration;
        std::chrono::milliseconds p95Duration;
        std::chrono::milliseconds p99Duration;
        uint64_t retryCount;
        double averageRetries;
    };
    
    struct TaskStats {
        uint64_t totalTasks;
        uint64_t completedTasks;
        uint64_t overdueTasks;
        double averageCompletionTime;
        std::map<std::string, uint64_t> tasksByAssignee;
        std::map<TaskPriority, uint64_t> tasksByPriority;
    };
    
    struct TimeRange {
        std::chrono::system_clock::time_point start;
        std::chrono::system_clock::time_point end;
        
        static TimeRange Last24Hours();
        static TimeRange Last7Days();
        static TimeRange Last30Days();
        static TimeRange Today();
        static TimeRange ThisWeek();
        static TimeRange ThisMonth();
    };
    
    explicit WorkflowAnalytics(std::shared_ptr<WorkflowMonitor> monitor);
    
    // Workflow analytics
    WorkflowStats GetWorkflowStats(const std::string& workflowId) const;
    WorkflowStats GetWorkflowStats(const std::string& workflowId,
                                    const TimeRange& range) const;
    std::vector<WorkflowStats> GetAllWorkflowStats() const;
    
    // Activity analytics
    ActivityStats GetActivityStats(const std::string& activityId) const;
    std::vector<ActivityStats> GetActivityStatsForWorkflow(
        const std::string& workflowId) const;
    
    // Task analytics
    TaskStats GetTaskStats() const;
    TaskStats GetTaskStats(const TimeRange& range) const;
    TaskStats GetTaskStatsForUser(const std::string& userId) const;
    
    // Trend analysis
    struct TrendPoint {
        std::chrono::system_clock::time_point timestamp;
        double value;
    };
    
    std::vector<TrendPoint> GetWorkflowVolumeTrend(
        const std::string& workflowId,
        const TimeRange& range,
        std::chrono::hours granularity) const;
    
    std::vector<TrendPoint> GetWorkflowDurationTrend(
        const std::string& workflowId,
        const TimeRange& range,
        std::chrono::hours granularity) const;
    
    std::vector<TrendPoint> GetErrorRateTrend(
        const std::string& workflowId,
        const TimeRange& range,
        std::chrono::hours granularity) const;
    
    // Bottleneck analysis
    struct Bottleneck {
        std::string activityId;
        std::string workflowId;
        double averageWaitTime;
        double averageExecutionTime;
        uint64_t queueDepth;
        double impactScore;
    };
    
    std::vector<Bottleneck> FindBottlenecks(const std::string& workflowId) const;
    std::vector<Bottleneck> FindBottlenecks(const TimeRange& range) const;
    
    // Comparison
    struct ComparisonResult {
        std::string metric;
        double baselineValue;
        double currentValue;
        double percentChange;
        bool isSignificant;
    };
    
    std::vector<ComparisonResult> CompareWorkflows(
        const std::string& workflowId1,
        const std::string& workflowId2,
        const TimeRange& range) const;
    
    // Reporting
    struct Report {
        std::string title;
        std::chrono::system_clock::time_point generatedAt;
        TimeRange timeRange;
        std::vector<WorkflowStats> workflowStats;
        std::vector<ActivityStats> activityStats;
        TaskStats taskStats;
        std::vector<Bottleneck> bottlenecks;
        std::map<std::string, std::any> customData;
    };
    
    Report GenerateReport(const TimeRange& range) const;
    Report GenerateReport(const std::string& workflowId,
                          const TimeRange& range) const;
    
    std::string ExportReportToJson(const Report& report) const;
    std::string ExportReportToCsv(const Report& report) const;
    std::string ExportReportToPdf(const Report& report) const;
    
    // Dashboard data
    struct DashboardData {
        uint64_t activeWorkflows;
        uint64_t completedToday;
        uint64_t failedToday;
        double averageDuration;
        std::vector<std::pair<std::string, uint64_t>> topWorkflows;
        std::vector<std::pair<std::string, uint64_t>> recentErrors;
    };
    
    DashboardData GetDashboardData() const;
    
private:
    std::shared_ptr<WorkflowMonitor> monitor_;
    mutable std::mutex mutex_;
    
    std::vector<WorkflowEvent> GetEvents(const TimeRange& range) const;
    std::vector<WorkflowEvent> GetEventsForWorkflow(const std::string& workflowId,
                                                        const TimeRange& range) const;
    double CalculatePercentile(const std::vector<double>& values, double percentile) const;
};

// ============================================================================
// Process Mining
// ============================================================================

/**
 * Process mining for workflow discovery and conformance.
 */
class ProcessMining {
public:
    struct EventLog {
        std::string caseId;
        std::string activity;
        std::string timestamp;
        std::optional<std::string> resource;
        std::map<std::string, std::string> attributes;
    };
    
    struct ProcessModel {
        struct Node {
            std::string id;
            std::string label;
            uint64_t frequency;
            double averageDuration;
        };
        
        struct Edge {
            std::string source;
            std::string target;
            uint64_t frequency;
            double probability;
        };
        
        std::vector<Node> nodes;
        std::vector<Edge> edges;
        std::string startNode;
        std::vector<std::string> endNodes;
    };
    
    struct ConformanceResult {
        double fitness;           // How well log fits model (0-1)
        double precision;         // How precise is the model (0-1)
        double generalization;    // How well model generalizes (0-1)
        double simplicity;        // How simple is the model (0-1)
        std::vector<std::string> deviations;
    };
    
    struct PerformanceAnalysis {
        struct ActivityPerformance {
            std::string activity;
            double averageDuration;
            double waitingTime;
            double serviceTime;
            uint64_t frequency;
        };
        
        std::vector<ActivityPerformance> activities;
        std::map<std::string, double> bottlenecks;
    };
    
    // Discovery algorithms
    enum class DiscoveryAlgorithm {
        ALPHA_MINER,
        HEURISTIC_MINER,
        INDUCTIVE_MINER,
        FUZZY_MINER
    };
    
    // Import event logs
    void ImportEventLog(const std::vector<EventLog>& events);
    void ImportFromXES(const std::string& filePath);
    void ImportFromCSV(const std::string& filePath);
    
    // Process discovery
    ProcessModel DiscoverProcess(DiscoveryAlgorithm algorithm);
    ProcessModel DiscoverProcess(const std::vector<EventLog>& events,
                                  DiscoveryAlgorithm algorithm);
    
    // Conformance checking
    ConformanceResult CheckConformance(const ProcessModel& model,
                                         const std::vector<EventLog>& events);
    std::vector<std::string> FindDeviations(const ProcessModel& model,
                                            const std::vector<EventLog>& events);
    
    // Performance analysis
    PerformanceAnalysis AnalyzePerformance(const std::vector<EventLog>& events);
    std::map<std::string, double> FindBottlenecks(const std::vector<EventLog>& events);
    
    // Social network analysis
    struct SocialNetwork {
        struct Relation {
            std::string source;
            std::string target;
            double strength;
            std::string type;  // handover, subcontracting, etc.
        };
        
        std::vector<std::string> actors;
        std::vector<Relation> relations;
    };
    
    SocialNetwork AnalyzeSocialNetwork(const std::vector<EventLog>& events);
    
    // Variant analysis
    struct Variant {
        std::vector<std::string> activities;
        uint64_t frequency;
        double averageDuration;
    };
    
    std::vector<Variant> GetVariants(const std::vector<EventLog>& events);
    std::vector<Variant> GetTopVariants(const std::vector<EventLog>& events,
                                           size_t limit);
    
    // Export
    std::string ExportToPNML(const ProcessModel& model);
    std::string ExportToDOT(const ProcessModel& model);
    std::string ExportToBPMN(const ProcessModel& model);
    
private:
    std::vector<EventLog> eventLog_;
    mutable std::mutex mutex_;
    
    ProcessModel AlphaMiner(const std::vector<EventLog>& events);
    ProcessModel HeuristicMiner(const std::vector<EventLog>& events);
    ProcessModel InductiveMiner(const std::vector<EventLog>& events);
    ProcessModel FuzzyMiner(const std::vector<EventLog>& events);
    
    std::map<std::string, std::vector<EventLog>> GroupByCase(
        const std::vector<EventLog>& events) const;
    std::vector<std::string> ExtractTraces(
        const std::map<std::string, std::vector<EventLog>>& cases) const;
};

} // namespace Workflow
