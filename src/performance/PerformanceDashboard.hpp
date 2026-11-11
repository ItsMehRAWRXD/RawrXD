/**
 * PerformanceDashboard.hpp
 *
 * Phase H Batch 5/5: Performance Dashboard & Integration
 *
 * Real-time performance dashboard with visualization,
 * alerting, and automated optimization triggers.
 */

#pragma once

#include "PerformanceProfiler.hpp"
#include "OptimizationEngine.hpp"
#include "BenchmarkFramework.hpp"
#include "LoadTesting.hpp"

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>
#include <queue>

namespace Performance {

// ============================================================================
// Forward Declarations
// ============================================================================

class PerformanceDashboard;
class PerformanceAlert;
class OptimizationTrigger;
class PerformanceReport;

// ============================================================================
// Dashboard Types
// ============================================================================

enum class DashboardWidgetType {
    CPU_USAGE,          // CPU utilization gauge
    MEMORY_USAGE,       // Memory usage chart
    THROUGHPUT,         // Requests/sec line chart
    LATENCY,            // Response time histogram
    ERROR_RATE,         // Error rate indicator
    ACTIVE_USERS,       // Concurrent users counter
    CACHE_HIT_RATE,     // Cache performance
    GPU_UTILIZATION,    // GPU usage
    CUSTOM_METRIC       // User-defined metric
};

enum class AlertSeverity {
    INFO,
    WARNING,
    CRITICAL,
    EMERGENCY
};

// ============================================================================
// Metric Data Point
// ============================================================================

/**
 * Single metric data point for time series.
 */
struct MetricDataPoint {
    uint64_t timestamp;
    double value;
    std::map<std::string, std::string> labels;
    
    MetricDataPoint() : timestamp(0), value(0.0) {}
    MetricDataPoint(uint64_t ts, double val) : timestamp(ts), value(val) {}
};

// ============================================================================
// Time Series
// ============================================================================

/**
 * Time series metric storage.
 */
class TimeSeries {
public:
    struct Config {
        uint64_t retentionMs = 3600000;  // 1 hour default
        uint32_t maxPoints = 10000;
        uint32_t downsamplingFactor = 10;
    };
    
    explicit TimeSeries(const std::string& name, const Config& config = Config{});
    
    // Add data point
    void AddPoint(const MetricDataPoint& point);
    void AddPoint(uint64_t timestamp, double value);
    
    // Query
    std::vector<MetricDataPoint> GetRange(uint64_t startTime, uint64_t endTime) const;
    std::vector<MetricDataPoint> GetRecent(uint64_t durationMs) const;
    
    // Statistics
    double GetAverage(uint64_t durationMs) const;
    double GetMin(uint64_t durationMs) const;
    double GetMax(uint64_t durationMs) const;
    double GetPercentile(uint64_t durationMs, double percentile) const;
    
    // Aggregation
    std::vector<MetricDataPoint> Downsample(uint64_t intervalMs) const;
    
    // Maintenance
    void Compact();
    void Clear();
    
    // Accessors
    std::string GetName() const { return name_; }
    size_t GetPointCount() const;
    
private:
    std::string name_;
    Config config_;
    
    std::deque<MetricDataPoint> points_;
    mutable std::mutex pointsMutex_;
    
    void DownsampleIfNeeded();
};

// ============================================================================
// Dashboard Widget
// ============================================================================

/**
 * Dashboard widget configuration.
 */
struct DashboardWidget {
    std::string id;
    std::string title;
    DashboardWidgetType type;
    std::string metricName;
    
    // Display options
    uint32_t width;
    uint32_t height;
    uint32_t refreshIntervalMs;
    
    // Thresholds
    double warningThreshold;
    double criticalThreshold;
    
    // Time range
    uint64_t timeRangeMs;
    
    // Visualization
    std::string colorScheme;
    bool showLegend;
    bool showGrid;
};

// ============================================================================
// Performance Alert
// ============================================================================

/**
 * Performance alert definition.
 */
struct PerformanceAlert {
    std::string id;
    std::string name;
    std::string description;
    AlertSeverity severity;
    
    // Condition
    std::string metricName;
    std::string condition;  // >, <, ==, >=, <=
    double threshold;
    uint32_t durationSeconds;  // Duration before triggering
    
    // State
    bool triggered;
    uint64_t triggeredAt;
    uint64_t resolvedAt;
    std::string message;
    
    // Actions
    std::vector<std::string> actions;  // notification, optimization, scaling
};

// ============================================================================
// Alert Manager
// ============================================================================

/**
 * Manages performance alerts.
 */
class AlertManager {
public:
    using AlertCallback = std::function<void(const PerformanceAlert&)>;
    
    AlertManager();
    ~AlertManager();
    
    // Alert definitions
    void AddAlert(const PerformanceAlert& alert);
    void RemoveAlert(const std::string& alertId);
    void UpdateAlert(const std::string& alertId, const PerformanceAlert& alert);
    std::vector<PerformanceAlert> GetAlerts() const;
    std::vector<PerformanceAlert> GetTriggeredAlerts() const;
    
    // Evaluation
    void EvaluateAlerts(const std::map<std::string, double>& metrics);
    void EvaluateAlert(PerformanceAlert& alert, double metricValue);
    
    // Callbacks
    void SetAlertCallback(AlertCallback callback);
    void SetResolveCallback(AlertCallback callback);
    
    // History
    std::vector<PerformanceAlert> GetAlertHistory(uint64_t since) const;
    
    // Acknowledgment
    void AcknowledgeAlert(const std::string& alertId);
    void ResolveAlert(const std::string& alertId);
    
private:
    std::vector<PerformanceAlert> alerts_;
    mutable std::mutex alertsMutex_;
    
    std::vector<PerformanceAlert> history_;
    mutable std::mutex historyMutex_;
    
    AlertCallback alertCallback_;
    AlertCallback resolveCallback_;
    
    std::map<std::string, uint64_t> triggerStartTimes_;
};

// ============================================================================
// Optimization Trigger
// ============================================================================

/**
 * Automatic optimization trigger.
 */
struct OptimizationTrigger {
    std::string id;
    std::string name;
    std::string description;
    
    // Condition
    std::string metricName;
    std::string condition;
    double threshold;
    uint32_t durationSeconds;
    
    // Action
    OptimizationType optimizationType;
    OptimizationLevel optimizationLevel;
    std::vector<std::string> targetComponents;
    
    // Safety
    bool requireConfirmation;
    bool dryRunFirst;
    uint32_t cooldownSeconds;
    
    // State
    bool enabled;
    uint64_t lastTriggered;
    uint32_t triggerCount;
};

// ============================================================================
// Auto Optimizer
// ============================================================================

/**
 * Automatic performance optimization.
 */
class AutoOptimizer {
public:
    struct Config {
        bool enabled = false;
        bool dryRun = true;
        OptimizationLevel maxLevel = OptimizationLevel::MODERATE;
        uint32_t cooldownSeconds = 300;
        double minImprovementThreshold = 0.05;
    };
    
    explicit AutoOptimizer(const Config& config);
    ~AutoOptimizer();
    
    // Initialize
    bool Initialize(std::shared_ptr<OptimizationEngine> engine);
    void Shutdown();
    
    // Triggers
    void AddTrigger(const OptimizationTrigger& trigger);
    void RemoveTrigger(const std::string& triggerId);
    void EnableTrigger(const std::string& triggerId, bool enabled);
    
    // Evaluation
    void EvaluateTriggers(const std::map<std::string, double>& metrics);
    
    // Manual trigger
    bool TriggerOptimization(const std::string& triggerId);
    
    // History
    std::vector<OptimizationResult> GetOptimizationHistory() const;
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    std::shared_ptr<OptimizationEngine> engine_;
    
    std::vector<OptimizationTrigger> triggers_;
    mutable std::mutex triggersMutex_;
    
    std::vector<OptimizationResult> history_;
    mutable std::mutex historyMutex_;
    
    std::map<std::string, uint64_t> triggerStartTimes_;
    
    bool CanTrigger(const OptimizationTrigger& trigger);
    OptimizationResult ExecuteOptimization(const OptimizationTrigger& trigger);
};

// ============================================================================
// Performance Report
// ============================================================================

/**
 * Comprehensive performance report.
 */
struct PerformanceReport {
    std::string reportId;
    std::string title;
    std::chrono::system_clock::time_point generatedAt;
    uint64_t timeRangeMs;
    
    // Executive summary
    struct Summary {
        double averageCpuPercent;
        double peakCpuPercent;
        double averageMemoryPercent;
        double peakMemoryPercent;
        double averageThroughput;
        double peakThroughput;
        double averageLatencyMs;
        double p99LatencyMs;
        double errorRate;
        uint32_t totalRequests;
    };
    Summary summary;
    
    // Detailed metrics
    std::map<std::string, std::vector<MetricDataPoint>> metrics;
    
    // Alerts
    std::vector<PerformanceAlert> alerts;
    uint32_t totalAlerts;
    uint32_t criticalAlerts;
    
    // Optimizations
    std::vector<OptimizationResult> optimizations;
    double totalImprovement;
    
    // Benchmarks
    std::vector<BenchmarkResult> benchmarks;
    
    // Recommendations
    std::vector<std::string> recommendations;
    
    // Export
    std::string ToHtml() const;
    std::string ToPdf() const;
    std::string ToJson() const;
};

// ============================================================================
// Report Generator
// ============================================================================

/**
 * Generates performance reports.
 */
class ReportGenerator {
public:
    struct Config {
        std::string templateDirectory;
        std::string outputDirectory;
        bool includeRawData = false;
        bool includeCharts = true;
    };
    
    explicit ReportGenerator(const Config& config);
    
    // Generate reports
    PerformanceReport GenerateReport(uint64_t timeRangeMs);
    PerformanceReport GenerateReport(const std::chrono::system_clock::time_point& start,
                                     const std::chrono::system_clock::time_point& end);
    
    // Scheduled reports
    void ScheduleDailyReport(uint32_t hour, uint32_t minute);
    void ScheduleWeeklyReport(uint32_t dayOfWeek, uint32_t hour, uint32_t minute);
    void CancelScheduledReports();
    
    // Export
    void ExportToHtml(const PerformanceReport& report, const std::string& filepath);
    void ExportToPdf(const PerformanceReport& report, const std::string& filepath);
    void ExportToJson(const PerformanceReport& report, const std::string& filepath);
    
    // Email
    void SetEmailConfig(const std::string& smtpServer, uint32_t port,
                       const std::string& username, const std::string& password);
    void EmailReport(const PerformanceReport& report,
                     const std::vector<std::string>& recipients);
    
private:
    Config config_;
    
    std::string GenerateHtmlContent(const PerformanceReport& report);
    std::string GenerateChartData(const std::string& metricName,
                                   const std::vector<MetricDataPoint>& points);
};

// ============================================================================
// Performance Dashboard
// ============================================================================

/**
 * Main performance dashboard.
 */
class PerformanceDashboard {
public:
    struct Config {
        // Server
        uint32_t port = 8080;
        std::string bindAddress = "0.0.0.0";
        
        // Update
        uint32_t updateIntervalMs = 1000;
        uint32_t metricRetentionHours = 24;
        
        // Features
        bool enableAlerts = true;
        bool enableAutoOptimization = false;
        bool enableBenchmarking = true;
        bool enableLoadTesting = false;
        
        // Authentication
        bool requireAuth = false;
        std::string authToken;
    };
    
    explicit PerformanceDashboard(const Config& config = Config{});
    ~PerformanceDashboard();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Components
    void SetProfiler(std::shared_ptr<PerformanceProfiler> profiler);
    void SetOptimizationEngine(std::shared_ptr<OptimizationEngine> engine);
    void SetBenchmarkRunner(std::shared_ptr<BenchmarkRunner> runner);
    void SetLoadTestRunner(std::shared_ptr<LoadTestRunner> runner);
    
    // Metrics
    void RecordMetric(const std::string& name, double value);
    void RecordMetric(const std::string& name, double value,
                      const std::map<std::string, std::string>& labels);
    
    TimeSeries* GetTimeSeries(const std::string& name);
    std::vector<std::string> GetMetricNames() const;
    
    // Widgets
    void AddWidget(const DashboardWidget& widget);
    void RemoveWidget(const std::string& widgetId);
    std::vector<DashboardWidget> GetWidgets() const;
    
    // Alerts
    void AddAlert(const PerformanceAlert& alert);
    void RemoveAlert(const std::string& alertId);
    std::vector<PerformanceAlert> GetActiveAlerts() const;
    
    // Reports
    PerformanceReport GenerateReport(uint64_t timeRangeMs);
    void ScheduleReport(uint64_t intervalMs, const std::string& email);
    
    // Control
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // API
    std::string HandleApiRequest(const std::string& path,
                                  const std::map<std::string, std::string>& params);
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    // Components
    std::shared_ptr<PerformanceProfiler> profiler_;
    std::shared_ptr<OptimizationEngine> optimizationEngine_;
    std::shared_ptr<BenchmarkRunner> benchmarkRunner_;
    std::shared_ptr<LoadTestRunner> loadTestRunner_;
    
    // Metrics
    std::map<std::string, std::unique_ptr<TimeSeries>> timeSeries_;
    mutable std::mutex timeSeriesMutex_;
    
    // Widgets
    std::vector<DashboardWidget> widgets_;
    mutable std::mutex widgetsMutex_;
    
    // Alerts
    std::unique_ptr<AlertManager> alertManager_;
    
    // Auto-optimization
    std::unique_ptr<AutoOptimizer> autoOptimizer_;
    
    // Reports
    std::unique_ptr<ReportGenerator> reportGenerator_;
    
    // Server
    std::thread serverThread_;
    
    void UpdateLoop();
    void EvaluateAlerts();
    void StartHttpServer();
    std::string GetDashboardHtml();
    std::string GetMetricsJson();
    std::string GetWidgetsJson();
    std::string GetAlertsJson();
};

// ============================================================================
// Performance System
// ============================================================================

/**
 * Integrated performance management system.
 */
class PerformanceSystem {
public:
    struct Config {
        PerformanceProfiler::Config profilerConfig;
        OptimizationEngine::Config optimizerConfig;
        PerformanceDashboard::Config dashboardConfig;
        bool autoStart = true;
    };
    
    explicit PerformanceSystem(const Config& config = Config{});
    ~PerformanceSystem();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Access components
    PerformanceProfiler* GetProfiler();
    OptimizationEngine* GetOptimizer();
    PerformanceDashboard* GetDashboard();
    BenchmarkRunner* GetBenchmarkRunner();
    LoadTestRunner* GetLoadTestRunner();
    
    // Convenience methods
    void ProfileScope(const std::string& name, std::function<void()> func);
    OptimizationResult Optimize(const OptimizationTarget& target);
    std::vector<BenchmarkResult> RunBenchmarks(BenchmarkSuite& suite);
    LoadTestResult RunLoadTest(LoadTestScenario& scenario);
    
    // System status
    std::string GetStatusJson() const;
    bool IsHealthy() const;
    
    // Global instance
    static PerformanceSystem* GetInstance();
    static void SetInstance(std::unique_ptr<PerformanceSystem> instance);
    
private:
    Config config_;
    
    std::unique_ptr<PerformanceProfiler> profiler_;
    std::unique_ptr<OptimizationEngine> optimizer_;
    std::unique_ptr<PerformanceDashboard> dashboard_;
    std::unique_ptr<BenchmarkRunner> benchmarkRunner_;
    std::unique_ptr<LoadTestRunner> loadTestRunner_;
    
    static std::unique_ptr<PerformanceSystem> instance_;
    static std::mutex instanceMutex_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Quick profile a function.
 */
template<typename Func>
auto Profile(const std::string& name, Func&& func) -> decltype(func()) {
    auto* system = PerformanceSystem::GetInstance();
    if (system) {
        auto* profiler = system->GetProfiler();
        if (profiler) {
            profiler->BeginRegion(name, ProfileType::CPU);
        }
    }
    
    auto result = func();
    
    if (system) {
        auto* profiler = system->GetProfiler();
        if (profiler) {
            profiler->EndRegion(name);
        }
    }
    
    return result;
}

/**
 * Scoped profiling guard.
 */
class ProfileGuard {
public:
    ProfileGuard(const std::string& name, ProfileType type = ProfileType::CPU);
    ~ProfileGuard();
    
private:
    std::string name_;
};

} // namespace Performance
