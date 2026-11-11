// SovereignObservability.hpp
// Phase D.4 Batch 4/5 — Observability & Operations
// Metrics collection, health monitoring, and operational tooling

#ifndef SOVEREIGN_OBSERVABILITY_HPP
#define SOVEREIGN_OBSERVABILITY_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <optional>
#include <atomic>
#include <thread>
#include <queue>

namespace Sovereign {

// ============================================================================
// Metric Types
// ============================================================================

enum class MetricType {
    COUNTER,      // Monotonically increasing
    GAUGE,        // Can go up or down
    HISTOGRAM,    // Distribution of values
    SUMMARY       // Similar to histogram
};

enum class MetricUnit {
    NONE,
    BYTES,
    SECONDS,
    MILLISECONDS,
    MICROSECONDS,
    NANOSECONDS,
    PERCENT,
    COUNT,
    BYTES_PER_SECOND,
    OPERATIONS_PER_SECOND
};

// ============================================================================
// Metric Value
// ============================================================================

struct MetricValue {
    double value;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> labels;
    
    MetricValue() : value(0.0) {}
    MetricValue(double v) : value(v), timestamp(std::chrono::system_clock::now()) {}
};

// ============================================================================
// Metric Definition
// ============================================================================

struct MetricDefinition {
    std::string name;
    std::string description;
    MetricType type;
    MetricUnit unit;
    std::vector<std::string> label_names;
    
    // Histogram/Summary specific
    std::vector<double> buckets;  // For histograms
    double quantiles[5];          // For summaries (0.5, 0.9, 0.95, 0.99, 1.0)
    
    MetricDefinition()
        : type(MetricType::GAUGE)
        , unit(MetricUnit::NONE)
    {
        quantiles[0] = 0.5;
        quantiles[1] = 0.9;
        quantiles[2] = 0.95;
        quantiles[3] = 0.99;
        quantiles[4] = 1.0;
    }
};

// ============================================================================
// Metric Collection
// ============================================================================

class MetricCollector {
public:
    MetricCollector();
    ~MetricCollector();
    
    // Registration
    void RegisterMetric(const MetricDefinition& definition);
    void UnregisterMetric(const std::string& name);
    
    // Recording
    void RecordCounter(const std::string& name, double increment = 1.0);
    void RecordCounter(const std::string& name, double increment,
                       const std::map<std::string, std::string>& labels);
    
    void RecordGauge(const std::string& name, double value);
    void RecordGauge(const std::string& name, double value,
                     const std::map<std::string, std::string>& labels);
    
    void RecordHistogram(const std::string& name, double value);
    void RecordHistogram(const std::string& name, double value,
                         const std::map<std::string, std::string>& labels);
    
    // Querying
    std::optional<double> GetValue(const std::string& name);
    std::optional<double> GetValue(const std::string& name,
                                    const std::map<std::string, std::string>& labels);
    
    std::vector<MetricValue> GetTimeSeries(const std::string& name,
                                           std::chrono::seconds duration);
    
    // Statistics
    struct MetricStats {
        double min;
        double max;
        double mean;
        double stddev;
        double p50;
        double p90;
        double p95;
        double p99;
        uint64_t count;
    };
    std::optional<MetricStats> GetStatistics(const std::string& name,
                                              std::chrono::seconds duration);
    
    // Export
    std::string ExportPrometheus();
    std::string ExportJSON();
    std::string ExportCSV();
    
    // Maintenance
    void SetRetention(std::chrono::hours hours);
    size_t CleanupOldData();
    void ClearAll();
    
private:
    std::map<std::string, MetricDefinition> definitions_;
    std::map<std::string, std::vector<MetricValue>> data_;
    mutable std::mutex data_mutex_;
    std::chrono::hours retention_;
    
    std::string FormatPrometheusValue(const MetricDefinition& def,
                                       const MetricValue& value);
    std::string UnitToPrometheus(MetricUnit unit);
};

// ============================================================================
// Health Check
// ============================================================================

enum class HealthStatus {
    HEALTHY,
    DEGRADED,
    UNHEALTHY,
    UNKNOWN
};

struct HealthCheckResult {
    std::string component;
    HealthStatus status;
    std::string message;
    std::chrono::system_clock::time_point checked_at;
    std::chrono::milliseconds response_time;
    std::map<std::string, std::string> metadata;
    
    HealthCheckResult()
        : status(HealthStatus::UNKNOWN)
    {}
};

class HealthMonitor {
public:
    using HealthCheckFunction = std::function<HealthCheckResult()>;
    
    HealthMonitor();
    ~HealthMonitor();
    
    // Registration
    void RegisterCheck(const std::string& name, HealthCheckFunction check);
    void UnregisterCheck(const std::string& name);
    
    // Execution
    HealthCheckResult RunCheck(const std::string& name);
    std::vector<HealthCheckResult> RunAllChecks();
    
    // Overall health
    HealthStatus GetOverallHealth() const;
    std::vector<std::string> GetUnhealthyComponents() const;
    
    // Background monitoring
    void StartMonitoring(std::chrono::seconds interval);
    void StopMonitoring();
    bool IsMonitoring() const;
    
    // Results access
    std::optional<HealthCheckResult> GetLastResult(const std::string& name);
    std::vector<HealthCheckResult> GetAllResults();
    
    // Health endpoint response
    std::string GetHealthEndpointResponse();
    
private:
    std::map<std::string, HealthCheckFunction> checks_;
    std::map<std::string, HealthCheckResult> last_results_;
    mutable std::mutex checks_mutex_;
    
    std::atomic<bool> monitoring_;
    std::thread monitor_thread_;
    std::chrono::seconds monitor_interval_;
    
    void MonitorLoop();
    std::string StatusToString(HealthStatus status);
};

// ============================================================================
// Performance Profiler
// ============================================================================

struct ProfileSample {
    std::string operation;
    std::chrono::nanoseconds duration;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> attributes;
    
    ProfileSample()
        : duration(0)
    {}
};

class PerformanceProfiler {
public:
    PerformanceProfiler();
    ~PerformanceProfiler();
    
    // Scoped profiling
    class ProfileScope {
    public:
        ProfileScope(PerformanceProfiler* profiler, const std::string& operation);
        ~ProfileScope();
        
        void AddAttribute(const std::string& key, const std::string& value);
        
    private:
        PerformanceProfiler* profiler_;
        std::string operation_;
        std::chrono::steady_clock::time_point start_;
        std::map<std::string, std::string> attributes_;
    };
    
    // Manual profiling
    void StartOperation(const std::string& operation);
    void EndOperation(const std::string& operation);
    
    // Recording
    void RecordSample(const ProfileSample& sample);
    
    // Analysis
    struct OperationStats {
        std::string operation;
        uint64_t count;
        std::chrono::nanoseconds total_time;
        std::chrono::nanoseconds min_time;
        std::chrono::nanoseconds max_time;
        std::chrono::nanoseconds avg_time;
        std::chrono::nanoseconds p95_time;
        std::chrono::nanoseconds p99_time;
    };
    std::vector<OperationStats> GetOperationStats(
        std::chrono::seconds duration = std::chrono::seconds(3600));
    
    // Export
    std::string ExportTrace();
    std::string ExportFlameGraph();
    
    // Control
    void Enable();
    void Disable();
    bool IsEnabled() const;
    void Clear();
    
private:
    std::atomic<bool> enabled_;
    std::vector<ProfileSample> samples_;
    mutable std::mutex samples_mutex_;
    
    std::map<std::string, std::chrono::steady_clock::time_point> active_operations_;
    mutable std::mutex operations_mutex_;
};

// ============================================================================
// Log Aggregator
// ============================================================================

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

struct LogEntry {
    std::string id;
    LogLevel level;
    std::string component;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> fields;
    std::string trace_id;
    std::string span_id;
    
    LogEntry()
        : level(LogLevel::INFO)
    {}
};

class LogAggregator {
public:
    LogAggregator();
    ~LogAggregator();
    
    // Configuration
    void SetMinLevel(LogLevel level);
    void SetBufferSize(size_t size);
    void SetOutputPath(const std::string& path);
    
    // Logging
    void Log(const LogEntry& entry);
    void Log(LogLevel level, const std::string& component,
             const std::string& message);
    void Log(LogLevel level, const std::string& component,
             const std::string& message,
             const std::map<std::string, std::string>& fields);
    
    // Convenience methods
    void Trace(const std::string& component, const std::string& message);
    void Debug(const std::string& component, const std::string& message);
    void Info(const std::string& component, const std::string& message);
    void Warn(const std::string& component, const std::string& message);
    void Error(const std::string& component, const std::string& message);
    void Fatal(const std::string& component, const std::string& message);
    
    // Querying
    std::vector<LogEntry> Query(LogLevel min_level = LogLevel::TRACE,
                                 std::optional<std::string> component = std::nullopt,
                                 std::optional<std::chrono::system_clock::time_point> start = std::nullopt,
                                 std::optional<std::chrono::system_clock::time_point> end = std::nullopt,
                                 size_t limit = 1000);
    
    std::vector<LogEntry> Search(const std::string& query,
                                  size_t limit = 1000);
    
    // Export
    bool ExportToFile(const std::string& path,
                      std::optional<LogLevel> min_level = std::nullopt);
    
    // Statistics
    struct LogStats {
        size_t total_entries;
        size_t trace_count;
        size_t debug_count;
        size_t info_count;
        size_t warn_count;
        size_t error_count;
        size_t fatal_count;
        std::chrono::system_clock::time_point oldest_entry;
        std::chrono::system_clock::time_point newest_entry;
    };
    LogStats GetStatistics() const;
    
    // Maintenance
    void Clear();
    size_t CleanupOldEntries(std::chrono::hours retention);
    
private:
    LogLevel min_level_;
    size_t buffer_size_;
    std::string output_path_;
    
    std::deque<LogEntry> entries_;
    mutable std::mutex entries_mutex_;
    
    std::string LevelToString(LogLevel level);
    std::string FormatEntry(const LogEntry& entry);
};

// ============================================================================
// Telemetry Exporter
// ============================================================================

class TelemetryExporter {
public:
    TelemetryExporter();
    ~TelemetryExporter();
    
    // Configuration
    void SetEndpoint(const std::string& url);
    void SetAPIKey(const std::string& key);
    void SetBatchSize(size_t size);
    void SetFlushInterval(std::chrono::seconds interval);
    
    // Export methods
    void ExportMetrics(const MetricCollector& collector);
    void ExportLogs(const LogAggregator& aggregator);
    void ExportTraces(const PerformanceProfiler& profiler);
    
    // Manual flush
    void Flush();
    
    // Control
    void Start();
    void Stop();
    bool IsRunning() const;
    
private:
    std::string endpoint_;
    std::string api_key_;
    size_t batch_size_;
    std::chrono::seconds flush_interval_;
    
    std::atomic<bool> running_;
    std::thread export_thread_;
    
    struct ExportBatch {
        std::string type;
        std::string data;
        std::chrono::system_clock::time_point timestamp;
    };
    std::queue<ExportBatch> pending_batches_;
    mutable std::mutex batches_mutex_;
    
    void ExportLoop();
    bool SendBatch(const ExportBatch& batch);
};

// ============================================================================
// Operational Commands
// ============================================================================

class OperationalCommands {
public:
    using CommandFunction = std::function<std::string(const std::vector<std::string>&)>;
    
    OperationalCommands();
    ~OperationalCommands();
    
    // Registration
    void RegisterCommand(const std::string& name,
                         const std::string& description,
                         CommandFunction func);
    void UnregisterCommand(const std::string& name);
    
    // Execution
    std::string Execute(const std::string& command,
                        const std::vector<std::string>& args);
    
    // Discovery
    std::vector<std::pair<std::string, std::string>> ListCommands();
    std::optional<std::string> GetCommandDescription(const std::string& name);
    
    // Built-in commands
    void RegisterBuiltInCommands(MetricCollector* metrics,
                                  HealthMonitor* health,
                                  LogAggregator* logs,
                                  PerformanceProfiler* profiler);
    
private:
    std::map<std::string, std::pair<std::string, CommandFunction>> commands_;
    mutable std::mutex commands_mutex_;
};

// ============================================================================
// Main Observability Layer
// ============================================================================

class SovereignObservability {
public:
    static SovereignObservability& GetInstance();
    
    // Initialization
    void Initialize(const std::string& config_path = "");
    void Shutdown();
    bool IsInitialized() const;
    
    // Component access
    MetricCollector& GetMetrics();
    HealthMonitor& GetHealth();
    PerformanceProfiler& GetProfiler();
    LogAggregator& GetLogs();
    TelemetryExporter& GetExporter();
    OperationalCommands& GetCommands();
    
    // Convenience methods
    void RecordMetric(const std::string& name, double value);
    void LogInfo(const std::string& component, const std::string& message);
    void LogError(const std::string& component, const std::string& message);
    
    // Health endpoint
    std::string GetHealthStatus();
    bool IsHealthy() const;
    
    // Status
    struct ObservabilityStatus {
        bool initialized;
        size_t metrics_count;
        size_t log_entries;
        size_t health_checks;
        bool monitoring_active;
        bool exporter_running;
    };
    ObservabilityStatus GetStatus() const;
    
private:
    SovereignObservability();
    ~SovereignObservability();
    
    SovereignObservability(const SovereignObservability&) = delete;
    SovereignObservability& operator=(const SovereignObservability&) = delete;
    
    std::unique_ptr<MetricCollector> metrics_;
    std::unique_ptr<HealthMonitor> health_;
    std::unique_ptr<PerformanceProfiler> profiler_;
    std::unique_ptr<LogAggregator> logs_;
    std::unique_ptr<TelemetryExporter> exporter_;
    std::unique_ptr<OperationalCommands> commands_;
    
    bool initialized_;
    mutable std::mutex init_mutex_;
};

// ============================================================================
// Built-in Metrics
// ============================================================================

namespace BuiltInMetrics {
    // System metrics
    constexpr const char* CPU_USAGE = "sovereign_cpu_usage_percent";
    constexpr const char* MEMORY_USAGE = "sovereign_memory_usage_bytes";
    constexpr const char* MEMORY_USAGE_PERCENT = "sovereign_memory_usage_percent";
    constexpr const char* DISK_USAGE = "sovereign_disk_usage_bytes";
    constexpr const char* NETWORK_BYTES_IN = "sovereign_network_bytes_in";
    constexpr const char* NETWORK_BYTES_OUT = "sovereign_network_bytes_out";
    
    // Inference metrics
    constexpr const char* INFERENCE_REQUESTS = "sovereign_inference_requests_total";
    constexpr const char* INFERENCE_LATENCY = "sovereign_inference_latency_seconds";
    constexpr const char* INFERENCE_TOKENS = "sovereign_inference_tokens_total";
    constexpr const char* INFERENCE_ERRORS = "sovereign_inference_errors_total";
    
    // Agent metrics
    constexpr const char* AGENTS_ACTIVE = "sovereign_agents_active";
    constexpr const char* AGENTS_CREATED = "sovereign_agents_created_total";
    constexpr const char* AGENT_TASKS = "sovereign_agent_tasks_total";
    constexpr const char* AGENT_LATENCY = "sovereign_agent_latency_seconds";
    
    // Swarm metrics
    constexpr const char* SWARMS_ACTIVE = "sovereign_swarms_active";
    constexpr const char* SWARM_AGENTS = "sovereign_swarm_agents_total";
    constexpr const char* SWARM_CONSENSUS_TIME = "sovereign_swarm_consensus_seconds";
    
    // Runtime metrics
    constexpr const char* UPTIME = "sovereign_uptime_seconds";
    constexpr const char* GOROUTINES = "sovereign_goroutines";
    constexpr const char* GC_DURATION = "sovereign_gc_duration_seconds";
    
    void RegisterAll(MetricCollector& collector);
}

} // namespace Sovereign

#endif // SOVEREIGN_OBSERVABILITY_HPP
