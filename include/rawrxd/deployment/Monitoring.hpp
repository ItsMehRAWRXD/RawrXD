#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <mutex>
#include <functional>
#include <queue>

namespace rawrxd {
namespace deployment {

// Metric types
enum class MetricType {
    COUNTER,      // Monotonically increasing
    GAUGE,        // Can go up or down
    HISTOGRAM,    // Distribution of values
    SUMMARY       // Similar to histogram but configurable quantiles
};

// Metric value
struct MetricValue {
    std::string name;
    MetricType type;
    double value = 0.0;
    std::map<std::string, std::string> labels;
    std::chrono::system_clock::time_point timestamp;
    
    // For histogram/summary
    std::vector<double> buckets;
    std::vector<int> counts;
};

// Metrics collector
class MetricsCollector {
public:
    static MetricsCollector& GetInstance();
    
    // Initialize
    bool Initialize(const std::string& endpoint = ":9090",
                    const std::string& jobName = "rawrxd");
    
    // Record metrics
    void Counter(const std::string& name, double value = 1.0,
                 const std::map<std::string, std::string>& labels = {});
    void Gauge(const std::string& name, double value,
               const std::map<std::string, std::string>& labels = {});
    void Histogram(const std::string& name, double value,
                   const std::map<std::string, std::string>& labels = {});
    void Summary(const std::string& name, double value,
                 const std::map<std::string, std::string>& labels = {});
    
    // Timer helper
    class Timer {
    public:
        Timer(const std::string& name, MetricsCollector* collector,
              const std::map<std::string, std::string>& labels = {});
        ~Timer();
        
        void Stop();
        double ElapsedMs() const;
        
    private:
        std::string name_;
        MetricsCollector* collector_;
        std::map<std::string, std::string> labels_;
        std::chrono::high_resolution_clock::time_point start_;
        bool stopped_ = false;
    };
    
    std::unique_ptr<Timer> NewTimer(const std::string& name,
                                    const std::map<std::string, std::string>& labels = {});
    
    // Export metrics
    std::string ExportPrometheusFormat();
    std::string ExportJSON();
    void ExportToFile(const std::string& path);
    
    // Get metric value
    double GetMetricValue(const std::string& name,
                          const std::map<std::string, std::string>& labels = {});
    
    // Clear metrics
    void Clear();

private:
    MetricsCollector() = default;
    ~MetricsCollector() = default;
    MetricsCollector(const MetricsCollector&) = delete;
    MetricsCollector& operator=(const MetricsCollector&) = delete;
    
    struct MetricData {
        MetricType type;
        double value = 0.0;
        std::vector<double> observations;
        std::map<std::string, std::string> labels;
    };
    
    std::map<std::string, std::vector<MetricData>> metrics_;
    mutable std::mutex mutex_;
    
    std::string endpoint_;
    std::string jobName_;
    
    void RecordObservation(const std::string& name, MetricType type,
                          double value, const std::map<std::string, std::string>& labels);
};

// Health checks
class HealthChecker {
public:
    enum class HealthStatus {
        HEALTHY,
        DEGRADED,
        UNHEALTHY
    };
    
    struct HealthCheck {
        std::string name;
        std::function<HealthStatus()> check;
        std::chrono::seconds interval;
        std::chrono::seconds timeout;
        int consecutiveFailures = 0;
        int maxConsecutiveFailures = 3;
    };
    
    static HealthChecker& GetInstance();
    
    // Register health check
    void RegisterCheck(const std::string& name,
                       std::function<HealthStatus()> check,
                       std::chrono::seconds interval = std::chrono::seconds(10),
                       std::chrono::seconds timeout = std::chrono::seconds(5));
    
    // Unregister health check
    void UnregisterCheck(const std::string& name);
    
    // Get overall health
    HealthStatus GetHealth() const;
    
    // Get individual check results
    std::map<std::string, HealthStatus> GetCheckResults() const;
    
    // Start monitoring
    void Start();
    
    // Stop monitoring
    void Stop();
    
    // Get health as JSON
    std::string GetHealthJSON() const;

private:
    HealthChecker() = default;
    ~HealthChecker();
    HealthChecker(const HealthChecker&) = delete;
    HealthChecker& operator=(const HealthChecker&) = delete;
    
    std::map<std::string, HealthCheck> checks_;
    mutable std::mutex mutex_;
    std::thread monitorThread_;
    std::atomic<bool> running_{false};
    std::map<std::string, HealthStatus> results_;
    
    void MonitorLoop();
    HealthStatus RunCheck(const HealthCheck& check);
};

// Distributed tracing
class Tracer {
public:
    struct Span {
        std::string traceId;
        std::string spanId;
        std::string parentSpanId;
        std::string operationName;
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
        std::map<std::string, std::string> tags;
        std::vector<std::pair<std::string, std::string>> logs;
        bool finished = false;
    };
    
    static Tracer& GetInstance();
    
    // Initialize
    bool Initialize(const std::string& serviceName = "rawrxd",
                     const std::string& collectorEndpoint = "http://localhost:9411");
    
    // Start span
    Span* StartSpan(const std::string& operationName,
                    const std::string& parentSpanId = "");
    
    // Finish span
    void FinishSpan(Span* span);
    
    // Add tag
    void SetTag(Span* span, const std::string& key, const std::string& value);
    
    // Add log
    void Log(Span* span, const std::string& event, const std::string& message);
    
    // Get current span
    Span* GetCurrentSpan();
    
    // Export spans
    void ExportSpans();
    
    // Clear finished spans
    void ClearFinishedSpans();

private:
    Tracer() = default;
    ~Tracer() = default;
    Tracer(const Tracer&) = delete;
    Tracer& operator=(const Tracer&) = delete;
    
    std::string serviceName_;
    std::string collectorEndpoint_;
    std::vector<std::unique_ptr<Span>> spans_;
    thread_local Span* currentSpan_ = nullptr;
    mutable std::mutex mutex_;
    
    std::string GenerateTraceId();
    std::string GenerateSpanId();
};

// Logging
class StructuredLogger {
public:
    enum class LogLevel {
        TRACE,
        DEBUG,
        INFO,
        WARN,
        ERROR,
        FATAL
    };
    
    struct LogEntry {
        std::chrono::system_clock::time_point timestamp;
        LogLevel level;
        std::string message;
        std::map<std::string, std::string> fields;
        std::string traceId;
        std::string spanId;
    };
    
    static StructuredLogger& GetInstance();
    
    // Initialize
    bool Initialize(const std::string& logPath = "logs",
                    LogLevel minLevel = LogLevel::INFO,
                    bool consoleOutput = true,
                    bool fileOutput = true);
    
    // Log methods
    void Trace(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Debug(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Info(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Warn(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Error(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Fatal(const std::string& message, const std::map<std::string, std::string>& fields = {});
    
    // Log with context
    void Log(LogLevel level, const std::string& message,
             const std::map<std::string, std::string>& fields = {});
    
    // Set minimum level
    void SetMinLevel(LogLevel level);
    
    // Flush logs
    void Flush();
    
    // Get recent logs
    std::vector<LogEntry> GetRecentLogs(int count = 100);

private:
    StructuredLogger() = default;
    ~StructuredLogger();
    StructuredLogger(const StructuredLogger&) = delete;
    StructuredLogger& operator=(const StructuredLogger&) = delete;
    
    LogLevel minLevel_ = LogLevel::INFO;
    std::string logPath_;
    bool consoleOutput_ = true;
    bool fileOutput_ = true;
    
    std::queue<LogEntry> logQueue_;
    mutable std::mutex mutex_;
    std::thread writerThread_;
    std::atomic<bool> running_{false};
    
    void WriterLoop();
    void WriteEntry(const LogEntry& entry);
    std::string FormatEntry(const LogEntry& entry);
    std::string LevelToString(LogLevel level);
};

// Alert manager
class AlertManager {
public:
    struct AlertRule {
        std::string name;
        std::string condition; // e.g., "latency_p95 > 1000"
        std::string severity;  // warning, critical
        int durationSeconds = 60;
        std::vector<std::string> notifications; // email, slack, pagerduty
    };
    
    struct Alert {
        std::string id;
        std::string ruleName;
        std::string severity;
        std::string message;
        std::chrono::system_clock::time_point firedAt;
        std::chrono::system_clock::time_point resolvedAt;
        bool resolved = false;
    };
    
    static AlertManager& GetInstance();
    
    // Initialize
    bool Initialize(const std::string& configPath = "alerts.yaml");
    
    // Add alert rule
    void AddRule(const AlertRule& rule);
    
    // Evaluate rules
    void EvaluateRules(const std::map<std::string, double>& metrics);
    
    // Get active alerts
    std::vector<Alert> GetActiveAlerts();
    
    // Get alert history
    std::vector<Alert> GetAlertHistory(int limit = 100);
    
    // Resolve alert
    void ResolveAlert(const std::string& alertId);
    
    // Send notification
    void SendNotification(const Alert& alert);

private:
    AlertManager() = default;
    ~AlertManager() = default;
    AlertManager(const AlertManager&) = delete;
    AlertManager& operator=(const AlertManager&) = delete;
    
    std::vector<AlertRule> rules_;
    std::vector<Alert> alerts_;
    mutable std::mutex mutex_;
    
    std::string configPath_;
    
    bool EvaluateCondition(const std::string& condition,
                          const std::map<std::string, double>& metrics);
    void SendEmail(const Alert& alert, const std::string& email);
    void SendSlack(const Alert& alert, const std::string& webhook);
};

} // namespace deployment
} // namespace rawrxd
