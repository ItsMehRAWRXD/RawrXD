// RawrXD Observability Platform
// Phase P.1: Unified observability with metrics, logs, and traces
// OpenTelemetry-compatible observability stack

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Performance {

// Observability signal types
enum class SignalType {
    METRIC,     // Time-series metrics
    LOG,        // Structured logs
    TRACE,      // Distributed traces
    EVENT       // Discrete events
};

// Severity levels for logs
enum class LogSeverity {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    FATAL = 4
};

// Metric types
enum class MetricType {
    COUNTER,        // Monotonically increasing
    GAUGE,          // Can go up and down
    HISTOGRAM,      // Distribution of values
    SUMMARY         // Calculated percentiles
};

// Metric value
struct MetricValue {
    std::string name;
    MetricType type;
    double value;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> labels;
    
    // For histograms
    std::vector<double> buckets;
    std::vector<uint64_t> counts;
};

// Log entry
struct LogEntry {
    std::chrono::steady_clock::time_point timestamp;
    LogSeverity severity;
    std::string message;
    std::string source;
    std::string traceId;
    std::string spanId;
    std::map<std::string, std::string> attributes;
    std::exception_ptr exception;
};

// Trace span
struct TraceSpan {
    std::string traceId;
    std::string spanId;
    std::string parentSpanId;
    std::string name;
    std::string service;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    std::chrono::nanoseconds duration;
    
    enum class Status {
        OK,
        ERROR,
        UNSET
    } status;
    std::string statusMessage;
    
    std::map<std::string, std::string> attributes;
    std::vector<std::string> events;
};

// Event
struct ObservabilityEvent {
    std::string name;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> attributes;
};

// Observability configuration
struct ObservabilityConfig {
    // Sampling
    float traceSampleRate = 1.0f;
    float metricSampleRate = 1.0f;
    float logSampleRate = 1.0f;
    
    // Batching
    uint32_t batchSize = 100;
    uint32_t flushIntervalMs = 1000;
    uint32_t maxQueueSize = 10000;
    
    // Retention
    uint32_t metricRetentionHours = 24;
    uint32_t logRetentionHours = 168;  // 7 days
    uint32_t traceRetentionHours = 24;
    
    // Export
    bool enableStdoutExport = true;
    bool enableFileExport = false;
    std::string fileExportPath = "./observability";
    bool enableOTLPExport = false;
    std::string otlpEndpoint = "http://localhost:4317";
    
    // Resource attributes
    std::string serviceName = "rawrxd";
    std::string serviceVersion = "1.0.0";
    std::string deploymentEnvironment = "production";
    std::map<std::string, std::string> customAttributes;
};

// Metric collector
class MetricCollector {
public:
    MetricCollector();
    ~MetricCollector();
    
    // Counter operations
    void counter(const std::string& name, double increment = 1.0);
    void counter(const std::string& name, double increment, 
                 const std::map<std::string, std::string>& labels);
    
    // Gauge operations
    void gauge(const std::string& name, double value);
    void gauge(const std::string& name, double value,
               const std::map<std::string, std::string>& labels);
    
    // Histogram operations
    void histogram(const std::string& name, double value);
    void histogram(const std::string& name, double value,
                   const std::map<std::string, std::string>& labels);
    void histogram(const std::string& name, double value,
                   const std::vector<double>& buckets);
    
    // Summary operations
    void summary(const std::string& name, double value);
    void summary(const std::string& name, double value,
                 const std::map<std::string, std::string>& labels);
    
    // Get metrics
    std::vector<MetricValue> getMetrics() const;
    std::vector<MetricValue> getMetrics(const std::string& name) const;
    void clearMetrics();
    
    // Export
    std::string exportPrometheus() const;
    std::string exportOTLP() const;
    
private:
    mutable std::mutex mutex_;
    std::map<std::string, MetricValue> metrics_;
    std::map<std::string, std::vector<double>> histogramValues_;
};

// Logger
class Logger {
public:
    Logger();
    ~Logger();
    
    // Log methods
    void debug(const std::string& message);
    void debug(const std::string& message, const std::map<std::string, std::string>& attributes);
    
    void info(const std::string& message);
    void info(const std::string& message, const std::map<std::string, std::string>& attributes);
    
    void warn(const std::string& message);
    void warn(const std::string& message, const std::map<std::string, std::string>& attributes);
    
    void error(const std::string& message);
    void error(const std::string& message, const std::map<std::string, std::string>& attributes);
    void error(const std::string& message, std::exception_ptr ex);
    
    void fatal(const std::string& message);
    void fatal(const std::string& message, const std::map<std::string, std::string>& attributes);
    void fatal(const std::string& message, std::exception_ptr ex);
    
    // Structured logging
    void log(LogSeverity severity, const std::string& message,
             const std::map<std::string, std::string>& attributes);
    
    // Get logs
    std::vector<LogEntry> getLogs() const;
    std::vector<LogEntry> getLogs(LogSeverity minSeverity) const;
    void clearLogs();
    
    // Export
    std::string exportJSON() const;
    std::string exportOTLP() const;
    
private:
    void logInternal(const LogEntry& entry);
    
    mutable std::mutex mutex_;
    std::vector<LogEntry> logs_;
    LogSeverity minLevel_ = LogSeverity::DEBUG;
};

// Tracer
class Tracer {
public:
    Tracer();
    ~Tracer();
    
    // Span creation
    std::string startSpan(const std::string& name);
    std::string startSpan(const std::string& name, const std::string& parentSpanId);
    std::string startSpan(const std::string& name, const std::map<std::string, std::string>& attributes);
    
    // Span operations
    void endSpan(const std::string& spanId);
    void setSpanAttribute(const std::string& spanId, const std::string& key, const std::string& value);
    void addSpanEvent(const std::string& spanId, const std::string& event);
    void setSpanStatus(const std::string& spanId, TraceSpan::Status status, const std::string& message = "");
    
    // Scoped span (RAII)
    class ScopedSpan {
    public:
        ScopedSpan(Tracer* tracer, const std::string& name);
        ~ScopedSpan();
        
        void setAttribute(const std::string& key, const std::string& value);
        void addEvent(const std::string& event);
        void setStatus(TraceSpan::Status status, const std::string& message = "");
        
    private:
        Tracer* tracer_;
        std::string spanId_;
    };
    
    ScopedSpan createScopedSpan(const std::string& name);
    
    // Get traces
    std::vector<TraceSpan> getSpans() const;
    std::vector<TraceSpan> getSpans(const std::string& traceId) const;
    void clearSpans();
    
    // Export
    std::string exportJSON() const;
    std::string exportOTLP() const;
    std::string exportW3C() const;
    
private:
    std::string generateTraceId();
    std::string generateSpanId();
    
    mutable std::mutex mutex_;
    std::map<std::string, TraceSpan> spans_;
    std::map<std::string, std::string> activeSpans_;
    std::atomic<uint64_t> spanCounter_{0};
};

// Event collector
class EventCollector {
public:
    EventCollector();
    ~EventCollector();
    
    // Event recording
    void record(const std::string& name);
    void record(const std::string& name, const std::map<std::string, std::string>& attributes);
    void record(const ObservabilityEvent& event);
    
    // Get events
    std::vector<ObservabilityEvent> getEvents() const;
    std::vector<ObservabilityEvent> getEvents(const std::string& name) const;
    void clearEvents();
    
private:
    mutable std::mutex mutex_;
    std::vector<ObservabilityEvent> events_;
};

// Main observability platform
class ObservabilityPlatform {
public:
    ObservabilityPlatform();
    ~ObservabilityPlatform();
    
    // Lifecycle
    bool initialize(const ObservabilityConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Component access
    MetricCollector* getMetrics() { return metrics_.get(); }
    Logger* getLogger() { return logger_.get(); }
    Tracer* getTracer() { return tracer_.get(); }
    EventCollector* getEvents() { return events_.get(); }
    
    // Convenience methods
    void counter(const std::string& name, double value = 1.0);
    void gauge(const std::string& name, double value);
    void histogram(const std::string& name, double value);
    
    void log(LogSeverity severity, const std::string& message);
    void debug(const std::string& message);
    void info(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);
    void fatal(const std::string& message);
    
    std::string startSpan(const std::string& name);
    void endSpan(const std::string& spanId);
    Tracer::ScopedSpan createSpan(const std::string& name);
    
    void recordEvent(const std::string& name);
    
    // Export
    bool exportToFile(const std::string& directory);
    bool exportToOTLP(const std::string& endpoint);
    
    // Health check
    bool isHealthy() const;
    std::map<std::string, bool> getComponentHealth() const;
    
private:
    void exportLoop();
    void cleanupLoop();
    
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread exportThread_;
    std::thread cleanupThread_;
    
    ObservabilityConfig config_;
    
    std::unique_ptr<MetricCollector> metrics_;
    std::unique_ptr<Logger> logger_;
    std::unique_ptr<Tracer> tracer_;
    std::unique_ptr<EventCollector> events_;
};

// Global observability instance
ObservabilityPlatform& getObservability();
bool initializeObservability(const ObservabilityConfig& config);
bool shutdownObservability();

} // namespace Performance
} // namespace RawrXD
