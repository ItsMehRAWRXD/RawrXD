// RawrXD Telemetry Pipeline
// Phase AH: Monitoring & Observability

#pragma once

#include <string>
#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <chrono>
#include <unordered_map>

namespace rawrxd {
namespace monitoring {

// Telemetry event types
enum class TelemetryEventType {
    REQUEST_START,
    REQUEST_END,
    MODEL_LOAD,
    MODEL_UNLOAD,
    INFERENCE_START,
    INFERENCE_END,
    ERROR,
    PERFORMANCE,
    SYSTEM,
    CUSTOM
};

// Telemetry event structure
struct TelemetryEvent {
    std::string id;
    TelemetryEventType type;
    std::string service_name;
    std::string operation;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::microseconds duration;
    std::unordered_map<std::string, std::string> attributes;
    std::unordered_map<std::string, double> metrics;
    bool success;
    std::string error_message;
    
    TelemetryEvent()
        : type(TelemetryEventType::CUSTOM)
        , duration(0)
        , success(true) {}
};

// Span context for distributed tracing
struct SpanContext {
    std::string trace_id;
    std::string span_id;
    std::string parent_span_id;
    bool sampled;
    
    SpanContext() : sampled(true) {}
    
    bool isValid() const {
        return !trace_id.empty() && !span_id.empty();
    }
};

// Trace span
struct TraceSpan {
    std::string trace_id;
    std::string span_id;
    std::string parent_span_id;
    std::string operation_name;
    std::chrono::system_clock::time_point start_time;
    std::chrono::microseconds duration;
    std::unordered_map<std::string, std::string> tags;
    std::unordered_map<std::string, std::string> logs;
    bool finished;
    
    TraceSpan() : duration(0), finished(false) {}
};

// Log entry
struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string level;
    std::string message;
    std::string source;
    std::unordered_map<std::string, std::string> fields;
    SpanContext span_context;
};

// Export configuration
struct TelemetryExportConfig {
    std::string endpoint;
    std::string protocol;  // "grpc", "http", "udp"
    std::string format;    // "otlp", "jaeger", "zipkin"
    std::chrono::seconds batch_timeout;
    size_t max_batch_size;
    size_t max_queue_size;
    bool compression_enabled;
    std::unordered_map<std::string, std::string> headers;
    
    TelemetryExportConfig()
        : protocol("http")
        , format("otlp")
        , batch_timeout(std::chrono::seconds(5))
        , max_batch_size(512)
        , max_queue_size(2048)
        , compression_enabled(true) {}
};

// Forward declarations
class TelemetryExporter;
class TraceCollector;
class LogCollector;

/**
 * TelemetryPipeline - Central telemetry collection and export
 * 
 * Collects metrics, traces, and logs for observability.
 * Supports OpenTelemetry protocol (OTLP) export.
 */
class TelemetryPipeline {
public:
    TelemetryPipeline();
    ~TelemetryPipeline();
    
    // Initialize pipeline
    bool initialize(const TelemetryExportConfig& config);
    
    // Event recording
    void recordEvent(const TelemetryEvent& event);
    void recordEvent(TelemetryEventType type, const std::string& operation,
                     const std::unordered_map<std::string, std::string>& attributes = {});
    
    // Tracing
    SpanContext startSpan(const std::string& operation_name,
                          const SpanContext& parent = SpanContext());
    void finishSpan(const SpanContext& context);
    void addSpanTag(const SpanContext& context, const std::string& key, const std::string& value);
    void addSpanLog(const SpanContext& context, const std::string& message);
    
    // Logging
    void log(const std::string& level, const std::string& message,
             const std::unordered_map<std::string, std::string>& fields = {});
    void debug(const std::string& message);
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void fatal(const std::string& message);
    
    // Batch operations
    void flush();
    void shutdown();
    
    // Configuration
    void setServiceName(const std::string& name);
    void setServiceVersion(const std::string& version);
    void setAttribute(const std::string& key, const std::string& value);
    
    // Sampling
    void setSamplingRate(double rate);  // 0.0 to 1.0
    bool shouldSample();
    
    // Status
    bool isHealthy() const;
    size_t getQueueSize() const;
    size_t getDroppedEvents() const;
    
private:
    std::string service_name_;
    std::string service_version_;
    std::unordered_map<std::string, std::string> attributes_;
    
    std::queue<TelemetryEvent> event_queue_;
    std::vector<TraceSpan> active_spans_;
    std::queue<LogEntry> log_queue_;
    
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    std::unique_ptr<TelemetryExporter> exporter_;
    std::unique_ptr<TraceCollector> trace_collector_;
    std::unique_ptr<LogCollector> log_collector_;
    
    std::thread export_thread_;
    bool running_;
    
    double sampling_rate_;
    size_t dropped_events_;
    
    TelemetryExportConfig config_;
    
    // Internal methods
    void exportLoop();
    void processBatch();
    std::string generateTraceId();
    std::string generateSpanId();
};

/**
 * TelemetryExporter - Export telemetry to backends
 */
class TelemetryExporter {
public:
    virtual ~TelemetryExporter() = default;
    virtual bool exportEvents(const std::vector<TelemetryEvent>& events) = 0;
    virtual bool exportSpans(const std::vector<TraceSpan>& spans) = 0;
    virtual bool exportLogs(const std::vector<LogEntry>& logs) = 0;
    virtual bool isHealthy() const = 0;
    virtual std::string getName() const = 0;
};

/**
 * OTLPExporter - OpenTelemetry Protocol exporter
 */
class OTLPExporter : public TelemetryExporter {
public:
    OTLPExporter(const TelemetryExportConfig& config);
    bool exportEvents(const std::vector<TelemetryEvent>& events) override;
    bool exportSpans(const std::vector<TraceSpan>& spans) override;
    bool exportLogs(const std::vector<LogEntry>& logs) override;
    bool isHealthy() const override;
    std::string getName() const override { return "otlp"; }
    
private:
    TelemetryExportConfig config_;
    bool healthy_;
    
    std::string serializeEvents(const std::vector<TelemetryEvent>& events);
    std::string serializeSpans(const std::vector<TraceSpan>& spans);
    std::string serializeLogs(const std::vector<LogEntry>& logs);
    bool sendRequest(const std::string& data, const std::string& path);
};

/**
 * TraceCollector - Distributed trace collection
 */
class TraceCollector {
public:
    TraceCollector();
    
    void startSpan(const TraceSpan& span);
    void finishSpan(const std::string& span_id);
    TraceSpan getSpan(const std::string& span_id) const;
    std::vector<TraceSpan> getFinishedSpans();
    void clearFinishedSpans();
    
private:
    std::unordered_map<std::string, TraceSpan> active_spans_;
    std::vector<TraceSpan> finished_spans_;
    mutable std::mutex mutex_;
};

/**
 * LogCollector - Structured log collection
 */
class LogCollector {
public:
    LogCollector();
    
    void addLog(const LogEntry& entry);
    std::vector<LogEntry> getLogs(size_t max_count);
    void clearLogs();
    size_t getLogCount() const;
    
private:
    std::queue<LogEntry> logs_;
    mutable std::mutex mutex_;
    size_t max_logs_;
};

// Global telemetry pipeline accessor
TelemetryPipeline* getTelemetryPipeline();
void setTelemetryPipeline(std::unique_ptr<TelemetryPipeline> pipeline);

// Convenience macros for telemetry
#define RAWRXD_TRACE(operation) \
    auto span_context = rawrxd::monitoring::getTelemetryPipeline() \
        ? rawrxd::monitoring::getTelemetryPipeline()->startSpan(operation) \
        : rawrxd::monitoring::SpanContext()

#define RAWRXD_TRACE_END() \
    do { \
        if (rawrxd::monitoring::getTelemetryPipeline() && span_context.isValid()) { \
            rawrxd::monitoring::getTelemetryPipeline()->finishSpan(span_context); \
        } \
    } while(0)

#define RAWRXD_LOG(level, message) \
    do { \
        if (rawrxd::monitoring::getTelemetryPipeline()) { \
            rawrxd::monitoring::getTelemetryPipeline()->level(message); \
        } \
    } while(0)

} // namespace monitoring
} // namespace rawrxd
