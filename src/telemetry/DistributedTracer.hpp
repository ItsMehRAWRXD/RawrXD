/**
 * DistributedTracer.hpp
 *
 * Phase F Batch 2/5: Distributed Tracing
 *
 * OpenTelemetry-compatible distributed tracing for request flow analysis.
 * Tracks requests across service boundaries with span context propagation.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <functional>
#include <optional>

namespace Telemetry {

// ============================================================================
// Span Context
// ============================================================================

/**
 * Trace context for distributed tracing.
 * Propagated across service boundaries.
 */
struct SpanContext {
    std::string traceId;      // Unique trace identifier
    std::string spanId;       // Current span identifier
    std::string parentSpanId; // Parent span identifier (empty if root)
    bool sampled;             // Whether this trace is sampled
    std::map<std::string, std::string> baggage; // Additional context
    
    bool IsValid() const;
    bool IsRoot() const { return parentSpanId.empty(); }
    
    // Serialization for propagation
    std::string ToW3C() const;           // W3C Trace Context format
    std::string ToJaeger() const;          // Jaeger format
    std::string ToZipkin() const;          // Zipkin B3 format
    
    static SpanContext FromW3C(const std::string& header);
    static SpanContext FromJaeger(const std::string& header);
    static SpanContext FromZipkin(const std::string& header);
    
    // Generate new IDs
    static std::string GenerateTraceId();
    static std::string GenerateSpanId();
};

// ============================================================================
// Span Kind
// ============================================================================

enum class SpanKind {
    INTERNAL,   // Internal operation
    SERVER,     // Server handling a request
    CLIENT,     // Client making a request
    PRODUCER,   // Message producer
    CONSUMER    // Message consumer
};

std::string SpanKindToString(SpanKind kind);

// ============================================================================
// Span Status
// ============================================================================

enum class SpanStatus {
    UNSET,      // Default, not set
    OK,         // Success
    ERROR       // Error occurred
};

std::string SpanStatusToString(SpanStatus status);

// ============================================================================
// Span Event
// ============================================================================

/**
 * Event attached to a span.
 */
struct SpanEvent {
    std::string name;
    uint64_t timestamp;
    std::map<std::string, std::string> attributes;
    
    SpanEvent() = default;
    SpanEvent(const std::string& name, uint64_t timestamp);
    
    void SetAttribute(const std::string& key, const std::string& value);
    void SetAttribute(const std::string& key, int64_t value);
    void SetAttribute(const std::string& key, double value);
    void SetAttribute(const std::string& key, bool value);
};

// ============================================================================
// Span Link
// ============================================================================

/**
 * Link to another span (for batch operations, etc.).
 */
struct SpanLink {
    SpanContext context;
    std::map<std::string, std::string> attributes;
};

// ============================================================================
// Span
// ============================================================================

/**
 * Single operation within a trace.
 */
class Span {
public:
    using Ptr = std::shared_ptr<Span>;
    
    Span(const std::string& name, const SpanContext& context);
    ~Span();
    
    // Span identification
    std::string GetSpanId() const { return context_.spanId; }
    std::string GetTraceId() const { return context_.traceId; }
    SpanContext GetContext() const { return context_; }
    
    // Timing
    void Start();
    void End();
    void End(uint64_t timestamp);
    bool IsRecording() const { return recording_; }
    
    // Duration
    uint64_t GetStartTime() const { return startTime_; }
    uint64_t GetEndTime() const { return endTime_; }
    uint64_t GetDurationMs() const;
    
    // Attributes
    void SetAttribute(const std::string& key, const std::string& value);
    void SetAttribute(const std::string& key, int64_t value);
    void SetAttribute(const std::string& key, double value);
    void SetAttribute(const std::string& key, bool value);
    void SetAttribute(const std::string& key, const char* value);
    
    template<typename T>
    void SetAttributes(const std::map<std::string, T>& attrs);
    
    // Status
    void SetStatus(SpanStatus status);
    void SetStatus(SpanStatus status, const std::string& description);
    SpanStatus GetStatus() const { return status_; }
    
    // Events
    void AddEvent(const std::string& name);
    void AddEvent(const std::string& name, uint64_t timestamp);
    void AddEvent(const SpanEvent& event);
    
    // Links
    void AddLink(const SpanContext& context);
    void AddLink(const SpanContext& context, const std::map<std::string, std::string>& attrs);
    
    // Kind
    void SetSpanKind(SpanKind kind) { kind_ = kind; }
    SpanKind GetSpanKind() const { return kind_; }
    
    // Serialization
    std::string ToJson() const;
    std::string ToProto() const; // OTLP format
    
private:
    std::string name_;
    SpanContext context_;
    SpanKind kind_ = SpanKind::INTERNAL;
    SpanStatus status_ = SpanStatus::UNSET;
    std::string statusDescription_;
    
    uint64_t startTime_ = 0;
    uint64_t endTime_ = 0;
    bool recording_ = false;
    
    std::map<std::string, std::string> attributes_;
    std::vector<SpanEvent> events_;
    std::vector<SpanLink> links_;
    
    mutable std::mutex mutex_;
};

// ============================================================================
// Tracer
// ============================================================================

/**
 * Creates and manages spans.
 */
class Tracer {
public:
    struct Config {
        std::string serviceName;
        std::string serviceVersion;
        std::string serviceInstanceId;
        std::map<std::string, std::string> resourceAttributes;
        
        // Sampling
        double samplingRatio = 1.0;  // 1.0 = always sample
        uint32_t maxSpansPerSecond = 0;  // 0 = unlimited
        
        // Export
        uint64_t batchTimeoutMs = 5000;
        size_t maxQueueSize = 2048;
        size_t maxExportBatchSize = 512;
    };
    
    explicit Tracer(const Config& config);
    ~Tracer();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Span creation
    Span::Ptr StartSpan(const std::string& name);
    Span::Ptr StartSpan(const std::string& name, const SpanContext& parent);
    Span::Ptr StartSpan(const std::string& name, Span::Ptr parent);
    
    // With options
    struct StartSpanOptions {
        std::optional<SpanContext> parent;
        SpanKind kind = SpanKind::INTERNAL;
        std::map<std::string, std::string> attributes;
        std::vector<SpanLink> links;
        uint64_t startTime = 0;
    };
    
    Span::Ptr StartSpan(const std::string& name, const StartSpanOptions& options);
    
    // Current span management
    Span::Ptr GetCurrentSpan();
    void SetCurrentSpan(Span::Ptr span);
    Scope<Span::Ptr> WithSpan(Span::Ptr span);
    
    // Context propagation
    SpanContext ExtractContext(const std::map<std::string, std::string>& carrier);
    void InjectContext(Span::Ptr span, std::map<std::string, std::string>& carrier);
    
    // Sampling
    bool ShouldSample(const std::string& traceId, const std::string& operation);
    
    // Force flush
    void ForceFlush();
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    
    std::atomic<uint64_t> spanCount_{0};
    std::atomic<uint64_t> droppedSpans_{0};
    
    thread_local static Span::Ptr currentSpan_;
    
    // Span processor
    std::unique_ptr<SpanProcessor> processor_;
    
    // Sampling
    std::unique_ptr<Sampler> sampler_;
};

// ============================================================================
// Span Processor
// ============================================================================

/**
 * Processes completed spans.
 */
class SpanProcessor {
public:
    virtual ~SpanProcessor() = default;
    
    virtual void OnStart(Span::Ptr span) = 0;
    virtual void OnEnd(Span::Ptr span) = 0;
    virtual void ForceFlush() = 0;
    virtual void Shutdown() = 0;
};

/**
 * Simple span processor that exports immediately.
 */
class SimpleSpanProcessor : public SpanProcessor {
public:
    explicit SimpleSpanProcessor(std::unique_ptr<SpanExporter> exporter);
    
    void OnStart(Span::Ptr span) override;
    void OnEnd(Span::Ptr span) override;
    void ForceFlush() override;
    void Shutdown() override;
    
private:
    std::unique_ptr<SpanExporter> exporter_;
};

/**
 * Batch span processor for efficiency.
 */
class BatchSpanProcessor : public SpanProcessor {
public:
    struct Config {
        uint64_t maxQueueSize = 2048;
        uint64_t scheduledDelayMs = 5000;
        uint64_t exportTimeoutMs = 30000;
        size_t maxExportBatchSize = 512;
    };
    
    BatchSpanProcessor(std::unique_ptr<SpanExporter> exporter, const Config& config);
    ~BatchSpanProcessor();
    
    void OnStart(Span::Ptr span) override;
    void OnEnd(Span::Ptr span) override;
    void ForceFlush() override;
    void Shutdown() override;
    
private:
    std::unique_ptr<SpanExporter> exporter_;
    Config config_;
    
    std::vector<Span::Ptr> queue_;
    mutable std::mutex queueMutex_;
    std::condition_variable cv_;
    
    std::atomic<bool> running_{false};
    std::thread workerThread_;
    
    void WorkerLoop();
    void ExportBatch(const std::vector<Span::Ptr>& batch);
};

// ============================================================================
// Span Exporter
// ============================================================================

/**
 * Exports spans to a backend.
 */
class SpanExporter {
public:
    enum class ExportResult {
        SUCCESS,
        FAILURE,
        TIMEOUT
    };
    
    virtual ~SpanExporter() = default;
    
    virtual ExportResult Export(const std::vector<Span::Ptr>& spans) = 0;
    virtual void ForceFlush() = 0;
    virtual void Shutdown() = 0;
};

/**
 * OTLP (OpenTelemetry Protocol) exporter.
 */
class OtlpExporter : public SpanExporter {
public:
    struct Config {
        std::string endpoint = "http://localhost:4318";
        std::string headers;
        uint64_t timeoutMs = 10000;
        bool insecure = false;
    };
    
    explicit OtlpExporter(const Config& config);
    
    ExportResult Export(const std::vector<Span::Ptr>& spans) override;
    void ForceFlush() override;
    void Shutdown() override;
    
private:
    Config config_;
    std::atomic<bool> running_{true};
};

/**
 * Jaeger exporter.
 */
class JaegerExporter : public SpanExporter {
public:
    struct Config {
        std::string endpoint = "http://localhost:14268";
        std::string username;
        std::string password;
        uint64_t timeoutMs = 10000;
    };
    
    explicit JaegerExporter(const Config& config);
    
    ExportResult Export(const std::vector<Span::Ptr>& spans) override;
    void ForceFlush() override;
    void Shutdown() override;
    
private:
    Config config_;
    std::atomic<bool> running_{true};
};

/**
 * Zipkin exporter.
 */
class ZipkinExporter : public SpanExporter {
public:
    struct Config {
        std::string endpoint = "http://localhost:9411";
        uint64_t timeoutMs = 10000;
    };
    
    explicit ZipkinExporter(const Config& config);
    
    ExportResult Export(const std::vector<Span::Ptr>& spans) override;
    void ForceFlush() override;
    void Shutdown() override;
    
private:
    Config config_;
    std::atomic<bool> running_{true};
};

/**
 * File exporter for debugging.
 */
class FileSpanExporter : public SpanExporter {
public:
    explicit FileSpanExporter(const std::string& filepath);
    
    ExportResult Export(const std::vector<Span::Ptr>& spans) override;
    void ForceFlush() override;
    void Shutdown() override;
    
private:
    std::string filepath_;
    std::ofstream file_;
    std::mutex mutex_;
};

// ============================================================================
// Sampler
// ============================================================================

/**
 * Decides whether to sample a trace.
 */
class Sampler {
public:
    virtual ~Sampler() = default;
    
    struct SamplingResult {
        bool sampled;
        std::map<std::string, std::string> attributes;
    };
    
    virtual SamplingResult ShouldSample(
        const SpanContext& parentContext,
        const std::string& traceId,
        const std::string& name,
        SpanKind kind,
        const std::map<std::string, std::string>& attributes,
        const std::vector<SpanLink>& links
    ) = 0;
    
    virtual std::string GetDescription() const = 0;
};

/**
 * Always sample.
 */
class AlwaysOnSampler : public Sampler {
public:
    SamplingResult ShouldSample(
        const SpanContext& parentContext,
        const std::string& traceId,
        const std::string& name,
        SpanKind kind,
        const std::map<std::string, std::string>& attributes,
        const std::vector<SpanLink>& links
    ) override;
    
    std::string GetDescription() const override { return "AlwaysOnSampler"; }
};

/**
 * Never sample.
 */
class AlwaysOffSampler : public Sampler {
public:
    SamplingResult ShouldSample(
        const SpanContext& parentContext,
        const std::string& traceId,
        const std::string& name,
        SpanKind kind,
        const std::map<std::string, std::string>& attributes,
        const std::vector<SpanLink>& links
    ) override;
    
    std::string GetDescription() const override { return "AlwaysOffSampler"; }
};

/**
 * Sample based on ratio.
 */
class TraceIdRatioSampler : public Sampler {
public:
    explicit TraceIdRatioSampler(double ratio);
    
    SamplingResult ShouldSample(
        const SpanContext& parentContext,
        const std::string& traceId,
        const std::string& name,
        SpanKind kind,
        const std::map<std::string, std::string>& attributes,
        const std::vector<SpanLink>& links
    ) override;
    
    std::string GetDescription() const override;
    
private:
    double ratio_;
};

/**
 * Parent-based sampler.
 */
class ParentBasedSampler : public Sampler {
public:
    explicit ParentBasedSampler(std::unique_ptr<Sampler> rootSampler);
    
    SamplingResult ShouldSample(
        const SpanContext& parentContext,
        const std::string& traceId,
        const std::string& name,
        SpanKind kind,
        const std::map<std::string, std::string>& attributes,
        const std::vector<SpanLink>& links
    ) override;
    
    std::string GetDescription() const override { return "ParentBasedSampler"; }
    
private:
    std::unique_ptr<Sampler> rootSampler_;
};

// ============================================================================
// Tracing Utilities
// ============================================================================

/**
 * RAII span wrapper.
 */
class SpanGuard {
public:
    explicit SpanGuard(Span::Ptr span);
    ~SpanGuard();
    
    Span::Ptr GetSpan() const { return span_; }
    
    // Prevent copying
    SpanGuard(const SpanGuard&) = delete;
    SpanGuard& operator=(const SpanGuard&) = delete;
    
    // Allow moving
    SpanGuard(SpanGuard&&) = default;
    SpanGuard& operator=(SpanGuard&&) = default;
    
private:
    Span::Ptr span_;
};

/**
 * Helper for creating spans.
 */
#define TRACE_SPAN(tracer, name) \
    auto __span_##__LINE__ = (tracer)->StartSpan(name); \
    Telemetry::SpanGuard __guard_##__LINE__(__span_##__LINE__)

#define TRACE_SPAN_WITH_PARENT(tracer, name, parent) \
    auto __span_##__LINE__ = (tracer)->StartSpan(name, parent); \
    Telemetry::SpanGuard __guard_##__LINE__(__span_##__LINE__)

/**
 * Global tracer access.
 */
class Tracing {
public:
    static void Initialize(const Tracer::Config& config);
    static void Shutdown();
    
    static Tracer* GetTracer();
    static Span::Ptr GetCurrentSpan();
    static SpanContext GetCurrentContext();
    
    static Span::Ptr StartSpan(const std::string& name);
    static Span::Ptr StartSpan(const std::string& name, const SpanContext& parent);
    
private:
    static std::unique_ptr<Tracer> tracer_;
    static std::mutex mutex_;
};

} // namespace Telemetry
