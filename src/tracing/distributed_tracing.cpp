// RawrXD Distributed Tracing
// Phase 9 - Task 19: Distributed Tracing

#include <windows.h>
#include <string>
#include <vector>
#include <stack>
#include <map>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>

// Span kind
enum SpanKind {
    SPAN_INTERNAL,
    SPAN_SERVER,
    SPAN_CLIENT,
    SPAN_PRODUCER,
    SPAN_CONSUMER
};

// Span status
enum SpanStatus {
    SPAN_UNSET,
    SPAN_OK,
    SPAN_ERROR
};

// Span
struct Span {
    std::string traceId;
    std::string spanId;
    std::string parentSpanId;
    std::string name;
    SpanKind kind;
    SpanStatus status;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    std::map<std::string, std::string> attributes;
    std::map<std::string, std::string> events;
    std::string serviceName;
    std::string serviceVersion;
};

// Trace context
struct TraceContext {
    std::string traceId;
    std::string spanId;
    bool sampled;
};

// Tracer configuration
struct TracerConfig {
    std::string serviceName;
    std::string serviceVersion;
    std::string endpoint;  // OTLP endpoint
    double samplingRate;   // 0.0 - 1.0
    int maxQueueSize;
    int batchSize;
    int exportIntervalMs;
};

// Distributed tracer
class DistributedTracer {
private:
    TracerConfig config;
    std::stack<Span> activeSpans;
    std::vector<Span> completedSpans;
    std::mutex spanMutex;
    std::thread exportThread;
    std::atomic<bool> running;
    std::mt19937 rng;
    std::uniform_real_distribution<double> dist;
    
public:
    DistributedTracer() : running(false), dist(0.0, 1.0) {
        std::random_device rd;
        rng.seed(rd());
    }
    
    ~DistributedTracer() {
        Shutdown();
    }
    
    bool Initialize(const TracerConfig& cfg) {
        config = cfg;
        running = true;
        
        // Start export thread
        exportThread = std::thread(&DistributedTracer::ExportLoop, this);
        
        printf("Distributed tracer initialized\n");
        printf("  Service: %s v%s\n", config.serviceName.c_str(), config.serviceVersion.c_str());
        printf("  Sampling: %.2f%%\n", config.samplingRate * 100);
        printf("  Endpoint: %s\n", config.endpoint.c_str());
        
        return true;
    }
    
    // Start a new span
    Span* StartSpan(const std::string& name, SpanKind kind = SPAN_INTERNAL) {
        // Check sampling
        if (!ShouldSample()) {
            return nullptr;
        }
        
        Span span;
        span.name = name;
        span.kind = kind;
        span.status = SPAN_UNSET;
        span.startTime = std::chrono::steady_clock::now();
        span.serviceName = config.serviceName;
        span.serviceVersion = config.serviceVersion;
        
        // Generate IDs
        span.spanId = GenerateSpanId();
        
        // Check if we have an active span (parent)
        {
            std::lock_guard<std::mutex> lock(spanMutex);
            
            if (!activeSpans.empty()) {
                // Inherit trace ID from parent
                span.traceId = activeSpans.top().traceId;
                span.parentSpanId = activeSpans.top().spanId;
            } else {
                // New trace
                span.traceId = GenerateTraceId();
            }
            
            activeSpans.push(span);
            return &activeSpans.top();
        }
    }
    
    // Start span with external parent
    Span* StartSpanWithParent(const std::string& name, const std::string& parentTraceId,
                             const std::string& parentSpanId, SpanKind kind = SPAN_INTERNAL) {
        if (!ShouldSample()) {
            return nullptr;
        }
        
        Span span;
        span.name = name;
        span.kind = kind;
        span.status = SPAN_UNSET;
        span.startTime = std::chrono::steady_clock::now();
        span.traceId = parentTraceId;
        span.parentSpanId = parentSpanId;
        span.spanId = GenerateSpanId();
        span.serviceName = config.serviceName;
        span.serviceVersion = config.serviceVersion;
        
        std::lock_guard<std::mutex> lock(spanMutex);
        activeSpans.push(span);
        return &activeSpans.top();
    }
    
    // End current span
    void EndSpan() {
        std::lock_guard<std::mutex> lock(spanMutex);
        
        if (activeSpans.empty()) return;
        
        Span span = activeSpans.top();
        span.endTime = std::chrono::steady_clock::now();
        activeSpans.pop();
        
        completedSpans.push_back(span);
        
        // Flush if queue is full
        if (completedSpans.size() >= (size_t)config.batchSize) {
            FlushUnlocked();
        }
    }
    
    // Set span attribute
    void SetAttribute(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(spanMutex);
        
        if (!activeSpans.empty()) {
            activeSpans.top().attributes[key] = value;
        }
    }
    
    // Add event
    void AddEvent(const std::string& name, const std::string& description) {
        std::lock_guard<std::mutex> lock(spanMutex);
        
        if (!activeSpans.empty()) {
            auto now = std::chrono::steady_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();
            
            activeSpans.top().events[name] = description;
        }
    }
    
    // Set span status
    void SetStatus(SpanStatus status) {
        std::lock_guard<std::mutex> lock(spanMutex);
        
        if (!activeSpans.empty()) {
            activeSpans.top().status = status;
        }
    }
    
    // Set error
    void SetError(const std::string& errorMessage) {
        SetStatus(SPAN_ERROR);
        SetAttribute("error", errorMessage);
        AddEvent("error", errorMessage);
    }
    
    // Get current trace context for propagation
    TraceContext GetCurrentContext() {
        std::lock_guard<std::mutex> lock(spanMutex);
        
        TraceContext ctx;
        ctx.sampled = ShouldSample();
        
        if (!activeSpans.empty()) {
            ctx.traceId = activeSpans.top().traceId;
            ctx.spanId = activeSpans.top().spanId;
        }
        
        return ctx;
    }
    
    // Parse trace context from incoming request (W3C Trace Context)
    TraceContext ParseTraceContext(const std::string& traceParent) {
        TraceContext ctx;
        ctx.sampled = false;
        
        // Format: version-traceId-parentId-flags
        // Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
        
        if (traceParent.length() < 55) return ctx;
        
        ctx.traceId = traceParent.substr(3, 32);
        ctx.spanId = traceParent.substr(36, 16);
        
        // Check sampled flag
        char flags = traceParent[53];
        ctx.sampled = (flags & 0x01) != 0;
        
        return ctx;
    }
    
    // Serialize trace context for outgoing request
    std::string SerializeTraceContext(const TraceContext& ctx) {
        std::stringstream ss;
        ss << "00-" << ctx.traceId << "-" << ctx.spanId;
        ss << "-" << (ctx.sampled ? "01" : "00");
        return ss.str();
    }
    
    // Flush spans to exporter
    void Flush() {
        std::lock_guard<std::mutex> lock(spanMutex);
        FlushUnlocked();
    }
    
    void Shutdown() {
        running = false;
        
        Flush();
        
        if (exportThread.joinable()) {
            exportThread.join();
        }
    }
    
    // Export spans as JSON (OpenTelemetry format)
    std::string ExportSpansJSON() {
        std::lock_guard<std::mutex> lock(spanMutex);
        
        std::stringstream ss;
        ss << "{\n";
        ss << "  \"resourceSpans\": [\n";
        ss << "    {\n";
        ss << "      \"resource\": {\n";
        ss << "        \"attributes\": [\n";
        ss << "          {\"key\":\"service.name\",\"value\":{\"stringValue\":\"" << config.serviceName << "\"}},\n";
        ss << "          {\"key\":\"service.version\",\"value\":{\"stringValue\":\"" << config.serviceVersion << "\"}}\n";
        ss << "        ]\n";
        ss << "      },\n";
        ss << "      \"scopeSpans\": [\n";
        ss << "        {\n";
        ss << "          \"spans\": [\n";
        
        bool first = true;
        for (const auto& span : completedSpans) {
            if (!first) ss << ",\n";
            
            ss << "            {\n";
            ss << "              \"traceId\":\"" << span.traceId << "\",\n";
            ss << "              \"spanId\":\"" << span.spanId << "\",\n";
            if (!span.parentSpanId.empty()) {
                ss << "              \"parentSpanId\":\"" << span.parentSpanId << "\",\n";
            }
            ss << "              \"name\":\"" << span.name << "\",\n";
            ss << "              \"kind\":" << (int)span.kind << ",\n";
            
            // Timestamps (nanoseconds)
            auto startNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                span.startTime.time_since_epoch()).count();
            auto endNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                span.endTime.time_since_epoch()).count();
            
            ss << "              \"startTimeUnixNano\":" << startNs << ",\n";
            ss << "              \"endTimeUnixNano\":" << endNs << ",\n";
            
            // Attributes
            if (!span.attributes.empty()) {
                ss << "              \"attributes\":[\n";
                bool attrFirst = true;
                for (const auto& attr : span.attributes) {
                    if (!attrFirst) ss << ",\n";
                    ss << "                {\"key\":\"" << attr.first << "\",\"value\":{\"stringValue\":\"" << attr.second << "\"}}";
                    attrFirst = false;
                }
                ss << "\n              ],\n";
            }
            
            // Status
            ss << "              \"status\":{\"code\":";
            switch (span.status) {
                case SPAN_UNSET: ss << "0"; break;
                case SPAN_OK: ss << "1"; break;
                case SPAN_ERROR: ss << "2"; break;
            }
            ss << "}\n";
            
            ss << "            }";
            first = false;
        }
        
        ss << "\n          ]\n";
        ss << "        }\n";
        ss << "      ]\n";
        ss << "    }\n";
        ss << "  ]\n";
        ss << "}\n";
        
        return ss.str();
    }
    
private:
    bool ShouldSample() {
        return dist(rng) < config.samplingRate;
    }
    
    std::string GenerateTraceId() {
        return GenerateHexId(32);
    }
    
    std::string GenerateSpanId() {
        return GenerateHexId(16);
    }
    
    std::string GenerateHexId(int length) {
        const char* hex = "0123456789abcdef";
        std::string result;
        result.reserve(length);
        
        for (int i = 0; i < length; i++) {
            result += hex[rng() % 16];
        }
        
        return result;
    }
    
    void FlushUnlocked() {
        // In production, this would send to OTLP endpoint
        // For now, just clear the queue
        completedSpans.clear();
    }
    
    void ExportLoop() {
        while (running) {
            Sleep(config.exportIntervalMs);
            Flush();
        }
    }
};

// Global instance
static DistributedTracer g_Tracer;

// C API
extern "C" {

bool Tracer_Init(const char* serviceName, const char* serviceVersion, 
                 const char* endpoint, double samplingRate) {
    TracerConfig config;
    config.serviceName = serviceName;
    config.serviceVersion = serviceVersion;
    config.endpoint = endpoint;
    config.samplingRate = samplingRate;
    config.maxQueueSize = 10000;
    config.batchSize = 100;
    config.exportIntervalMs = 5000;
    
    return g_Tracer.Initialize(config);
}

void* Tracer_StartSpan(const char* name, int kind) {
    return g_Tracer.StartSpan(name, (SpanKind)kind);
}

void Tracer_EndSpan() {
    g_Tracer.EndSpan();
}

void Tracer_SetAttribute(const char* key, const char* value) {
    g_Tracer.SetAttribute(key, value);
}

void Tracer_AddEvent(const char* name, const char* description) {
    g_Tracer.AddEvent(name, description);
}

void Tracer_SetStatus(int status) {
    g_Tracer.SetStatus((SpanStatus)status);
}

void Tracer_SetError(const char* message) {
    g_Tracer.SetError(message);
}

const char* Tracer_GetTraceParent() {
    static std::string traceParent;
    TraceContext ctx = g_Tracer.GetCurrentContext();
    traceParent = g_Tracer.SerializeTraceContext(ctx);
    return traceParent.c_str();
}

void Tracer_ParseTraceParent(const char* traceParent, char* traceId, char* spanId, int* sampled) {
    TraceContext ctx = g_Tracer.ParseTraceContext(traceParent);
    strcpy(traceId, ctx.traceId.c_str());
    strcpy(spanId, ctx.spanId.c_str());
    *sampled = ctx.sampled ? 1 : 0;
}

void Tracer_Flush() {
    g_Tracer.Flush();
}

void Tracer_Shutdown() {
    g_Tracer.Shutdown();
}

} // extern "C"
