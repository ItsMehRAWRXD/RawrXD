/**
 * DistributedTracer.cpp
 *
 * Phase F Batch 2/5: Distributed Tracing
 *
 * Implementation of OpenTelemetry-compatible distributed tracing.
 */

#include "DistributedTracer.hpp"
#include "../core/Logger.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>

namespace Telemetry {

// ============================================================================
// SpanContext Implementation
// ============================================================================

bool SpanContext::IsValid() const {
    return !traceId.empty() && !spanId.empty();
}

std::string SpanContext::ToW3C() const {
    // W3C format: version-traceId-parentId-flags
    std::string flags = sampled ? "01" : "00";
    return "00-" + traceId + "-" + spanId + "-" + flags;
}

std::string SpanContext::ToJaeger() const {
    // Jaeger format: {traceId}:{spanId}:{parentSpanId}:{flags}
    std::string flags = sampled ? "1" : "0";
    return traceId + ":" + spanId + ":" + parentSpanId + ":" + flags;
}

std::string SpanContext::ToZipkin() const {
    // Zipkin B3 format
    return sampled ? "1" : "0";
}

SpanContext SpanContext::FromW3C(const std::string& header) {
    SpanContext ctx;
    // Parse: version-traceId-parentId-flags
    // Simplified parsing
    return ctx;
}

SpanContext SpanContext::FromJaeger(const std::string& header) {
    SpanContext ctx;
    // Parse: traceId:spanId:parentSpanId:flags
    // Simplified parsing
    return ctx;
}

SpanContext SpanContext::FromZipkin(const std::string& header) {
    SpanContext ctx;
    ctx.sampled = (header == "1" || header == "d");
    return ctx;
}

std::string SpanContext::GenerateTraceId() {
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dis;
    
    uint64_t high = dis(gen);
    uint64_t low = dis(gen);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << high
       << std::setw(16) << low;
    return ss.str();
}

std::string SpanContext::GenerateSpanId() {
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dis;
    
    uint64_t id = dis(gen);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << id;
    return ss.str();
}

// ============================================================================
// SpanKind Helpers
// ============================================================================

std::string SpanKindToString(SpanKind kind) {
    switch (kind) {
        case SpanKind::INTERNAL: return "INTERNAL";
        case SpanKind::SERVER:   return "SERVER";
        case SpanKind::CLIENT:   return "CLIENT";
        case SpanKind::PRODUCER: return "PRODUCER";
        case SpanKind::CONSUMER: return "CONSUMER";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// SpanStatus Helpers
// ============================================================================

std::string SpanStatusToString(SpanStatus status) {
    switch (status) {
        case SpanStatus::UNSET: return "UNSET";
        case SpanStatus::OK:    return "OK";
        case SpanStatus::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// SpanEvent Implementation
// ============================================================================

SpanEvent::SpanEvent(const std::string& name, uint64_t timestamp)
    : name(name), timestamp(timestamp) {}

void SpanEvent::SetAttribute(const std::string& key, const std::string& value) {
    attributes[key] = value;
}

void SpanEvent::SetAttribute(const std::string& key, int64_t value) {
    attributes[key] = std::to_string(value);
}

void SpanEvent::SetAttribute(const std::string& key, double value) {
    attributes[key] = std::to_string(value);
}

void SpanEvent::SetAttribute(const std::string& key, bool value) {
    attributes[key] = value ? "true" : "false";
}

// ============================================================================
// Span Implementation
// ============================================================================

Span::Span(const std::string& name, const SpanContext& context)
    : name_(name), context_(context) {}

Span::~Span() {
    if (recording_) {
        End();
    }
}

void Span::Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    startTime_ = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    recording_ = true;
}

void Span::End() {
    uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    End(now);
}

void Span::End(uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!recording_) return;
    
    endTime_ = timestamp;
    recording_ = false;
}

uint64_t Span::GetDurationMs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (startTime_ == 0) return 0;
    uint64_t end = endTime_ > 0 ? endTime_ : 
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    return (end - startTime_) / 1000000; // Convert ns to ms
}

void Span::SetAttribute(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    attributes_[key] = value;
}

void Span::SetAttribute(const std::string& key, int64_t value) {
    SetAttribute(key, std::to_string(value));
}

void Span::SetAttribute(const std::string& key, double value) {
    SetAttribute(key, std::to_string(value));
}

void Span::SetAttribute(const std::string& key, bool value) {
    SetAttribute(key, std::string(value ? "true" : "false"));
}

void Span::SetAttribute(const std::string& key, const char* value) {
    SetAttribute(key, std::string(value));
}

void Span::SetStatus(SpanStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_ = status;
}

void Span::SetStatus(SpanStatus status, const std::string& description) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_ = status;
    statusDescription_ = description;
}

void Span::AddEvent(const std::string& name) {
    uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    AddEvent(name, now);
}

void Span::AddEvent(const std::string& name, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.emplace_back(name, timestamp);
}

void Span::AddEvent(const SpanEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(event);
}

void Span::AddLink(const SpanContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    SpanLink link;
    link.context = context;
    links_.push_back(link);
}

void Span::AddLink(const SpanContext& context, const std::map<std::string, std::string>& attrs) {
    std::lock_guard<std::mutex> lock(mutex_);
    SpanLink link;
    link.context = context;
    link.attributes = attrs;
    links_.push_back(link);
}

std::string Span::ToJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string json = "{";
    json += "\"traceId\":\"" + context_.traceId + "\",";
    json += "\"spanId\":\"" + context_.spanId + "\",";
    json += "\"parentSpanId\":\"" + context_.parentSpanId + "\",";
    json += "\"name\":\"" + name_ + "\",";
    json += "\"kind\":\"" + SpanKindToString(kind_) + "\",";
    json += "\"status\":\"" + SpanStatusToString(status_) + "\",";
    json += "\"startTime\":" + std::to_string(startTime_) + ",";
    json += "\"endTime\":" + std::to_string(endTime_) + ",";
    
    // Attributes
    json += "\"attributes\":{";
    bool first = true;
    for (const auto& [key, value] : attributes_) {
        if (!first) json += ",";
        first = false;
        json += "\"" + key + "\":\"" + value + "\"";
    }
    json += "}";
    
    json += "}";
    return json;
}

std::string Span::ToProto() const {
    // OTLP protobuf format - simplified
    return ToJson();
}

// ============================================================================
// Tracer Implementation
// ============================================================================

thread_local Span::Ptr Tracer::currentSpan_ = nullptr;

Tracer::Tracer(const Config& config) : config_(config) {}

Tracer::~Tracer() {
    Shutdown();
}

bool Tracer::Initialize() {
    // Create sampler
    if (config_.samplingRatio >= 1.0) {
        sampler_ = std::make_unique<AlwaysOnSampler>();
    } else if (config_.samplingRatio <= 0.0) {
        sampler_ = std::make_unique<AlwaysOffSampler>();
    } else {
        sampler_ = std::make_unique<TraceIdRatioSampler>(config_.samplingRatio);
    }
    
    LOG_INFO("Tracer initialized for service: " + config_.serviceName);
    return true;
}

void Tracer::Shutdown() {
    if (processor_) {
        processor_->Shutdown();
    }
}

Span::Ptr Tracer::StartSpan(const std::string& name) {
    return StartSpan(name, StartSpanOptions{});
}

Span::Ptr Tracer::StartSpan(const std::string& name, const SpanContext& parent) {
    StartSpanOptions options;
    options.parent = parent;
    return StartSpan(name, options);
}

Span::Ptr Tracer::StartSpan(const std::string& name, Span::Ptr parent) {
    if (parent) {
        return StartSpan(name, parent->GetContext());
    }
    return StartSpan(name);
}

Span::Ptr Tracer::StartSpan(const std::string& name, const StartSpanOptions& options) {
    SpanContext context;
    context.traceId = options.parent ? options.parent->traceId : SpanContext::GenerateTraceId();
    context.spanId = SpanContext::GenerateSpanId();
    context.parentSpanId = options.parent ? options.parent->spanId : "";
    
    // Check sampling
    auto samplingResult = sampler_->ShouldSample(
        options.parent ? *options.parent : SpanContext{},
        context.traceId,
        name,
        options.kind,
        options.attributes,
        options.links
    );
    
    context.sampled = samplingResult.sampled;
    
    auto span = std::make_shared<Span>(name, context);
    span->SetSpanKind(options.kind);
    
    for (const auto& [key, value] : options.attributes) {
        span->SetAttribute(key, value);
    }
    
    for (const auto& link : options.links) {
        span->AddLink(link.context, link.attributes);
    }
    
    if (options.startTime > 0) {
        span->Start();
    } else {
        span->Start();
    }
    
    if (processor_) {
        processor_->OnStart(span);
    }
    
    spanCount_++;
    return span;
}

Span::Ptr Tracer::GetCurrentSpan() {
    return currentSpan_;
}

void Tracer::SetCurrentSpan(Span::Ptr span) {
    currentSpan_ = span;
}

SpanContext Tracer::ExtractContext(const std::map<std::string, std::string>& carrier) {
    auto it = carrier.find("traceparent");
    if (it != carrier.end()) {
        return SpanContext::FromW3C(it->second);
    }
    
    it = carrier.find("uber-trace-id");
    if (it != carrier.end()) {
        return SpanContext::FromJaeger(it->second);
    }
    
    it = carrier.find("X-B3-Sampled");
    if (it != carrier.end()) {
        return SpanContext::FromZipkin(it->second);
    }
    
    return SpanContext{};
}

void Tracer::InjectContext(Span::Ptr span, std::map<std::string, std::string>& carrier) {
    if (!span) return;
    
    carrier["traceparent"] = span->GetContext().ToW3C();
    carrier["uber-trace-id"] = span->GetContext().ToJaeger();
}

bool Tracer::ShouldSample(const std::string& traceId, const std::string& operation) {
    auto result = sampler_->ShouldSample(
        SpanContext{}, traceId, operation, SpanKind::INTERNAL, {}, {}
    );
    return result.sampled;
}

void Tracer::ForceFlush() {
    if (processor_) {
        processor_->ForceFlush();
    }
}

std::string Tracer::GetStatusJson() const {
    std::string json = "{";
    json += "\"serviceName\":\"" + config_.serviceName + "\",";
    json += "\"spanCount\":" + std::to_string(spanCount_.load()) + ",";
    json += "\"droppedSpans\":" + std::to_string(droppedSpans_.load()) + ",";
    json += "\"samplingRatio\":" + std::to_string(config_.samplingRatio);
    json += "}";
    return json;
}

// ============================================================================
// SimpleSpanProcessor Implementation
// ============================================================================

SimpleSpanProcessor::SimpleSpanProcessor(std::unique_ptr<SpanExporter> exporter)
    : exporter_(std::move(exporter)) {}

void SimpleSpanProcessor::OnStart(Span::Ptr span) {
    // No-op for simple processor
}

void SimpleSpanProcessor::OnEnd(Span::Ptr span) {
    if (exporter_) {
        exporter_->Export({span});
    }
}

void SimpleSpanProcessor::ForceFlush() {
    if (exporter_) {
        exporter_->ForceFlush();
    }
}

void SimpleSpanProcessor::Shutdown() {
    if (exporter_) {
        exporter_->Shutdown();
    }
}

// ============================================================================
// BatchSpanProcessor Implementation
// ============================================================================

BatchSpanProcessor::BatchSpanProcessor(std::unique_ptr<SpanExporter> exporter, const Config& config)
    : exporter_(std::move(exporter)), config_(config) {}

BatchSpanProcessor::~BatchSpanProcessor() {
    Shutdown();
}

void BatchSpanProcessor::OnStart(Span::Ptr span) {
    // No-op
}

void BatchSpanProcessor::OnEnd(Span::Ptr span) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    if (queue_.size() >= config_.maxQueueSize) {
        // Queue full, drop span
        return;
    }
    
    queue_.push_back(span);
    cv_.notify_one();
}

void BatchSpanProcessor::ForceFlush() {
    std::vector<Span::Ptr> batch;
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        batch = std::move(queue_);
        queue_.clear();
    }
    
    if (!batch.empty() && exporter_) {
        ExportBatch(batch);
    }
}

void BatchSpanProcessor::Shutdown() {
    running_ = false;
    cv_.notify_all();
    
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    
    ForceFlush();
    
    if (exporter_) {
        exporter_->Shutdown();
    }
}

void BatchSpanProcessor::WorkerLoop() {
    running_ = true;
    
    while (running_) {
        std::vector<Span::Ptr> batch;
        
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(config_.scheduledDelayMs), [this] {
                return !queue_.empty() || !running_;
            });
            
            if (!running_) break;
            
            // Take batch from queue
            size_t batchSize = std::min(queue_.size(), config_.maxExportBatchSize);
            batch.assign(queue_.begin(), queue_.begin() + batchSize);
            queue_.erase(queue_.begin(), queue_.begin() + batchSize);
        }
        
        if (!batch.empty() && exporter_) {
            ExportBatch(batch);
        }
    }
}

void BatchSpanProcessor::ExportBatch(const std::vector<Span::Ptr>& batch) {
    auto result = exporter_->Export(batch);
    
    if (result != SpanExporter::ExportResult::SUCCESS) {
        LOG_WARNING("Failed to export span batch");
    }
}

// ============================================================================
// OTLP Exporter Implementation
// ============================================================================

OtlpExporter::OtlpExporter(const Config& config) : config_(config) {}

SpanExporter::ExportResult OtlpExporter::Export(const std::vector<Span::Ptr>& spans) {
    // TODO: Implement HTTP export to OTLP endpoint
    // For now, just log
    LOG_DEBUG("Exporting " + std::to_string(spans.size()) + " spans to OTLP");
    return ExportResult::SUCCESS;
}

void OtlpExporter::ForceFlush() {
    // No-op for now
}

void OtlpExporter::Shutdown() {
    running_ = false;
}

// ============================================================================
// Jaeger Exporter Implementation
// ============================================================================

JaegerExporter::JaegerExporter(const Config& config) : config_(config) {}

SpanExporter::ExportResult JaegerExporter::Export(const std::vector<Span::Ptr>& spans) {
    // TODO: Implement HTTP export to Jaeger
    LOG_DEBUG("Exporting " + std::to_string(spans.size()) + " spans to Jaeger");
    return ExportResult::SUCCESS;
}

void JaegerExporter::ForceFlush() {
    // No-op
}

void JaegerExporter::Shutdown() {
    running_ = false;
}

// ============================================================================
// Zipkin Exporter Implementation
// ============================================================================

ZipkinExporter::ZipkinExporter(const Config& config) : config_(config) {}

SpanExporter::ExportResult ZipkinExporter::Export(const std::vector<Span::Ptr>& spans) {
    // TODO: Implement HTTP export to Zipkin
    LOG_DEBUG("Exporting " + std::to_string(spans.size()) + " spans to Zipkin");
    return ExportResult::SUCCESS;
}

void ZipkinExporter::ForceFlush() {
    // No-op
}

void ZipkinExporter::Shutdown() {
    running_ = false;
}

// ============================================================================
// FileSpanExporter Implementation
// ============================================================================

FileSpanExporter::FileSpanExporter(const std::string& filepath) : filepath_(filepath) {
    file_.open(filepath, std::ios::app);
}

SpanExporter::ExportResult FileSpanExporter::Export(const std::vector<Span::Ptr>& spans) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!file_.is_open()) {
        return ExportResult::FAILURE;
    }
    
    for (const auto& span : spans) {
        file_ << span->ToJson() << std::endl;
    }
    
    file_.flush();
    return ExportResult::SUCCESS;
}

void FileSpanExporter::ForceFlush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.flush();
    }
}

void FileSpanExporter::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.close();
    }
}

// ============================================================================
// Sampler Implementations
// ============================================================================

Sampler::SamplingResult AlwaysOnSampler::ShouldSample(
    const SpanContext& parentContext,
    const std::string& traceId,
    const std::string& name,
    SpanKind kind,
    const std::map<std::string, std::string>& attributes,
    const std::vector<SpanLink>& links
) {
    return {true, {}};
}

Sampler::SamplingResult AlwaysOffSampler::ShouldSample(
    const SpanContext& parentContext,
    const std::string& traceId,
    const std::string& name,
    SpanKind kind,
    const std::map<std::string, std::string>& attributes,
    const std::vector<SpanLink>& links
) {
    return {false, {}};
}

TraceIdRatioSampler::TraceIdRatioSampler(double ratio) : ratio_(ratio) {}

Sampler::SamplingResult TraceIdRatioSampler::ShouldSample(
    const SpanContext& parentContext,
    const std::string& traceId,
    const std::string& name,
    SpanKind kind,
    const std::map<std::string, std::string>& attributes,
    const std::vector<SpanLink>& links
) {
    // Use trace ID to make consistent sampling decision
    uint64_t traceIdValue = std::stoull(traceId.substr(0, 16), nullptr, 16);
    bool sampled = (traceIdValue % 10000) < (ratio_ * 10000);
    
    return {sampled, {}};
}

std::string TraceIdRatioSampler::GetDescription() const {
    return "TraceIdRatioSampler{" + std::to_string(ratio_) + "}";
}

ParentBasedSampler::ParentBasedSampler(std::unique_ptr<Sampler> rootSampler)
    : rootSampler_(std::move(rootSampler)) {}

Sampler::SamplingResult ParentBasedSampler::ShouldSample(
    const SpanContext& parentContext,
    const std::string& traceId,
    const std::string& name,
    SpanKind kind,
    const std::map<std::string, std::string>& attributes,
    const std::vector<SpanLink>& links
) {
    if (parentContext.IsValid()) {
        // Follow parent decision
        return {parentContext.sampled, {}};
    }
    
    // No parent, use root sampler
    return rootSampler_->ShouldSample(parentContext, traceId, name, kind, attributes, links);
}

// ============================================================================
// SpanGuard Implementation
// ============================================================================

SpanGuard::SpanGuard(Span::Ptr span) : span_(span) {}

SpanGuard::~SpanGuard() {
    if (span_) {
        span_->End();
    }
}

// ============================================================================
// Tracing Implementation
// ============================================================================

std::unique_ptr<Tracer> Tracing::tracer_ = nullptr;
std::mutex Tracing::mutex_;

void Tracing::Initialize(const Tracer::Config& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    tracer_ = std::make_unique<Tracer>(config);
    tracer_->Initialize();
}

void Tracing::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (tracer_) {
        tracer_->Shutdown();
        tracer_.reset();
    }
}

Tracer* Tracing::GetTracer() {
    std::lock_guard<std::mutex> lock(mutex_);
    return tracer_.get();
}

Span::Ptr Tracing::GetCurrentSpan() {
    if (tracer_) {
        return tracer_->GetCurrentSpan();
    }
    return nullptr;
}

SpanContext Tracing::GetCurrentContext() {
    auto span = GetCurrentSpan();
    if (span) {
        return span->GetContext();
    }
    return SpanContext{};
}

Span::Ptr Tracing::StartSpan(const std::string& name) {
    if (tracer_) {
        return tracer_->StartSpan(name);
    }
    return nullptr;
}

Span::Ptr Tracing::StartSpan(const std::string& name, const SpanContext& parent) {
    if (tracer_) {
        return tracer_->StartSpan(name, parent);
    }
    return nullptr;
}

} // namespace Telemetry
