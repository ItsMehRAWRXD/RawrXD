// RawrXD Telemetry Pipeline Implementation
// Phase AH: Monitoring & Observability

#include "telemetry_pipeline.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <curl/curl.h>

namespace rawrxd {
namespace monitoring {

// Global telemetry pipeline instance
static std::unique_ptr<TelemetryPipeline> g_telemetry_pipeline;

TelemetryPipeline* getTelemetryPipeline() {
    return g_telemetry_pipeline.get();
}

void setTelemetryPipeline(std::unique_ptr<TelemetryPipeline> pipeline) {
    g_telemetry_pipeline = std::move(pipeline);
}

// TelemetryPipeline implementation
TelemetryPipeline::TelemetryPipeline()
    : running_(false)
    , sampling_rate_(1.0)
    , dropped_events_(0) {
}

TelemetryPipeline::~TelemetryPipeline() {
    shutdown();
}

bool TelemetryPipeline::initialize(const TelemetryExportConfig& config) {
    config_ = config;
    
    // Initialize exporters
    if (config.format == "otlp") {
        exporter_ = std::make_unique<OTLPExporter>(config);
    }
    
    trace_collector_ = std::make_unique<TraceCollector>();
    log_collector_ = std::make_unique<LogCollector>();
    
    // Start export thread
    running_ = true;
    export_thread_ = std::thread(&TelemetryPipeline::exportLoop, this);
    
    return true;
}

void TelemetryPipeline::recordEvent(const TelemetryEvent& event) {
    if (!shouldSample()) return;
    
    std::lock_guard<std::mutex> lock(queue_mutex_);
    
    if (event_queue_.size() >= config_.max_queue_size) {
        dropped_events_++;
        return;
    }
    
    event_queue_.push(event);
    queue_cv_.notify_one();
}

void TelemetryPipeline::recordEvent(TelemetryEventType type, const std::string& operation,
                                     const std::unordered_map<std::string, std::string>& attributes) {
    TelemetryEvent event;
    event.type = type;
    event.operation = operation;
    event.service_name = service_name_;
    event.timestamp = std::chrono::system_clock::now();
    event.attributes = attributes;
    event.success = true;
    
    recordEvent(event);
}

SpanContext TelemetryPipeline::startSpan(const std::string& operation_name,
                                          const SpanContext& parent) {
    if (!shouldSample()) {
        SpanContext ctx;
        ctx.sampled = false;
        return ctx;
    }
    
    SpanContext context;
    context.trace_id = parent.trace_id.empty() ? generateTraceId() : parent.trace_id;
    context.span_id = generateSpanId();
    context.parent_span_id = parent.span_id;
    context.sampled = true;
    
    TraceSpan span;
    span.trace_id = context.trace_id;
    span.span_id = context.span_id;
    span.parent_span_id = context.parent_span_id;
    span.operation_name = operation_name;
    span.start_time = std::chrono::system_clock::now();
    
    trace_collector_->startSpan(span);
    
    return context;
}

void TelemetryPipeline::finishSpan(const SpanContext& context) {
    if (!context.isValid() || !context.sampled) return;
    
    trace_collector_->finishSpan(context.span_id);
}

void TelemetryPipeline::addSpanTag(const SpanContext& context, const std::string& key, const std::string& value) {
    if (!context.isValid() || !context.sampled) return;
    
    auto span = trace_collector_->getSpan(context.span_id);
    span.tags[key] = value;
}

void TelemetryPipeline::addSpanLog(const SpanContext& context, const std::string& message) {
    if (!context.isValid() || !context.sampled) return;
    
    auto span = trace_collector_->getSpan(context.span_id);
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    span.logs[std::to_string(timestamp)] = message;
}

void TelemetryPipeline::log(const std::string& level, const std::string& message,
                             const std::unordered_map<std::string, std::string>& fields) {
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.message = message;
    entry.source = service_name_;
    entry.fields = fields;
    
    log_collector_->addLog(entry);
    
    // Also output to console
    std::cout << "[" << level << "] " << message << std::endl;
}

void TelemetryPipeline::debug(const std::string& message) {
    log("DEBUG", message);
}

void TelemetryPipeline::info(const std::string& message) {
    log("INFO", message);
}

void TelemetryPipeline::warning(const std::string& message) {
    log("WARNING", message);
}

void TelemetryPipeline::error(const std::string& message) {
    log("ERROR", message);
}

void TelemetryPipeline::fatal(const std::string& message) {
    log("FATAL", message);
}

void TelemetryPipeline::flush() {
    processBatch();
}

void TelemetryPipeline::shutdown() {
    running_ = false;
    queue_cv_.notify_all();
    
    if (export_thread_.joinable()) {
        export_thread_.join();
    }
    
    // Final flush
    processBatch();
}

void TelemetryPipeline::setServiceName(const std::string& name) {
    service_name_ = name;
}

void TelemetryPipeline::setServiceVersion(const std::string& version) {
    service_version_ = version;
}

void TelemetryPipeline::setAttribute(const std::string& key, const std::string& value) {
    attributes_[key] = value;
}

void TelemetryPipeline::setSamplingRate(double rate) {
    sampling_rate_ = std::clamp(rate, 0.0, 1.0);
}

bool TelemetryPipeline::shouldSample() {
    if (sampling_rate_ >= 1.0) return true;
    if (sampling_rate_ <= 0.0) return false;
    
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    return dis(gen) < sampling_rate_;
}

bool TelemetryPipeline::isHealthy() const {
    return exporter_ ? exporter_->isHealthy() : true;
}

size_t TelemetryPipeline::getQueueSize() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return event_queue_.size();
}

size_t TelemetryPipeline::getDroppedEvents() const {
    return dropped_events_;
}

void TelemetryPipeline::exportLoop() {
    while (running_) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        auto timeout = std::chrono::seconds(5);
        queue_cv_.wait_for(lock, timeout, [this] {
            return !event_queue_.empty() || !running_;
        });
        
        lock.unlock();
        
        if (!running_) break;
        
        processBatch();
    }
}

void TelemetryPipeline::processBatch() {
    // Collect events
    std::vector<TelemetryEvent> events;
    std::vector<TraceSpan> spans;
    std::vector<LogEntry> logs;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        
        while (!event_queue_.empty() && events.size() < config_.max_batch_size) {
            events.push_back(event_queue_.front());
            event_queue_.pop();
        }
    }
    
    spans = trace_collector_->getFinishedSpans();
    trace_collector_->clearFinishedSpans();
    
    logs = log_collector_->getLogs(config_.max_batch_size);
    log_collector_->clearLogs();
    
    // Export
    if (exporter_) {
        if (!events.empty()) {
            exporter_->exportEvents(events);
        }
        if (!spans.empty()) {
            exporter_->exportSpans(spans);
        }
        if (!logs.empty()) {
            exporter_->exportLogs(logs);
        }
    }
}

std::string TelemetryPipeline::generateTraceId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 32; ++i) {
        ss << dis(gen);
    }
    return ss.str();
}

std::string TelemetryPipeline::generateSpanId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 16; ++i) {
        ss << dis(gen);
    }
    return ss.str();
}

// OTLPExporter implementation
OTLPExporter::OTLPExporter(const TelemetryExportConfig& config)
    : config_(config)
    , healthy_(true) {
}

bool OTLPExporter::exportEvents(const std::vector<TelemetryEvent>& events) {
    std::string data = serializeEvents(events);
    return sendRequest(data, "/v1/metrics");
}

bool OTLPExporter::exportSpans(const std::vector<TraceSpan>& spans) {
    std::string data = serializeSpans(spans);
    return sendRequest(data, "/v1/traces");
}

bool OTLPExporter::exportLogs(const std::vector<LogEntry>& logs) {
    std::string data = serializeLogs(logs);
    return sendRequest(data, "/v1/logs");
}

bool OTLPExporter::isHealthy() const {
    return healthy_;
}

std::string OTLPExporter::serializeEvents(const std::vector<TelemetryEvent>& events) {
    // Simplified JSON serialization
    std::stringstream ss;
    ss << "{\"resourceMetrics\":[{\"instrumentationLibraryMetrics\":[{\"metrics\":[";
    
    for (size_t i = 0; i < events.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "{\"name\":\"" << events[i].operation << "\"}";
    }
    
    ss << "]}]}]}";
    return ss.str();
}

std::string OTLPExporter::serializeSpans(const std::vector<TraceSpan>& spans) {
    std::stringstream ss;
    ss << "{\"resourceSpans\":[{\"instrumentationLibrarySpans\":[{\"spans\":[";
    
    for (size_t i = 0; i < spans.size(); ++i) {
        if (i > 0) ss << ",";
        const auto& span = spans[i];
        ss << "{";
        ss << "\"traceId\":\"" << span.trace_id << "\",";
        ss << "\"spanId\":\"" << span.span_id << "\",";
        ss << "\"name\":\"" << span.operation_name << "\"";
        ss << "}";
    }
    
    ss << "]}]}]}";
    return ss.str();
}

std::string OTLPExporter::serializeLogs(const std::vector<LogEntry>& logs) {
    std::stringstream ss;
    ss << "{\"resourceLogs\":[{\"instrumentationLibraryLogs\":[{\"logs\":[";
    
    for (size_t i = 0; i < logs.size(); ++i) {
        if (i > 0) ss << ",";
        const auto& log = logs[i];
        ss << "{";
        ss << "\"severityText\":\"" << log.level << "\",";
        ss << "\"body\":{\"stringValue\":\"" << log.message << "\"}";
        ss << "}";
    }
    
    ss << "]}]}]}";
    return ss.str();
}

bool OTLPExporter::sendRequest(const std::string& data, const std::string& path) {
    // Simplified HTTP POST implementation
    // In production, use proper HTTP client library
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    
    std::string url = config_.endpoint + path;
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    for (const auto& [key, value] : config_.headers) {
        std::string header = key + ": " + value;
        headers = curl_slist_append(headers, header.c_str());
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    healthy_ = (res == CURLE_OK);
    return healthy_;
}

// TraceCollector implementation
TraceCollector::TraceCollector() = default;

void TraceCollector::startSpan(const TraceSpan& span) {
    std::lock_guard<std::mutex> lock(mutex_);
    active_spans_[span.span_id] = span;
}

void TraceCollector::finishSpan(const std::string& span_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = active_spans_.find(span_id);
    if (it != active_spans_.end()) {
        it->second.duration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now() - it->second.start_time);
        it->second.finished = true;
        
        finished_spans_.push_back(it->second);
        active_spans_.erase(it);
    }
}

TraceSpan TraceCollector::getSpan(const std::string& span_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = active_spans_.find(span_id);
    if (it != active_spans_.end()) {
        return it->second;
    }
    
    return TraceSpan();
}

std::vector<TraceSpan> TraceCollector::getFinishedSpans() {
    std::lock_guard<std::mutex> lock(mutex_);
    return finished_spans_;
}

void TraceCollector::clearFinishedSpans() {
    std::lock_guard<std::mutex> lock(mutex_);
    finished_spans_.clear();
}

// LogCollector implementation
LogCollector::LogCollector() : max_logs_(10000) {}

void LogCollector::addLog(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (logs_.size() >= max_logs_) {
        logs_.pop();
    }
    
    logs_.push(entry);
}

std::vector<LogEntry> LogCollector::getLogs(size_t max_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<LogEntry> result;
    auto temp_queue = logs_;
    
    while (!temp_queue.empty() && result.size() < max_count) {
        result.push_back(temp_queue.front());
        temp_queue.pop();
    }
    
    return result;
}

void LogCollector::clearLogs() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Clear by swapping with empty queue
    std::queue<LogEntry> empty;
    std::swap(logs_, empty);
}

size_t LogCollector::getLogCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return logs_.size();
}

} // namespace monitoring
} // namespace rawrxd
