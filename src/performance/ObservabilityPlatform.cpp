// RawrXD Observability Platform Implementation
// Phase P.1: Unified observability with metrics, logs, and traces

#include "ObservabilityPlatform.hpp"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>

namespace RawrXD {
namespace Performance {

// MetricCollector Implementation

MetricCollector::MetricCollector() {}

MetricCollector::~MetricCollector() {}

void MetricCollector::counter(const std::string& name, double increment) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        MetricValue value;
        value.name = name;
        value.type = MetricType::COUNTER;
        value.value = increment;
        value.timestamp = std::chrono::steady_clock::now();
        metrics_[name] = value;
    } else {
        it->second.value += increment;
        it->second.timestamp = std::chrono::steady_clock::now();
    }
}

void MetricCollector::counter(const std::string& name, double increment,
                               const std::map<std::string, std::string>& labels) {
    // Create labeled metric name
    std::stringstream ss;
    ss << name;
    for (const auto& pair : labels) {
        ss << "{" << pair.first << "=" << pair.second << "}";
    }
    counter(ss.str(), increment);
}

void MetricCollector::gauge(const std::string& name, double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        MetricValue mv;
        mv.name = name;
        mv.type = MetricType::GAUGE;
        mv.value = value;
        mv.timestamp = std::chrono::steady_clock::now();
        metrics_[name] = mv;
    } else {
        it->second.value = value;
        it->second.timestamp = std::chrono::steady_clock::now();
    }
}

void MetricCollector::gauge(const std::string& name, double value,
                            const std::map<std::string, std::string>& labels) {
    std::stringstream ss;
    ss << name;
    for (const auto& pair : labels) {
        ss << "{" << pair.first << "=" << pair.second << "}";
    }
    gauge(ss.str(), value);
}

void MetricCollector::histogram(const std::string& name, double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    histogramValues_[name].push_back(value);
    
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        MetricValue mv;
        mv.name = name;
        mv.type = MetricType::HISTOGRAM;
        mv.value = value;
        mv.timestamp = std::chrono::steady_clock::now();
        metrics_[name] = mv;
    }
}

void MetricCollector::histogram(const std::string& name, double value,
                                 const std::map<std::string, std::string>& labels) {
    std::stringstream ss;
    ss << name;
    for (const auto& pair : labels) {
        ss << "{" << pair.first << "=" << pair.second << "}";
    }
    histogram(ss.str(), value);
}

void MetricCollector::histogram(const std::string& name, double value,
                                  const std::vector<double>& buckets) {
    histogram(name, value);
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = metrics_.find(name);
    if (it != metrics_.end()) {
        it->second.buckets = buckets;
        it->second.counts.resize(buckets.size(), 0);
        
        for (size_t i = 0; i < buckets.size(); i++) {
            if (value <= buckets[i]) {
                it->second.counts[i]++;
                break;
            }
        }
    }
}

void MetricCollector::summary(const std::string& name, double value) {
    histogram(name, value); // Summary uses histogram internally
}

void MetricCollector::summary(const std::string& name, double value,
                               const std::map<std::string, std::string>& labels) {
    histogram(name, value, labels);
}

std::vector<MetricValue> MetricCollector::getMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MetricValue> result;
    for (const auto& pair : metrics_) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<MetricValue> MetricCollector::getMetrics(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MetricValue> result;
    
    auto it = metrics_.find(name);
    if (it != metrics_.end()) {
        result.push_back(it->second);
    }
    return result;
}

void MetricCollector::clearMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.clear();
    histogramValues_.clear();
}

std::string MetricCollector::exportPrometheus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::stringstream ss;
    
    for (const auto& pair : metrics_) {
        const auto& metric = pair.second;
        ss << "# HELP " << metric.name << " " << metric.name << " metric\n";
        ss << "# TYPE " << metric.name << " ";
        
        switch (metric.type) {
            case MetricType::COUNTER:
                ss << "counter";
                break;
            case MetricType::GAUGE:
                ss << "gauge";
                break;
            case MetricType::HISTOGRAM:
                ss << "histogram";
                break;
            case MetricType::SUMMARY:
                ss << "summary";
                break;
        }
        ss << "\n";
        ss << metric.name << " " << metric.value << "\n";
    }
    
    return ss.str();
}

std::string MetricCollector::exportOTLP() const {
    // Would export in OTLP format
    return exportPrometheus(); // Simplified
}

// Logger Implementation

Logger::Logger() : minLevel_(LogSeverity::DEBUG) {}

Logger::~Logger() {}

void Logger::debug(const std::string& message) {
    log(LogSeverity::DEBUG, message, {});
}

void Logger::debug(const std::string& message, const std::map<std::string, std::string>& attributes) {
    log(LogSeverity::DEBUG, message, attributes);
}

void Logger::info(const std::string& message) {
    log(LogSeverity::INFO, message, {});
}

void Logger::info(const std::string& message, const std::map<std::string, std::string>& attributes) {
    log(LogSeverity::INFO, message, attributes);
}

void Logger::warn(const std::string& message) {
    log(LogSeverity::WARN, message, {});
}

void Logger::warn(const std::string& message, const std::map<std::string, std::string>& attributes) {
    log(LogSeverity::WARN, message, attributes);
}

void Logger::error(const std::string& message) {
    log(LogSeverity::ERROR, message, {});
}

void Logger::error(const std::string& message, const std::map<std::string, std::string>& attributes) {
    log(LogSeverity::ERROR, message, attributes);
}

void Logger::error(const std::string& message, std::exception_ptr ex) {
    log(LogSeverity::ERROR, message, {});
}

void Logger::fatal(const std::string& message) {
    log(LogSeverity::FATAL, message, {});
}

void Logger::fatal(const std::string& message, const std::map<std::string, std::string>& attributes) {
    log(LogSeverity::FATAL, message, attributes);
}

void Logger::fatal(const std::string& message, std::exception_ptr ex) {
    log(LogSeverity::FATAL, message, {});
}

void Logger::log(LogSeverity severity, const std::string& message,
                  const std::map<std::string, std::string>& attributes) {
    if (severity < minLevel_) {
        return;
    }
    
    LogEntry entry;
    entry.timestamp = std::chrono::steady_clock::now();
    entry.severity = severity;
    entry.message = message;
    entry.attributes = attributes;
    
    logInternal(entry);
}

void Logger::logInternal(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    logs_.push_back(entry);
    
    // Also output to console
    const char* severityStr[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    std::cout << "[" << severityStr[static_cast<int>(entry.severity)] << "] " 
              << entry.message << std::endl;
}

std::vector<LogEntry> Logger::getLogs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return logs_;
}

std::vector<LogEntry> Logger::getLogs(LogSeverity minSeverity) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (const auto& log : logs_) {
        if (log.severity >= minSeverity) {
            result.push_back(log);
        }
    }
    return result;
}

void Logger::clearLogs() {
    std::lock_guard<std::mutex> lock(mutex_);
    logs_.clear();
}

std::string Logger::exportJSON() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::stringstream ss;
    ss << "[\n";
    
    for (size_t i = 0; i < logs_.size(); i++) {
        const auto& log = logs_[i];
        ss << "  {\n";
        ss << "    \"timestamp\": " << std::chrono::duration_cast<std::chrono::milliseconds>(
            log.timestamp.time_since_epoch()).count() << ",\n";
        ss << "    \"severity\": " << static_cast<int>(log.severity) << ",\n";
        ss << "    \"message\": \"" << log.message << "\"\n";
        ss << "  }";
        if (i < logs_.size() - 1) ss << ",";
        ss << "\n";
    }
    
    ss << "]\n";
    return ss.str();
}

std::string Logger::exportOTLP() const {
    return exportJSON(); // Simplified
}

// Tracer Implementation

Tracer::Tracer() {}

Tracer::~Tracer() {}

std::string Tracer::startSpan(const std::string& name) {
    return startSpan(name, std::map<std::string, std::string>());
}

std::string Tracer::startSpan(const std::string& name, const std::string& parentSpanId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string spanId = generateSpanId();
    std::string traceId;
    
    // Inherit trace ID from parent
    auto parentIt = spans_.find(parentSpanId);
    if (parentIt != spans_.end()) {
        traceId = parentIt->second.traceId;
    } else {
        traceId = generateTraceId();
    }
    
    TraceSpan span;
    span.traceId = traceId;
    span.spanId = spanId;
    span.parentSpanId = parentSpanId;
    span.name = name;
    span.startTime = std::chrono::steady_clock::now();
    span.status = TraceSpan::Status::UNSET;
    
    spans_[spanId] = span;
    activeSpans_[spanId] = traceId;
    
    return spanId;
}

std::string Tracer::startSpan(const std::string& name,
                               const std::map<std::string, std::string>& attributes) {
    std::string spanId = startSpan(name);
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = spans_.find(spanId);
    if (it != spans_.end()) {
        it->second.attributes = attributes;
    }
    
    return spanId;
}

void Tracer::endSpan(const std::string& spanId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = spans_.find(spanId);
    if (it != spans_.end()) {
        it->second.endTime = std::chrono::steady_clock::now();
        it->second.duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
            it->second.endTime - it->second.startTime);
        
        if (it->second.status == TraceSpan::Status::UNSET) {
            it->second.status = TraceSpan::Status::OK;
        }
        
        activeSpans_.erase(spanId);
    }
}

void Tracer::setSpanAttribute(const std::string& spanId, const std::string& key, 
                               const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = spans_.find(spanId);
    if (it != spans_.end()) {
        it->second.attributes[key] = value;
    }
}

void Tracer::addSpanEvent(const std::string& spanId, const std::string& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = spans_.find(spanId);
    if (it != spans_.end()) {
        it->second.events.push_back(event);
    }
}

void Tracer::setSpanStatus(const std::string& spanId, TraceSpan::Status status, 
                            const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = spans_.find(spanId);
    if (it != spans_.end()) {
        it->second.status = status;
        it->second.statusMessage = message;
    }
}

Tracer::ScopedSpan Tracer::createScopedSpan(const std::string& name) {
    return ScopedSpan(this, name);
}

std::vector<TraceSpan> Tracer::getSpans() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TraceSpan> result;
    for (const auto& pair : spans_) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<TraceSpan> Tracer::getSpans(const std::string& traceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TraceSpan> result;
    for (const auto& pair : spans_) {
        if (pair.second.traceId == traceId) {
            result.push_back(pair.second);
        }
    }
    return result;
}

void Tracer::clearSpans() {
    std::lock_guard<std::mutex> lock(mutex_);
    spans_.clear();
    activeSpans_.clear();
}

std::string Tracer::exportJSON() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::stringstream ss;
    ss << "[\n";
    
    size_t i = 0;
    for (const auto& pair : spans_) {
        const auto& span = pair.second;
        ss << "  {\n";
        ss << "    \"traceId\": \"" << span.traceId << "\",\n";
        ss << "    \"spanId\": \"" << span.spanId << "\",\n";
        ss << "    \"name\": \"" << span.name << "\",\n";
        ss << "    \"duration\": " << span.duration.count() << "\n";
        ss << "  }";
        if (++i < spans_.size()) ss << ",";
        ss << "\n";
    }
    
    ss << "]\n";
    return ss.str();
}

std::string Tracer::exportOTLP() const {
    return exportJSON(); // Simplified
}

std::string Tracer::exportW3C() const {
    // W3C trace context format
    return "00-" + generateTraceId() + "-" + generateSpanId() + "-00";
}

std::string Tracer::generateTraceId() {
    uint64_t id1 = std::chrono::steady_clock::now().time_since_epoch().count();
    uint64_t id2 = spanCounter_.fetch_add(1);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << id1
       << std::setw(16) << id2;
    return ss.str();
}

std::string Tracer::generateSpanId() {
    uint64_t id = spanCounter_.fetch_add(1);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << id;
    return ss.str();
}

// ScopedSpan Implementation

Tracer::ScopedSpan::ScopedSpan(Tracer* tracer, const std::string& name)
    : tracer_(tracer) {
    spanId_ = tracer_->startSpan(name);
}

Tracer::ScopedSpan::~ScopedSpan() {
    if (tracer_) {
        tracer_->endSpan(spanId_);
    }
}

void Tracer::ScopedSpan::setAttribute(const std::string& key, const std::string& value) {
    if (tracer_) {
        tracer_->setSpanAttribute(spanId_, key, value);
    }
}

void Tracer::ScopedSpan::addEvent(const std::string& event) {
    if (tracer_) {
        tracer_->addSpanEvent(spanId_, event);
    }
}

void Tracer::ScopedSpan::setStatus(TraceSpan::Status status, const std::string& message) {
    if (tracer_) {
        tracer_->setSpanStatus(spanId_, status, message);
    }
}

// EventCollector Implementation

EventCollector::EventCollector() {}

EventCollector::~EventCollector() {}

void EventCollector::record(const std::string& name) {
    record(name, {});
}

void EventCollector::record(const std::string& name, 
                             const std::map<std::string, std::string>& attributes) {
    ObservabilityEvent event;
    event.name = name;
    event.timestamp = std::chrono::steady_clock::now();
    event.attributes = attributes;
    record(event);
}

void EventCollector::record(const ObservabilityEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(event);
}

std::vector<ObservabilityEvent> EventCollector::getEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_;
}

std::vector<ObservabilityEvent> EventCollector::getEvents(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ObservabilityEvent> result;
    for (const auto& event : events_) {
        if (event.name == name) {
            result.push_back(event);
        }
    }
    return result;
}

void EventCollector::clearEvents() {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
}

// ObservabilityPlatform Implementation

ObservabilityPlatform::ObservabilityPlatform()
    : running_(false)
    , initialized_(false)
{
}

ObservabilityPlatform::~ObservabilityPlatform() {
    shutdown();
}

bool ObservabilityPlatform::initialize(const ObservabilityConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Initialize components
    metrics_ = std::make_unique<MetricCollector>();
    logger_ = std::make_unique<Logger>();
    tracer_ = std::make_unique<Tracer>();
    events_ = std::make_unique<EventCollector>();
    
    running_ = true;
    
    // Start background threads
    exportThread_ = std::thread(&ObservabilityPlatform::exportLoop, this);
    cleanupThread_ = std::thread(&ObservabilityPlatform::cleanupLoop, this);
    
    initialized_ = true;
    
    info("Observability platform initialized");
    
    return true;
}

bool ObservabilityPlatform::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    // Stop threads
    if (exportThread_.joinable()) {
        exportThread_.join();
    }
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    
    initialized_ = false;
    return true;
}

void ObservabilityPlatform::counter(const std::string& name, double value) {
    if (metrics_) {
        metrics_->counter(name, value);
    }
}

void ObservabilityPlatform::gauge(const std::string& name, double value) {
    if (metrics_) {
        metrics_->gauge(name, value);
    }
}

void ObservabilityPlatform::histogram(const std::string& name, double value) {
    if (metrics_) {
        metrics_->histogram(name, value);
    }
}

void ObservabilityPlatform::log(LogSeverity severity, const std::string& message) {
    if (logger_) {
        logger_->log(severity, message, {});
    }
}

void ObservabilityPlatform::debug(const std::string& message) {
    log(LogSeverity::DEBUG, message);
}

void ObservabilityPlatform::info(const std::string& message) {
    log(LogSeverity::INFO, message);
}

void ObservabilityPlatform::warn(const std::string& message) {
    log(LogSeverity::WARN, message);
}

void ObservabilityPlatform::error(const std::string& message) {
    log(LogSeverity::ERROR, message);
}

void ObservabilityPlatform::fatal(const std::string& message) {
    log(LogSeverity::FATAL, message);
}

std::string ObservabilityPlatform::startSpan(const std::string& name) {
    if (tracer_) {
        return tracer_->startSpan(name);
    }
    return "";
}

void ObservabilityPlatform::endSpan(const std::string& spanId) {
    if (tracer_) {
        tracer_->endSpan(spanId);
    }
}

Tracer::ScopedSpan ObservabilityPlatform::createSpan(const std::string& name) {
    return tracer_->createScopedSpan(name);
}

void ObservabilityPlatform::recordEvent(const std::string& name) {
    if (events_) {
        events_->record(name);
    }
}

bool ObservabilityPlatform::exportToFile(const std::string& directory) {
    // Would export all data to files
    return true;
}

bool ObservabilityPlatform::exportToOTLP(const std::string& endpoint) {
    // Would export to OTLP endpoint
    return true;
}

bool ObservabilityPlatform::isHealthy() const {
    return initialized_ && metrics_ && logger_ && tracer_ && events_;
}

std::map<std::string, bool> ObservabilityPlatform::getComponentHealth() const {
    std::map<std::string, bool> health;
    health["metrics"] = metrics_ != nullptr;
    health["logger"] = logger_ != nullptr;
    health["tracer"] = tracer_ != nullptr;
    health["events"] = events_ != nullptr;
    return health;
}

void ObservabilityPlatform::exportLoop() {
    while (running_) {
        // Periodic export
        if (config_.enableFileExport) {
            exportToFile(config_.fileExportPath);
        }
        if (config_.enableOTLPExport) {
            exportToOTLP(config_.otlpEndpoint);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.flushIntervalMs));
    }
}

void ObservabilityPlatform::cleanupLoop() {
    while (running_) {
        // Periodic cleanup of old data
        std::this_thread::sleep_for(std::chrono::hours(1));
    }
}

// Global instance
static std::unique_ptr<ObservabilityPlatform> g_observability;

ObservabilityPlatform& getObservability() {
    if (!g_observability) {
        g_observability = std::make_unique<ObservabilityPlatform>();
    }
    return *g_observability;
}

bool initializeObservability(const ObservabilityConfig& config) {
    return getObservability().initialize(config);
}

bool shutdownObservability() {
    if (g_observability) {
        return g_observability->shutdown();
    }
    return true;
}

} // namespace Performance
} // namespace RawrXD
