// AgenticObservability Implementation
#include "agentic_observability.h"
#include <iostream>
#include <fstream>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace {

std::string generateUuid() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint16_t> dist(0, 0xffff);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) ss << dist(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << dist(gen);
    ss << "-";
    ss << "4";
    for (int i = 0; i < 3; ++i) ss << dist(gen) & 0x0fff;
    ss << "-";
    ss << (dist(gen) & 0x3fff | 0x8000);
    for (int i = 0; i < 3; ++i) ss << dist(gen);
    ss << "-";
    for (int i = 0; i < 6; ++i) ss << dist(gen);
    return ss.str();
}

std::string nowIsoString() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

} // namespace

AgenticObservability::AgenticObservability() {
    std::clog << "[AgenticObservability] Initialized - Observability system ready" << std::endl;
}

AgenticObservability::~AgenticObservability() {
    std::clog << "[AgenticObservability] Destroyed" << std::endl;
}

// ===== LOGGING =====

void AgenticObservability::log(LogLevel level, const std::string& component, const std::string& message, const json& context) {
    if (static_cast<int>(level) < static_cast<int>(m_minLogLevel)) return;

    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.component = component;
    entry.message = message;
    entry.context = context;
    entry.traceId = generateTraceId();
    entry.spanId = generateSpanId();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_logHistory.push_back(entry);

    writeLog(entry);

    if (m_onLogEntry) m_onLogEntry(entry);
}

void AgenticObservability::logDebug(const std::string& component, const std::string& message, const json& context) {
    log(LogLevel::DEBUG, component, message, context);
}

void AgenticObservability::logInfo(const std::string& component, const std::string& message, const json& context) {
    log(LogLevel::INFO, component, message, context);
}

void AgenticObservability::logWarn(const std::string& component, const std::string& message, const json& context) {
    log(LogLevel::WARN, component, message, context);
}

void AgenticObservability::logError(const std::string& component, const std::string& message, const json& context) {
    log(LogLevel::ERROR, component, message, context);
}

void AgenticObservability::logCritical(const std::string& component, const std::string& message, const json& context) {
    log(LogLevel::CRITICAL, component, message, context);
}

const std::vector<AgenticObservability::LogEntry>& AgenticObservability::getLogHistory(size_t limit) const {
    return m_logHistory;
}

void AgenticObservability::writeLog(const LogEntry& entry) {
    std::string levelStr = logLevelToString(entry.level);
    auto t = std::chrono::system_clock::to_time_t(entry.timestamp);
    std::stringstream timeSs;
    timeSs << std::put_time(std::gmtime(&t), "%H:%M:%S");

    std::stringstream ss;
    ss << "[" << timeSs.str() << "] [" << levelStr << "] [" << entry.component << "] " << entry.message;

    if (m_logToStdout) {
        if (entry.level >= LogLevel::ERROR) {
            std::cerr << ss.str() << std::endl;
        } else {
            std::clog << ss.str() << std::endl;
        }
    }

    if (m_logToFile && !m_logFilePath.empty()) {
        std::ofstream file(m_logFilePath, std::ios::app);
        if (file.is_open()) {
            file << ss.str() << "\n";
            file.close();
        }
    }
}

// ===== METRICS =====

void AgenticObservability::incrementCounter(const std::string& metricName, const json& labels) {
    MetricPoint point;
    point.metricName = metricName;
    point.value = 1.0f;
    point.labels = labels;
    point.timestamp = std::chrono::system_clock::now();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_metrics[metricName].push_back(point);

    if (m_onMetricRecorded) m_onMetricRecorded(point);
}

void AgenticObservability::recordGauge(const std::string& metricName, float value, const json& labels) {
    MetricPoint point;
    point.metricName = metricName;
    point.value = value;
    point.labels = labels;
    point.timestamp = std::chrono::system_clock::now();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_metrics[metricName].push_back(point);

    if (m_onMetricRecorded) m_onMetricRecorded(point);
}

void AgenticObservability::recordHistogram(const std::string& metricName, float value, const json& labels) {
    MetricPoint point;
    point.metricName = metricName;
    point.value = value;
    point.labels = labels;
    point.timestamp = std::chrono::system_clock::now();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_metrics[metricName].push_back(point);

    if (m_onMetricRecorded) m_onMetricRecorded(point);
}

json AgenticObservability::getMetrics(const std::string& metricName) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!metricName.empty()) {
        auto it = m_metrics.find(metricName);
        if (it != m_metrics.end()) {
            json result = json::array();
            for (const auto& p : it->second) {
                json entry;
                entry["value"] = p.value;
                entry["timestamp"] = nowIsoString();
                entry["labels"] = p.labels;
                result.push_back(entry);
            }
            return result;
        }
        return json::array();
    }

    json result = json::object();
    for (const auto& pair : m_metrics) {
        json values = json::array();
        for (const auto& p : pair.second) {
            json entry;
            entry["value"] = p.value;
            entry["timestamp"] = nowIsoString();
            entry["labels"] = p.labels;
            values.push_back(entry);
        }
        result[pair.first] = values;
    }
    return result;
}

// ===== TRACING =====

std::string AgenticObservability::startSpan(const std::string& operationName, const std::string& parentSpanId) {
    Span span;
    span.spanId = generateSpanId();
    span.traceId = parentSpanId.empty() ? generateTraceId() : parentSpanId;
    span.parentSpanId = parentSpanId;
    span.operationName = operationName;
    span.startTime = std::chrono::system_clock::now();
    span.completed = false;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_spans[span.spanId] = span;
    m_traces[span.traceId].push_back(span);

    return span.spanId;
}

void AgenticObservability::endSpan(const std::string& spanId) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_spans.find(spanId);
    if (it != m_spans.end()) {
        it->second.endTime = std::chrono::system_clock::now();
        it->second.completed = true;

        if (m_onSpanCompleted) m_onSpanCompleted(it->second);
    }
}

json AgenticObservability::getTrace(const std::string& traceId) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_traces.find(traceId);
    if (it != m_traces.end()) {
        json result = json::array();
        for (const auto& span : it->second) {
            json entry;
            entry["span_id"] = span.spanId;
            entry["trace_id"] = span.traceId;
            entry["parent_span_id"] = span.parentSpanId;
            entry["operation_name"] = span.operationName;
            entry["completed"] = span.completed;
            result.push_back(entry);
        }
        return result;
    }
    return json::array();
}

// ===== CONFIGURATION =====

void AgenticObservability::setMinLogLevel(LogLevel level) {
    m_minLogLevel = level;
}

void AgenticObservability::setLogOutput(bool toStdout, bool toFile) {
    m_logToStdout = toStdout;
    m_logToFile = toFile;
}

void AgenticObservability::setLogFile(const std::string& filePath) {
    m_logFilePath = filePath;
}

// ===== PRIVATE HELPERS =====

std::string AgenticObservability::generateTraceId() {
    return generateUuid();
}

std::string AgenticObservability::generateSpanId() {
    return generateUuid().substr(0, 16);
}

std::string AgenticObservability::logLevelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}
