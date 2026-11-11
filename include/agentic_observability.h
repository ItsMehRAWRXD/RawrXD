#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * @class AgenticObservability
 * @brief Comprehensive observability for agentic systems
 * 
 * Three pillars of observability:
 * 1. STRUCTURED LOGGING: Detailed context at key points
 * 2. METRICS: Quantifiable measurements for performance tracking
 * 3. DISTRIBUTED TRACING: Request flow visualization across components
 * 
 * Enables production monitoring, debugging, and performance optimization.
 */
class AgenticObservability {
public:
    enum class LogLevel {
        DEBUG = 0,
        INFO = 1,
        WARN = 2,
        ERROR = 3,
        CRITICAL = 4
    };

    struct LogEntry {
        std::chrono::system_clock::time_point timestamp;
        LogLevel level;
        std::string component;
        std::string message;
        json context;
        std::string traceId;
        std::string spanId;
    };

    struct MetricPoint {
        std::string metricName;
        float value;
        json labels;
        std::chrono::system_clock::time_point timestamp;
    };

    struct Span {
        std::string spanId;
        std::string traceId;
        std::string parentSpanId;
        std::string operationName;
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
        bool completed;
    };

public:
    AgenticObservability();
    ~AgenticObservability();

    // ===== LOGGING =====
    void logDebug(const std::string& component, const std::string& message, const json& context = json::object());
    void logInfo(const std::string& component, const std::string& message, const json& context = json::object());
    void logWarn(const std::string& component, const std::string& message, const json& context = json::object());
    void logError(const std::string& component, const std::string& message, const json& context = json::object());
    void logCritical(const std::string& component, const std::string& message, const json& context = json::object());

    void log(LogLevel level, const std::string& component, const std::string& message, const json& context = json::object());
    const std::vector<LogEntry>& getLogHistory(size_t limit = 100) const;

    // ===== METRICS =====
    void incrementCounter(const std::string& metricName, const json& labels = json::object());
    void recordGauge(const std::string& metricName, float value, const json& labels = json::object());
    void recordHistogram(const std::string& metricName, float value, const json& labels = json::object());
    json getMetrics(const std::string& metricName = "") const;

    // ===== TRACING =====
    std::string startSpan(const std::string& operationName, const std::string& parentSpanId = "");
    void endSpan(const std::string& spanId);
    json getTrace(const std::string& traceId) const;

    // ===== CONFIGURATION =====
    void setMinLogLevel(LogLevel level);
    void setLogOutput(bool toStdout, bool toFile);
    void setLogFile(const std::string& filePath);

    // Callbacks (replaces Qt signals)
    using LogEntryCallback = std::function<void(const LogEntry&)>;
    using MetricRecordedCallback = std::function<void(const MetricPoint&)>;
    using SpanCompletedCallback = std::function<void(const Span&)>;
    
    void setOnLogEntry(LogEntryCallback cb) { m_onLogEntry = cb; }
    void setOnMetricRecorded(MetricRecordedCallback cb) { m_onMetricRecorded = cb; }
    void setOnSpanCompleted(SpanCompletedCallback cb) { m_onSpanCompleted = cb; }

private:
    // Internal helpers
    std::string generateTraceId();
    std::string generateSpanId();
    std::string logLevelToString(LogLevel level) const;
    void writeLog(const LogEntry& entry);

    // State
    std::vector<LogEntry> m_logHistory;
    std::unordered_map<std::string, std::vector<MetricPoint>> m_metrics;
    std::unordered_map<std::string, Span> m_spans;
    std::unordered_map<std::string, std::vector<Span>> m_traces;
    
    LogLevel m_minLogLevel = LogLevel::INFO;
    bool m_logToStdout = true;
    bool m_logToFile = false;
    std::string m_logFilePath;
    
    std::mutex m_mutex;

    // Callbacks
    LogEntryCallback m_onLogEntry;
    MetricRecordedCallback m_onMetricRecorded;
    SpanCompletedCallback m_onSpanCompleted;
};
