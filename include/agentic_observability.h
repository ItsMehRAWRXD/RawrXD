#pragma once

// Non-Qt observability header
// Uses std types instead of Qt types for cross-platform builds

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class AgenticObservability
{
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
        std::string unit;
    };

    struct TraceSpan {
        std::string spanId;
        std::string parentSpanId;
        std::string traceId;
        std::string operation;
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
        json attributes;
        bool hasError = false;
        std::string errorMessage;
        int statusCode = 0;
    };

public:
    AgenticObservability() = default;
    ~AgenticObservability() = default;

    // Structured logging
    void log(LogLevel level, const std::string& component, const std::string& message, const json& context = {});
    void logDebug(const std::string& component, const std::string& message, const json& context = {});
    void logInfo(const std::string& component, const std::string& message, const json& context = {});
    void logWarn(const std::string& component, const std::string& message, const json& context = {});
    void logError(const std::string& component, const std::string& message, const json& context = {});
    void logCritical(const std::string& component, const std::string& message, const json& context = {});

    std::vector<LogEntry> getLogs(int limit = 100, LogLevel minLevel = LogLevel::DEBUG, const std::string& component = "");

    // Metrics
    void recordMetric(const std::string& metricName, float value, const json& labels = {}, const std::string& unit = "");
    void incrementCounter(const std::string& metricName, int delta = 1, const json& labels = {});
    float getCounterValue(const std::string& metricName) const;
    void setGauge(const std::string& metricName, float value, const json& labels = {});
    float getGaugeValue(const std::string& metricName) const;
    void recordHistogram(const std::string& metricName, float value, const json& labels = {});
    json getHistogramStats(const std::string& metricName) const;

    class TimingGuard {
    public:
        TimingGuard(AgenticObservability* obs, const std::string& metricName);
        ~TimingGuard();
    private:
        AgenticObservability* m_obs;
        std::string m_metricName;
        std::chrono::high_resolution_clock::time_point m_start;
    };

    std::unique_ptr<TimingGuard> measureDuration(const std::string& metricName);

    std::vector<MetricPoint> getMetrics(const std::string& pattern = "", int limit = 100);
    json getMetricsSummary() const;

    // Tracing
    std::string startTrace(const std::string& operation);
    std::string startSpan(const std::string& spanName, const std::string& parentSpanId = "");
    void endSpan(const std::string& spanId, bool hasError = false, const std::string& errorMessage = "", int statusCode = 0);
    TraceSpan* getSpan(const std::string& spanId);
    std::vector<TraceSpan> getTraceSpans(const std::string& traceId);

    // Health
    json getSystemHealth() const;
    bool isHealthy() const;
    json getPerformanceSummary() const;

    // Config
    void setLogLevel(LogLevel level) { m_minLogLevel = level; }
    void setMaxLogEntries(int max) { m_maxLogEntries = max; }
    void setTracingEnabled(bool enabled) { m_tracingEnabled = enabled; }

private:
    std::string generateTraceId();
    std::string generateSpanId();
    std::string levelToString(LogLevel level) const;
    void checkAndRotateLogs();

    std::vector<LogEntry> m_logs;
    std::vector<MetricPoint> m_metrics;
    std::unordered_map<std::string, TraceSpan> m_spans;
    std::unordered_map<std::string, std::vector<std::string>> m_traceSpans;

    LogLevel m_minLogLevel = LogLevel::DEBUG;
    int m_maxLogEntries = 10000;
    bool m_tracingEnabled = true;
    float m_samplingRate = 1.0f;
    
    std::chrono::system_clock::time_point m_systemStartTime;
    int m_totalLogsWritten = 0;
    int m_totalMetricsRecorded = 0;
    std::unordered_map<std::string, int> m_errorCounts;
};
