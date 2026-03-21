// AgenticObservability Implementation
#include "agentic_observability.h"

#include <algorithm>
#include <cmath>
#include <random>
#include <sstream>
#include <iomanip>

// ===== STRUCTURED LOGGING =====

void AgenticObservability::log(
    LogLevel level,
    const std::string& component,
    const std::string& message,
    const json& context)
{
    if (level < m_minLogLevel) {
        return;
    }

    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.component = component;
    entry.message = message;
    entry.context = context;
    entry.traceId = generateTraceId();
    entry.spanId = generateSpanId();

    m_logs.push_back(entry);
    m_totalLogsWritten++;

    checkAndRotateLogs();
}

void AgenticObservability::logDebug(
    const std::string& component,
    const std::string& message,
    const json& context)
{
    log(LogLevel::DEBUG, component, message, context);
}

void AgenticObservability::logInfo(
    const std::string& component,
    const std::string& message,
    const json& context)
{
    log(LogLevel::INFO, component, message, context);
}

void AgenticObservability::logWarn(
    const std::string& component,
    const std::string& message,
    const json& context)
{
    log(LogLevel::WARN, component, message, context);
}

void AgenticObservability::logError(
    const std::string& component,
    const std::string& message,
    const json& context)
{
    log(LogLevel::ERROR, component, message, context);
    m_errorCounts[component]++;
}

void AgenticObservability::logCritical(
    const std::string& component,
    const std::string& message,
    const json& context)
{
    log(LogLevel::CRITICAL, component, message, context);
    m_errorCounts[component]++;
}

std::vector<AgenticObservability::LogEntry> AgenticObservability::getLogs(
    int limit,
    LogLevel minLevel,
    const std::string& component)
{
    std::vector<LogEntry> filtered;

    for (const auto& entry : m_logs) {
        if (entry.level < minLevel) continue;
        if (!component.empty() && entry.component != component) continue;
        filtered.push_back(entry);
    }

    if (limit > 0 && static_cast<int>(filtered.size()) > limit) {
        filtered.erase(filtered.begin(), filtered.end() - limit);
    }

    return filtered;
}

// ===== METRICS =====

void AgenticObservability::recordMetric(
    const std::string& metricName,
    float value,
    const json& labels,
    const std::string& unit)
{
    MetricPoint point;
    point.metricName = metricName;
    point.value = value;
    point.labels = labels;
    point.timestamp = std::chrono::system_clock::now();
    point.unit = unit;

    m_metrics.push_back(point);
    m_totalMetricsRecorded++;
}

void AgenticObservability::incrementCounter(
    const std::string& metricName,
    int delta,
    const json& labels)
{
    recordMetric(metricName, static_cast<float>(delta), labels, "count");
}

float AgenticObservability::getCounterValue(const std::string& metricName) const
{
    float sum = 0.0f;
    for (const auto& metric : m_metrics) {
        if (metric.metricName == metricName) {
            sum += metric.value;
        }
    }
    return sum;
}

void AgenticObservability::setGauge(
    const std::string& metricName,
    float value,
    const json& labels)
{
    recordMetric(metricName, value, labels, "gauge");
}

float AgenticObservability::getGaugeValue(const std::string& metricName) const
{
    for (auto it = m_metrics.rbegin(); it != m_metrics.rend(); ++it) {
        if (it->metricName == metricName) {
            return it->value;
        }
    }
    return 0.0f;
}

void AgenticObservability::recordHistogram(
    const std::string& metricName,
    float value,
    const json& labels)
{
    recordMetric(metricName + "_histogram", value, labels, "histogram");
}

json AgenticObservability::getHistogramStats(const std::string& metricName) const
{
    std::vector<float> values;

    for (const auto& metric : m_metrics) {
        if (metric.metricName == metricName + "_histogram") {
            values.push_back(metric.value);
        }
    }

    json stats;

    if (values.empty()) {
        stats["count"] = 0;
        return stats;
    }

    std::sort(values.begin(), values.end());

    float sum = 0.0f;
    for (float v : values) sum += v;

    float mean = sum / static_cast<float>(values.size());

    stats["count"] = static_cast<int>(values.size());
    stats["min"] = values.front();
    stats["max"] = values.back();
    stats["mean"] = mean;
    stats["median"] = values[values.size() / 2];

    float variance = 0.0f;
    for (float v : values) {
        variance += (v - mean) * (v - mean);
    }
    stats["stddev"] = std::sqrt(variance / static_cast<float>(values.size()));

    return stats;
}

AgenticObservability::TimingGuard::TimingGuard(
    AgenticObservability* obs,
    const std::string& metricName)
    : m_obs(obs), m_metricName(metricName),
      m_start(std::chrono::high_resolution_clock::now())
{
}

AgenticObservability::TimingGuard::~TimingGuard()
{
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - m_start);

    if (m_obs) {
        m_obs->recordMetric(m_metricName + "_duration",
                            static_cast<float>(duration.count()), {}, "ms");
    }
}

std::unique_ptr<AgenticObservability::TimingGuard> AgenticObservability::measureDuration(
    const std::string& metricName)
{
    return std::make_unique<TimingGuard>(this, metricName);
}

std::vector<AgenticObservability::MetricPoint> AgenticObservability::getMetrics(
    const std::string& pattern,
    int limit)
{
    std::vector<MetricPoint> filtered;

    for (const auto& metric : m_metrics) {
        if (!pattern.empty() &&
            metric.metricName.find(pattern) == std::string::npos) {
            continue;
        }
        filtered.push_back(metric);
    }

    if (limit > 0 && static_cast<int>(filtered.size()) > limit) {
        filtered.erase(filtered.begin(), filtered.end() - limit);
    }

    return filtered;
}

json AgenticObservability::getMetricsSummary() const
{
    json summary;

    std::unordered_map<std::string, std::vector<float>> metricGroups;
    for (const auto& metric : m_metrics) {
        metricGroups[metric.metricName].push_back(metric.value);
    }

    json metrics;
    for (const auto& [name, vals] : metricGroups) {
        float sum = 0.0f;
        for (float v : vals) sum += v;

        json metricInfo;
        metricInfo["count"] = static_cast<int>(vals.size());
        metricInfo["latest"] = vals.back();
        metricInfo["avg"] = sum / static_cast<float>(vals.size());

        metrics[name] = metricInfo;
    }

    summary["metrics"] = metrics;
    summary["total_recorded"] = m_totalMetricsRecorded;

    return summary;
}

// ===== DISTRIBUTED TRACING =====

std::string AgenticObservability::startTrace(const std::string& operation)
{
    if (!m_tracingEnabled) return "";

    std::string traceId = generateTraceId();
    m_traceSpans[traceId] = {};

    // Create a root span for the trace
    TraceSpan rootSpan;
    rootSpan.spanId = generateSpanId();
    rootSpan.traceId = traceId;
    rootSpan.operation = operation;
    rootSpan.startTime = std::chrono::system_clock::now();
    rootSpan.hasError = false;
    rootSpan.statusCode = 0;

    m_spans[rootSpan.spanId] = rootSpan;
    m_traceSpans[traceId].push_back(rootSpan.spanId);

    return traceId;
}

std::string AgenticObservability::startSpan(const std::string& spanName, const std::string& parentSpanId)
{
    if (!m_tracingEnabled) return "";

    std::string spanId = generateSpanId();

    TraceSpan span;
    span.spanId = spanId;
    span.parentSpanId = parentSpanId;
    span.operation = spanName;
    span.startTime = std::chrono::system_clock::now();
    span.hasError = false;
    span.statusCode = 0;

    // Inherit traceId from parent if available
    if (!parentSpanId.empty()) {
        auto parentIt = m_spans.find(parentSpanId);
        if (parentIt != m_spans.end()) {
            span.traceId = parentIt->second.traceId;
            m_traceSpans[span.traceId].push_back(spanId);
        }
    }

    m_spans[spanId] = span;

    return spanId;
}

void AgenticObservability::endSpan(
    const std::string& spanId,
    bool hasError,
    const std::string& errorMessage,
    int statusCode)
{
    auto it = m_spans.find(spanId);
    if (it != m_spans.end()) {
        it->second.endTime = std::chrono::system_clock::now();
        it->second.hasError = hasError;
        it->second.errorMessage = errorMessage;
        it->second.statusCode = statusCode;
    }
}

AgenticObservability::TraceSpan* AgenticObservability::getSpan(const std::string& spanId)
{
    auto it = m_spans.find(spanId);
    if (it != m_spans.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<AgenticObservability::TraceSpan> AgenticObservability::getTraceSpans(
    const std::string& traceId)
{
    std::vector<TraceSpan> spans;

    auto it = m_traceSpans.find(traceId);
    if (it != m_traceSpans.end()) {
        for (const auto& spanId : it->second) {
            auto spanIt = m_spans.find(spanId);
            if (spanIt != m_spans.end()) {
                spans.push_back(spanIt->second);
            }
        }
    }

    return spans;
}

// ===== DIAGNOSTICS =====

json AgenticObservability::getSystemHealth() const
{
    json health;

    int errorCount = 0;
    for (const auto& [component, count] : m_errorCounts) {
        errorCount += count;
    }

    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_systemStartTime);
    float uptime = static_cast<float>(elapsed.count()) / 1000.0f;

    health["uptime_seconds"] = uptime;
    health["total_logs"] = m_totalLogsWritten;
    health["total_metrics"] = m_totalMetricsRecorded;
    health["total_errors"] = errorCount;
    health["error_rate"] = errorCount / std::max(1.0f, uptime / 60.0f);
    health["healthy"] = errorCount < 10;

    return health;
}

bool AgenticObservability::isHealthy() const
{
    json health = getSystemHealth();
    if (health.contains("healthy") && health["healthy"].is_boolean()) {
        return health["healthy"].get<bool>();
    }
    return true;
}

json AgenticObservability::getPerformanceSummary() const
{
    json summary;

    std::unordered_map<std::string, bool> seen;
    for (const auto& metric : m_metrics) {
        if (metric.metricName.find("duration") != std::string::npos &&
            seen.find(metric.metricName) == seen.end()) {
            seen[metric.metricName] = true;
            // Strip "_duration" suffix to get histogram base name
            std::string baseName = metric.metricName;
            auto pos = baseName.find("_duration");
            if (pos != std::string::npos) {
                baseName.erase(pos);
            }
            summary[metric.metricName] = getHistogramStats(baseName);
        }
    }

    return summary;
}

// ===== PRIVATE HELPERS =====

std::string AgenticObservability::generateTraceId()
{
    static thread_local std::mt19937_64 rng([] {
        std::random_device rd;
        std::seed_seq seq{rd(), rd(), rd(), rd()};
        return std::mt19937_64(seq);
    }());
    std::uniform_int_distribution<uint64_t> dist;

    uint64_t hi = dist(rng);
    uint64_t lo = dist(rng);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(16) << hi
        << std::setw(16) << lo;
    return oss.str();
}

std::string AgenticObservability::generateSpanId()
{
    static thread_local std::mt19937_64 rng([] {
        std::random_device rd;
        std::seed_seq seq{rd(), rd(), rd(), rd()};
        return std::mt19937_64(seq);
    }());
    std::uniform_int_distribution<uint64_t> dist;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(16) << dist(rng);
    return oss.str();
}

std::string AgenticObservability::levelToString(LogLevel level) const
{
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

void AgenticObservability::checkAndRotateLogs()
{
    if (static_cast<int>(m_logs.size()) > m_maxLogEntries) {
        int toRemove = static_cast<int>(m_logs.size()) - (m_maxLogEntries * 9 / 10);
        m_logs.erase(m_logs.begin(), m_logs.begin() + toRemove);
    }
}

