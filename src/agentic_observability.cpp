// AgenticObservability Implementation (Qt-free)
#include "agentic_observability.h"
<<<<<<< HEAD
=======


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <random>
#include <sstream>
#include <iomanip>

<<<<<<< HEAD
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string GenerateHexId(int length = 32) {
    static thread_local std::mt19937 rng(
        static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<int> dist(0, 15);
    const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i) {
        result += hex[dist(rng)];
    }
    return result;
}

static double SamplingRoll() {
    static thread_local std::mt19937 rng(
        static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count() ^ 0xBEEF));
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(rng);
}

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

AgenticObservability& AgenticObservability::instance() {
    static AgenticObservability inst;
    return inst;
}

AgenticObservability::AgenticObservability()
    : m_systemStartTime(std::chrono::system_clock::now())
{
    fprintf(stderr, "[AgenticObservability] Initialized - Ready for comprehensive observability\n");
    startHeartbeatLoop();
=======
AgenticObservability::AgenticObservability(void* parent)
    : void(parent),
      m_systemStartTime(std::chrono::system_clock::time_point::currentDateTime())
{
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

AgenticObservability::~AgenticObservability()
{
<<<<<<< HEAD
    stopHeartbeatLoop();
    fprintf(stderr, "[AgenticObservability] Destroyed - Logged %d entries and %d metrics\n",
            m_totalLogsWritten, m_totalMetricsRecorded);
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

std::string AgenticObservability::timePointToISO(const TimePoint& tp) {
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &tt);
#else
    gmtime_r(&tt, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf);
=======
             << m_totalLogsWritten << "entries and"
             << m_totalMetricsRecorded << "metrics";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ===== STRUCTURED LOGGING =====

void AgenticObservability::log(
    LogLevel level,
    const std::string& component,
    const std::string& message,
<<<<<<< HEAD
    const nlohmann::json& context)
=======
    const void*& context)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    // Apply sampling
    if (SamplingRoll() > m_samplingRate) {
        return;
    }

    LogEntry entry;
<<<<<<< HEAD
    entry.timestamp = std::chrono::system_clock::now();
=======
    entry.timestamp = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    entry.level = level;
    entry.component = component;
    entry.message = message;
    entry.context = context;
    entry.traceId = generateTraceId();
    entry.spanId = generateSpanId();

    m_logs.push_back(entry);
    m_totalLogsWritten++;

    // Keep buffer bounded
    if (static_cast<int>(m_logs.size()) > m_maxLogEntries) {
        m_logs.erase(m_logs.begin());
    }

<<<<<<< HEAD
    if (m_logCb) m_logCb(entry, m_logCbData);
=======
    logWritten(entry);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void AgenticObservability::logDebug(
    const std::string& component,
    const std::string& message,
<<<<<<< HEAD
    const nlohmann::json& context)
{
    log(LogLevel::ObsDebug, component, message, context);
=======
    const void*& context)
{
    log(LogLevel::DEBUG, component, message, context);
}

void AgenticObservability::logInfo(
    const std::string& component,
    const std::string& message,
    const void*& context)
{
    log(LogLevel::INFO, component, message, context);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void AgenticObservability::logWarn(
    const std::string& component,
    const std::string& message,
<<<<<<< HEAD
    const nlohmann::json& context)
=======
    const void*& context)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    log(LogLevel::ObsWarn, component, message, context);
}

void AgenticObservability::logInfo(
    const std::string& component,
    const std::string& message,
    const nlohmann::json& context)
{
    log(LogLevel::ObsInfo, component, message, context);
}

void AgenticObservability::logError(
    const std::string& component,
    const std::string& message,
<<<<<<< HEAD
    const nlohmann::json& context)
=======
    const void*& context)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    log(LogLevel::ObsError, component, message, context);
    m_errorCounts[component]++;
}

void AgenticObservability::logCritical(
    const std::string& component,
    const std::string& message,
<<<<<<< HEAD
    const nlohmann::json& context)
=======
    const void*& context)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    log(LogLevel::ObsCritical, component, message, context);
    m_errorCounts[component]++;
}

std::vector<AgenticObservability::LogEntry> AgenticObservability::getLogs(
    int limit,
    LogLevel minLevel,
<<<<<<< HEAD
    const std::string& component) const
=======
    const std::string& component)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
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

std::vector<AgenticObservability::LogEntry> AgenticObservability::getLogsByTimeRange(
<<<<<<< HEAD
    const TimePoint& start,
    const TimePoint& end,
    LogLevel minLevel) const
=======
    const std::chrono::system_clock::time_point& start,
    const std::chrono::system_clock::time_point& end,
    LogLevel minLevel)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    std::vector<LogEntry> filtered;

    for (const auto& entry : m_logs) {
        if (entry.timestamp < start || entry.timestamp > end) continue;
        if (entry.level < minLevel) continue;
        filtered.push_back(entry);
    }

    return filtered;
}

// ===== METRICS =====

void AgenticObservability::recordMetric(
    const std::string& metricName,
    float value,
<<<<<<< HEAD
    const nlohmann::json& labels,
=======
    const void*& labels,
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    const std::string& unit)
{
    MetricPoint point;
    point.metricName = metricName;
    point.value = value;
    point.labels = labels;
<<<<<<< HEAD
    point.timestamp = std::chrono::system_clock::now();
=======
    point.timestamp = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    point.unit = unit;

    m_metrics.push_back(point);
    m_totalMetricsRecorded++;

    // Keep buffer bounded
    if (static_cast<int>(m_metrics.size()) > m_metricsBufferSize) {
        m_metrics.erase(m_metrics.begin());
    }

<<<<<<< HEAD
    if (m_metricCb) m_metricCb(metricName, m_metricCbData);
=======
    metricRecorded(metricName);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void AgenticObservability::incrementCounter(
    const std::string& metricName,
    int delta,
<<<<<<< HEAD
    const nlohmann::json& labels)
=======
    const void*& labels)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
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
<<<<<<< HEAD
    const nlohmann::json& labels)
=======
    const void*& labels)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    recordMetric(metricName, value, labels, "gauge");
}

float AgenticObservability::getGaugeValue(const std::string& metricName) const
{
    // Return most recent value
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
<<<<<<< HEAD
    const nlohmann::json& labels)
=======
    const void*& labels)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    recordMetric(metricName + "_histogram", value, labels, "histogram");
}

<<<<<<< HEAD
nlohmann::json AgenticObservability::getHistogramStats(const std::string& metricName) const
=======
void* AgenticObservability::getHistogramStats(const std::string& metricName) const
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    std::vector<float> values;

    for (const auto& metric : m_metrics) {
        if (metric.metricName == metricName + "_histogram") {
            values.push_back(metric.value);
        }
    }

<<<<<<< HEAD
    nlohmann::json stats;
=======
    void* stats;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    if (values.empty()) {
        stats["count"] = 0;
        return stats;
    }

    std::sort(values.begin(), values.end());

    float sum = 0.0f;
    for (float v : values) sum += v;

    stats["count"] = static_cast<int>(values.size());
    stats["min"] = values.front();
    stats["max"] = values.back();
    stats["mean"] = sum / values.size();
    stats["median"] = values[values.size() / 2];

    // Calculate standard deviation
    float variance = 0.0f;
    float mean = sum / static_cast<float>(values.size());
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
        m_obs->recordMetric(m_metricName + "_duration", static_cast<float>(duration.count()), {}, "ms");
    }
}

std::unique_ptr<AgenticObservability::TimingGuard> AgenticObservability::measureDuration(
    const std::string& metricName)
{
    return std::make_unique<TimingGuard>(this, metricName);
}

std::vector<AgenticObservability::MetricPoint> AgenticObservability::getMetrics(
    const std::string& pattern,
<<<<<<< HEAD
    int limit) const
=======
    int limit)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    std::vector<MetricPoint> filtered;

    for (const auto& metric : m_metrics) {
<<<<<<< HEAD
        if (!pattern.empty() && metric.metricName.find(pattern) == std::string::npos) {
=======
        if (!pattern.empty() && !metric.metricName.contains(pattern)) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            continue;
        }
        filtered.push_back(metric);
    }

    if (limit > 0 && static_cast<int>(filtered.size()) > limit) {
        filtered.erase(filtered.begin(), filtered.end() - limit);
    }

    return filtered;
}

<<<<<<< HEAD
nlohmann::json AgenticObservability::getMetricsSummary() const
{
    nlohmann::json summary;
=======
void* AgenticObservability::getMetricsSummary() const
{
    void* summary;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    // Group metrics by name
    std::unordered_map<std::string, std::vector<float>> metricGroups;
    for (const auto& metric : m_metrics) {
        metricGroups[metric.metricName].push_back(metric.value);
    }

<<<<<<< HEAD
    nlohmann::json metrics;
=======
    void* metrics;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    for (const auto& pair : metricGroups) {
        float sum = 0.0f;
        for (float v : pair.second) sum += v;

<<<<<<< HEAD
        nlohmann::json metricInfo;
=======
        void* metricInfo;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        metricInfo["count"] = static_cast<int>(pair.second.size());
        metricInfo["latest"] = pair.second.back();
        metricInfo["avg"] = sum / static_cast<float>(pair.second.size());

<<<<<<< HEAD
        metrics[pair.first] = metricInfo;
=======
        metrics[std::string::fromStdString(pair.first)] = metricInfo;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    summary["metrics"] = metrics;
    summary["total_recorded"] = m_totalMetricsRecorded;

    return summary;
}

<<<<<<< HEAD
nlohmann::json AgenticObservability::getPercentiles(const std::string& metricName) const
=======
void* AgenticObservability::getPercentiles(const std::string& metricName) const
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    std::vector<float> values;

    for (const auto& metric : m_metrics) {
        if (metric.metricName == metricName) {
            values.push_back(metric.value);
        }
    }

<<<<<<< HEAD
    nlohmann::json percentiles;
=======
    void* percentiles;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    if (values.empty()) {
        return percentiles;
    }

    std::sort(values.begin(), values.end());

    percentiles["p50"] = values[values.size() / 2];
    percentiles["p95"] = values[static_cast<size_t>(values.size() * 0.95)];
    percentiles["p99"] = values[static_cast<size_t>(values.size() * 0.99)];

    return percentiles;
}

// ===== DISTRIBUTED TRACING =====

std::string AgenticObservability::startTrace(const std::string& operation)
{
    if (!m_tracingEnabled) return "";

    std::string traceId = generateTraceId();
<<<<<<< HEAD
    m_traceSpans[traceId] = {};
=======
    m_traceSpans[traceId.toStdString()] = {};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

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
<<<<<<< HEAD
    span.startTime = std::chrono::system_clock::now();
=======
    span.startTime = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    span.hasError = false;
    span.statusCode = 0;

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
<<<<<<< HEAD
        it->second.endTime = std::chrono::system_clock::now();
=======
        it->second.endTime = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        it->second.hasError = hasError;
        it->second.errorMessage = errorMessage;
        it->second.statusCode = statusCode;

<<<<<<< HEAD
        if (m_spanCb) m_spanCb(spanId, m_spanCbData);
=======
        spanCompleted(spanId);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

void AgenticObservability::setSpanAttribute(
    const std::string& spanId,
    const std::string& key,
<<<<<<< HEAD
    const nlohmann::json& value)
=======
    const std::any& value)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    auto it = m_spans.find(spanId);
    if (it != m_spans.end()) {
<<<<<<< HEAD
        it->second.attributes[key] = value;
=======
        it->second.attributes[key] = void*::fromVariant(value);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

void AgenticObservability::addSpanEvent(
    const std::string& spanId,
    const std::string& eventName,
<<<<<<< HEAD
    const nlohmann::json& attributes)
=======
    const void*& attributes)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    auto it = m_spans.find(spanId);
    if (it != m_spans.end()) {
<<<<<<< HEAD
        nlohmann::json event;
        event["name"] = eventName;
        event["timestamp"] = timePointToISO(std::chrono::system_clock::now());
        event["attributes"] = attributes;
        
        // Store event in attributes array
        if (!it->second.attributes.contains("events")) {
            it->second.attributes["events"] = nlohmann::json::array();
        }
        it->second.attributes["events"].push_back(event);
=======
        void* event;
        event["name"] = eventName;
        event["timestamp"] = std::chrono::system_clock::time_point::currentDateTime().toString(//ISODate);
        event["attributes"] = attributes;
        
        // Store event in attributes array
        void* events = it->second.attributes.value("events").toArray();
        events.append(event);
        it->second.attributes["events"] = events;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
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
<<<<<<< HEAD
    const std::string& traceId) const
=======
    const std::string& traceId)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
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

<<<<<<< HEAD
nlohmann::json AgenticObservability::getTraceVisualization(const std::string& traceId) const
{
    nlohmann::json visualization;

    auto spans = getTraceSpans(traceId);
    nlohmann::json spanArray = nlohmann::json::array();

    for (const auto& span : spans) {
        nlohmann::json spanObj;
=======
void* AgenticObservability::getTraceVisualization(const std::string& traceId)
{
    void* visualization;

    auto spans = getTraceSpans(traceId);
    void* spanArray;

    for (const auto& span : spans) {
        void* spanObj;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        spanObj["spanId"] = span.spanId;
        spanObj["operation"] = span.operation;
        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            span.endTime - span.startTime).count();
        spanObj["duration"] = static_cast<int>(durationMs);
        spanObj["hasError"] = span.hasError;

        spanArray.push_back(spanObj);
    }

    visualization["traceId"] = traceId;
    visualization["spans"] = spanArray;

    return visualization;
}

// ===== DIAGNOSTICS =====

<<<<<<< HEAD
nlohmann::json AgenticObservability::getSystemHealth() const
{
    nlohmann::json health;
=======
void* AgenticObservability::getSystemHealth() const
{
    void* health;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    int errorCount = 0;
    for (const auto& pair : m_errorCounts) {
        errorCount += pair.second;
    }

<<<<<<< HEAD
    auto now = std::chrono::system_clock::now();
    float uptime = std::chrono::duration<float>(now - m_systemStartTime).count();
=======
    float uptime = m_systemStartTime.msecsTo(std::chrono::system_clock::time_point::currentDateTime()) / 1000.0f;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    health["uptime_seconds"] = uptime;
    health["total_logs"] = m_totalLogsWritten;
    health["total_metrics"] = m_totalMetricsRecorded;
    health["total_errors"] = errorCount;
    health["error_rate"] = errorCount / std::max(1.0f, uptime / 60.0f); // errors per minute

    health["healthy"] = errorCount < 10;

    return health;
}

bool AgenticObservability::isHealthy() const
{
    auto health = getSystemHealth();
    return health.value("healthy", true);
}

<<<<<<< HEAD
nlohmann::json AgenticObservability::getPerformanceSummary() const
{
    nlohmann::json summary;
=======
void* AgenticObservability::getPerformanceSummary() const
{
    void* summary;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    // Find latency-related metrics
    for (const auto& metric : m_metrics) {
        if (metric.metricName.find("duration") != std::string::npos) {
            std::string histogramName = metric.metricName;
            auto pos = histogramName.find("_duration");
            if (pos != std::string::npos) {
                histogramName.erase(pos);
            }
            auto stats = getHistogramStats(histogramName);
            summary[metric.metricName] = stats;
        }
    }

    return summary;
}

<<<<<<< HEAD
nlohmann::json AgenticObservability::getErrorSummary() const
{
    nlohmann::json summary;

    nlohmann::json errorsByComponent;
    for (const auto& pair : m_errorCounts) {
        errorsByComponent[pair.first] = pair.second;
=======
void* AgenticObservability::getErrorSummary() const
{
    void* summary;

    void* errorsByComponent;
    for (const auto& pair : m_errorCounts) {
        errorsByComponent[std::string::fromStdString(pair.first)] = pair.second;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    summary["errors_by_component"] = errorsByComponent;
    summary["total_errors"] = getSystemHealth().value("total_errors", 0);

    return summary;
}

std::vector<std::string> AgenticObservability::detectBottlenecks()
{
    std::vector<std::string> bottlenecks;

    // Aggregate duration metrics: sum and count per metric name
    std::unordered_map<std::string, float> sumDurations;
    std::unordered_map<std::string, int>   countDurations;

    for (const auto& metric : m_metrics) {
        if (metric.metricName.find("duration") != std::string::npos) {
            sumDurations[metric.metricName] += metric.value;
            countDurations[metric.metricName]++;
        }
    }

    // Compute averages and flag operations exceeding 100ms threshold
    constexpr float BOTTLENECK_THRESHOLD_MS = 100.0f;

    for (const auto& pair : sumDurations) {
        int count = countDurations[pair.first];
        if (count == 0) continue;
        float avg = pair.second / static_cast<float>(count);
        if (avg > BOTTLENECK_THRESHOLD_MS) {
            bottlenecks.push_back(pair.first + " avg=" +
                std::to_string(avg) + "ms (" +
                std::to_string(count) + " samples)");
        }
    }

    // Sort by severity (longest average first)
    std::sort(bottlenecks.begin(), bottlenecks.end(),
        [&](const std::string& a, const std::string& b) {
            // Extract avg value from string for ordering
            auto extractAvg = [](const std::string& s) -> float {
                auto pos = s.find("avg=");
                if (pos == std::string::npos) return 0.0f;
                return std::stof(s.substr(pos + 4));
            };
            return extractAvg(a) > extractAvg(b);
        });

    return bottlenecks;
}

<<<<<<< HEAD
nlohmann::json AgenticObservability::analyzeLatency()
=======
void* AgenticObservability::analyzeLatency()
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    return getPerformanceSummary();
}

// ===== EXPORT/REPORTING =====

std::string AgenticObservability::generateReport(
<<<<<<< HEAD
    const TimePoint& startTime,
    const TimePoint& endTime) const
{
    std::ostringstream report;
    report << "=== OBSERVABILITY REPORT ===\n\n";
=======
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime) const
{
    std::string report;
    report += "=== OBSERVABILITY REPORT ===\n\n";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    report << "LOGS:\n";
    auto logs = getLogs(100, LogLevel::ObsDebug);
    for (const auto& log : logs) {
        if (log.timestamp < startTime || log.timestamp > endTime) continue;
<<<<<<< HEAD
        report << "[" << timePointToISO(log.timestamp) << "] "
               << log.component << ": " << log.message << "\n";
=======
        report += std::string("[%1] %2: %3\n")
                  )
                  
                  ;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    report << "\nMETRICS:\n";
    for (const auto& metric : getMetrics("", 50)) {
        if (metric.timestamp < startTime || metric.timestamp > endTime) continue;
<<<<<<< HEAD
        report << metric.metricName << " = " << metric.value << "\n";
=======
        report += std::string("%1 = %2\n");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    return report.str();
}

std::string AgenticObservability::exportMetricsAsCsv() const
{
<<<<<<< HEAD
    std::ostringstream csv;
    csv << "timestamp,metric_name,value,unit\n";

    for (const auto& metric : m_metrics) {
        csv << timePointToISO(metric.timestamp) << ","
            << metric.metricName << ","
            << metric.value << ","
            << metric.unit << "\n";
=======
    std::string csv = "timestamp,metric_name,value,unit\n";

    for (const auto& metric : m_metrics) {
        csv += std::string("%1,%2,%3,%4\n")
               )


               ;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    return csv.str();
}

std::string AgenticObservability::exportTracesAsJson() const
{
<<<<<<< HEAD
    nlohmann::json traces = nlohmann::json::array();

    for (const auto& pair : m_traceSpans) {
        traces.push_back(getTraceVisualization(pair.first));
    }

    return traces.dump(2);
=======
    void* traces;

    for (const auto& pair : m_traceSpans) {
        traces.append(getTraceVisualization(std::string::fromStdString(pair.first)));
    }

    return std::string::fromUtf8(void*(traces).toJson());
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

std::string AgenticObservability::exportLogsAsJson() const
{
<<<<<<< HEAD
    nlohmann::json logs = nlohmann::json::array();

    for (const auto& log : m_logs) {
        nlohmann::json obj;
        obj["timestamp"] = timePointToISO(log.timestamp);
=======
    void* logs;

    for (const auto& log : m_logs) {
        void* obj;
        obj["timestamp"] = log.timestamp.toString(//ISODate);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        obj["level"] = levelToString(log.level);
        obj["component"] = log.component;
        obj["message"] = log.message;
        obj["context"] = log.context;

        logs.push_back(obj);
    }

<<<<<<< HEAD
    return logs.dump(2);
}

std::string AgenticObservability::exportMetricsAsPrometheus() const
{
    std::ostringstream prom;
    std::unordered_map<std::string, float> latestMetrics;
    
    // Grab the latest value for each metric
    for (const auto& metric : m_metrics) {
        latestMetrics[metric.metricName] = metric.value;
    }

    // Add generic info
    prom << "# HELP agentic_observability_total_logs Total number of written logs\n"
         << "# TYPE agentic_observability_total_logs counter\n"
         << "agentic_observability_total_logs " << m_totalLogsWritten << "\n";
         
    prom << "# HELP agentic_observability_total_metrics Total number of metrics recorded\n"
         << "# TYPE agentic_observability_total_metrics counter\n"
         << "agentic_observability_total_metrics " << m_totalMetricsRecorded << "\n";
    
    for (const auto& pair : latestMetrics) {
        // Sanitize metric name for prometheus (replacing non-alphanumeric with underscores mostly)
        std::string safeName = pair.first;
        for(auto& c : safeName) {
            if(!std::isalnum(c)) c = '_';
        }
        prom << "# HELP " << safeName << " Auto-generated metric for " << pair.first << "\n"
             << "# TYPE " << safeName << " gauge\n"
             << safeName << " " << pair.second << "\n";
    }

    return prom.str();
}

void AgenticObservability::startHeartbeatLoop()
{
    if (m_heartbeatRunning) return;
    m_heartbeatRunning = true;
    m_heartbeatThread = std::make_unique<std::thread>(&AgenticObservability::heartbeatWorker, this);
}

void AgenticObservability::stopHeartbeatLoop()
{
    if (m_heartbeatRunning) {
        m_heartbeatRunning = false;
        if (m_heartbeatThread && m_heartbeatThread->joinable()) {
            m_heartbeatThread->join();
        }
    }
}

// -----------------------------------------------------------------------
// Core Agent Metrics Hooks 
// -----------------------------------------------------------------------

void AgenticObservability::updateTokensPerSecond(float tps)
{
    setGauge("inference_tokens_per_sec", tps, {});
}

void AgenticObservability::updateAgentLoopIterationTime(float ms)
{
    recordHistogram("agent_loop_iteration_time_ms", ms, {});
    setGauge("agent_loop_iteration_latest_ms", ms, {});
}

void AgenticObservability::updateMemoryUsage(size_t bytes)
{
    setGauge("memory_usage_bytes", static_cast<float>(bytes), {});
}

#include <fstream>
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#else
#include <sys/resource.h>
#endif

void AgenticObservability::heartbeatWorker()
{
    while (m_heartbeatRunning) {
        // Collect automated memory metrics
        size_t memoryUsage = 0;
#ifdef _WIN32
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            memoryUsage = pmc.WorkingSetSize;
        }
#endif
        if (memoryUsage > 0) {
            recordMetric("memory_usage_bytes", static_cast<float>(memoryUsage), {}, "bytes");
        }

        // Write metrics to metrics.prom file
        std::ofstream promFile("metrics.prom", std::ios::trunc);
        if (promFile.is_open()) {
            promFile << exportMetricsAsPrometheus();
            promFile.flush();
            promFile.close();
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
=======
    return std::string::fromUtf8(void*(logs).toJson());
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ===== PRIVATE HELPERS =====

std::string AgenticObservability::generateTraceId()
{
    return GenerateHexId(32);
}

std::string AgenticObservability::generateSpanId()
{
    return GenerateHexId(16);
}

std::string AgenticObservability::levelToString(LogLevel level) const
{
    switch (level) {
        case LogLevel::ObsDebug: return "DEBUG";
        case LogLevel::ObsInfo: return "INFO";
        case LogLevel::ObsWarn: return "WARN";
        case LogLevel::ObsError: return "ERROR";
        case LogLevel::ObsCritical: return "CRITICAL";
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

void AgenticObservability::prune()
{
    checkAndRotateLogs();
}


