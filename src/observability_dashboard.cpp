// ============================================================================
// observability_dashboard.cpp - Full Implementation
// Real-time metrics dashboard for monitoring model inference performance
// ============================================================================

#include "observability_dashboard.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <chrono>
#include <cstring>

// ============================================================================
// ObservabilityDashboard Implementation
// ============================================================================

ObservabilityDashboard::ObservabilityDashboard(void* parent)
    : m_parent(parent)
    , m_initialized(false)
    , m_enabled(true)
    , m_refreshIntervalMs(1000)
    , m_maxDataPoints(3600) // 1 hour at 1s intervals
    , m_totalInferences(0)
    , m_totalTokens(0)
    , m_totalErrors(0)
    , m_startTime(std::chrono::steady_clock::now())
{
    // Initialize metric counters
    std::memset(&m_currentMetrics, 0, sizeof(SystemMetrics));
    m_currentMetrics.cpuUsage = 0.0;
    m_currentMetrics.gpuUsage = 0.0;
    m_currentMetrics.memoryUsageMB = 0.0;
    m_currentMetrics.inferenceLatencyMs = 0.0;
    m_currentMetrics.tokensPerSecond = 0.0;
    m_currentMetrics.batchSize = 1;
    m_currentMetrics.activeRequests = 0;
    m_currentMetrics.queueDepth = 0;
    m_currentMetrics.temperature = 0.7f;
    m_currentMetrics.topP = 0.9f;
}

ObservabilityDashboard::~ObservabilityDashboard() {
    shutdown();
}

bool ObservabilityDashboard::initialize(int refreshIntervalMs, int maxDataPoints) {
    if (m_initialized) return true;

    m_refreshIntervalMs = refreshIntervalMs;
    m_maxDataPoints = maxDataPoints;
    m_initialized = true;

    std::cout << "ObservabilityDashboard initialized (refresh: "
              << refreshIntervalMs << "ms, max points: "
              << maxDataPoints << ")" << std::endl;
    return true;
}

void ObservabilityDashboard::shutdown() {
    if (!m_initialized) return;
    m_initialized = false;
    m_metricsHistory.clear();
    std::cout << "ObservabilityDashboard shutdown" << std::endl;
}

void ObservabilityDashboard::updateMetrics(const SystemMetrics& metrics) {
    m_currentMetrics = metrics;

    // Update aggregate counters
    m_totalInferences += metrics.activeRequests;
    m_totalTokens += static_cast<uint64_t>(metrics.tokensPerSecond * 10.0);

    // Add to history with timestamp
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_startTime).count();

    MetricPoint point;
    point.timestamp = elapsed;
    point.cpuUsage = metrics.cpuUsage;
    point.gpuUsage = metrics.gpuUsage;
    point.memoryUsageMB = metrics.memoryUsageMB;
    point.inferenceLatencyMs = metrics.inferenceLatencyMs;
    point.tokensPerSecond = metrics.tokensPerSecond;
    point.activeRequests = metrics.activeRequests;
    point.queueDepth = metrics.queueDepth;

    m_metricsHistory.push_back(point);

    // Trim history to max size
    while (m_metricsHistory.size() > m_maxDataPoints) {
        m_metricsHistory.pop_front();
    }
}

void ObservabilityDashboard::recordInference(double latencyMs, size_t tokens) {
    m_totalInferences++;
    m_totalTokens += tokens;

    m_currentMetrics.inferenceLatencyMs =
        (m_currentMetrics.inferenceLatencyMs * 0.9) + (latencyMs * 0.1);
    m_currentMetrics.tokensPerSecond =
        (tokens > 0) ? (static_cast<double>(tokens) / (latencyMs / 1000.0)) : 0.0;
}

void ObservabilityDashboard::recordError(const std::string& error) {
    m_totalErrors++;
    m_errorLog.push_back({
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - m_startTime).count(),
        error
    });

    // Keep last 100 errors
    while (m_errorLog.size() > 100) {
        m_errorLog.pop_front();
    }
}

ObservabilityDashboard::SystemMetrics ObservabilityDashboard::getCurrentMetrics() const {
    return m_currentMetrics;
}

std::vector<ObservabilityDashboard::MetricPoint>
ObservabilityDashboard::getMetricsHistory(int lastNSeconds) const {
    if (lastNSeconds <= 0) {
        return std::vector<MetricPoint>(m_metricsHistory.begin(),
                                        m_metricsHistory.end());
    }

    auto now = std::chrono::steady_clock::now();
    auto cutoff = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_startTime).count() - (lastNSeconds * 1000);

    std::vector<MetricPoint> recent;
    for (const auto& point : m_metricsHistory) {
        if (point.timestamp >= cutoff) {
            recent.push_back(point);
        }
    }
    return recent;
}

std::string ObservabilityDashboard::generateReport() const {
    std::ostringstream report;

    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_startTime).count();

    report << "=== Observability Report ===" << "\n";
    report << "Uptime: " << uptime << "s" << "\n";
    report << "Total Inferences: " << m_totalInferences << "\n";
    report << "Total Tokens: " << m_totalTokens << "\n";
    report << "Total Errors: " << m_totalErrors << "\n";
    report << "\n";

    report << "--- Current Metrics ---" << "\n";
    report << "CPU Usage: " << std::fixed << std::setprecision(1)
           << m_currentMetrics.cpuUsage << "%" << "\n";
    report << "GPU Usage: " << m_currentMetrics.gpuUsage << "%" << "\n";
    report << "Memory: " << m_currentMetrics.memoryUsageMB << " MB" << "\n";
    report << "Latency: " << m_currentMetrics.inferenceLatencyMs << " ms" << "\n";
    report << "Tokens/s: " << m_currentMetrics.tokensPerSecond << "\n";
    report << "Active Requests: " << m_currentMetrics.activeRequests << "\n";
    report << "Queue Depth: " << m_currentMetrics.queueDepth << "\n";
    report << "\n";

    if (!m_errorLog.empty()) {
        report << "--- Recent Errors (" << m_errorLog.size() << ") ---" << "\n";
        int count = 0;
        for (const auto& error : m_errorLog) {
            if (count++ >= 10) break;
            report << "  [" << error.timestamp << "ms] " << error.message << "\n";
        }
    }

    return report.str();
}

std::string ObservabilityDashboard::formatMetricsJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"cpu_usage\":" << m_currentMetrics.cpuUsage << ",";
    json << "\"gpu_usage\":" << m_currentMetrics.gpuUsage << ",";
    json << "\"memory_mb\":" << m_currentMetrics.memoryUsageMB << ",";
    json << "\"latency_ms\":" << m_currentMetrics.inferenceLatencyMs << ",";
    json << "\"tokens_per_sec\":" << m_currentMetrics.tokensPerSecond << ",";
    json << "\"active_requests\":" << m_currentMetrics.activeRequests << ",";
    json << "\"queue_depth\":" << m_currentMetrics.queueDepth << ",";
    json << "\"total_inferences\":" << m_totalInferences << ",";
    json << "\"total_tokens\":" << m_totalTokens << ",";
    json << "\"total_errors\":" << m_totalErrors;
    json << "}";
    return json.str();
}

void ObservabilityDashboard::setEnabled(bool enabled) {
    m_enabled = enabled;
}

bool ObservabilityDashboard::isEnabled() const {
    return m_enabled;
}

void ObservabilityDashboard::reset() {
    m_metricsHistory.clear();
    m_errorLog.clear();
    m_totalInferences = 0;
    m_totalTokens = 0;
    m_totalErrors = 0;
    m_startTime = std::chrono::steady_clock::now();
    std::memset(&m_currentMetrics, 0, sizeof(SystemMetrics));
    std::cout << "ObservabilityDashboard metrics reset" << std::endl;
}
