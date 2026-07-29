<<<<<<< HEAD
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
=======
#include "observability_dashboard.h"
#include "profiler.h"


ObservabilityDashboard::ObservabilityDashboard(Profiler* profiler, void* parent)
    : void(parent)
    , m_tabWidget(nullptr)
    , m_profiler(profiler)
{
    // Lightweight constructor - defer Qt Charts creation to initialize()
}

ObservabilityDashboard::~ObservabilityDashboard()
{
    // Qt handles widget cleanup
}

// Two-phase init: Create Qt Charts widgets after void is running
void ObservabilityDashboard::initialize() {
    if (m_tabWidget) return;  // Already initialized
    
    setWindowTitle("Observability Dashboard");
    setMinimumSize(1000, 700);

    m_tabWidget = new void(this);
    setupUI();
    setupConnections();
}

void ObservabilityDashboard::setupUI()
{
    void* mainLayout = new void(this);

    // ===== Create Charts =====
    createResourceChart();
    createThroughputChart();
    createLatencyChart();
    createMetricsPanel();

    // ===== Add to Tab Widget =====
    m_resourceChartView = nullptr;
    m_resourceChartView->setRenderHint(QPainter::Antialiasing);
    m_tabWidget->addTab(m_resourceChartView, "System Resources");

    m_throughputChartView = nullptr;
    m_throughputChartView->setRenderHint(QPainter::Antialiasing);
    m_tabWidget->addTab(m_throughputChartView, "Training Throughput");

    m_latencyChartView = nullptr;
    m_latencyChartView->setRenderHint(QPainter::Antialiasing);
    m_tabWidget->addTab(m_latencyChartView, "Latency Analysis");

    m_tabWidget->addTab(m_metricsPanel, "Live Metrics");

    mainLayout->addWidget(m_tabWidget);
    setLayout(mainLayout);
}

void ObservabilityDashboard::createResourceChart()
{
    m_resourceChart = nullptr;
    m_resourceChart->setTitle("System Resource Utilization");
    m_resourceChart->setAnimationOptions(QChart::SeriesAnimations);
    m_resourceChart->setBackgroundBrush(QBrush(//white));

    // Create series
    m_cpuSeries = nullptr;
    m_cpuSeries->setName("CPU %");
    m_cpuSeries->setColor(//blue);

    m_memorySeries = nullptr;
    m_memorySeries->setName("Memory MB");
    m_memorySeries->setColor(//red);

    m_gpuSeries = nullptr;
    m_gpuSeries->setName("GPU %");
    m_gpuSeries->setColor(//green);

    m_resourceChart->addSeries(m_cpuSeries);
    m_resourceChart->addSeries(m_memorySeries);
    m_resourceChart->addSeries(m_gpuSeries);

    // Create axes
    m_resourceAxisX = nullptr;
    m_resourceAxisX->setFormat("hh:mm:ss");
    m_resourceAxisX->setTickCount(5);
    m_resourceChart->addAxis(m_resourceAxisX, //AlignBottom);
    m_cpuSeries->attachAxis(m_resourceAxisX);
    m_memorySeries->attachAxis(m_resourceAxisX);
    m_gpuSeries->attachAxis(m_resourceAxisX);

    m_resourceAxisY = nullptr;
    m_resourceAxisY->setTitleText("Value");
    m_resourceAxisY->setRange(0, 100);
    m_resourceChart->addAxis(m_resourceAxisY, //AlignLeft);
    m_cpuSeries->attachAxis(m_resourceAxisY);
    m_memorySeries->attachAxis(m_resourceAxisY);
    m_gpuSeries->attachAxis(m_resourceAxisY);

    m_resourceChart->legend()->setVisible(true);
    m_resourceChart->legend()->setAlignment(//AlignTop);
}

void ObservabilityDashboard::createThroughputChart()
{
    m_throughputChart = nullptr;
    m_throughputChart->setTitle("Training Throughput");
    m_throughputChart->setAnimationOptions(QChart::SeriesAnimations);
    m_throughputChart->setBackgroundBrush(QBrush(//white));

    // Create series
    m_samplesPerSecSeries = nullptr;
    m_samplesPerSecSeries->setName("Samples/sec");
    m_samplesPerSecSeries->setColor(//darkMagenta);

    m_tokensPerSecSeries = nullptr;
    m_tokensPerSecSeries->setName("Tokens/sec");
    m_tokensPerSecSeries->setColor(//darkCyan);

    m_throughputChart->addSeries(m_samplesPerSecSeries);
    m_throughputChart->addSeries(m_tokensPerSecSeries);

    // Create axes
    m_throughputAxisX = nullptr;
    m_throughputAxisX->setFormat("hh:mm:ss");
    m_throughputAxisX->setTickCount(5);
    m_throughputChart->addAxis(m_throughputAxisX, //AlignBottom);
    m_samplesPerSecSeries->attachAxis(m_throughputAxisX);
    m_tokensPerSecSeries->attachAxis(m_throughputAxisX);

    m_throughputAxisY = nullptr;
    m_throughputAxisY->setTitleText("Throughput");
    m_throughputAxisY->setRange(0, 1000);
    m_throughputChart->addAxis(m_throughputAxisY, //AlignLeft);
    m_samplesPerSecSeries->attachAxis(m_throughputAxisY);
    m_tokensPerSecSeries->attachAxis(m_throughputAxisY);

    m_throughputChart->legend()->setVisible(true);
    m_throughputChart->legend()->setAlignment(//AlignTop);
}

void ObservabilityDashboard::createLatencyChart()
{
    m_latencyChart = nullptr;
    m_latencyChart->setTitle("Batch Latency Analysis");
    m_latencyChart->setAnimationOptions(QChart::SeriesAnimations);
    m_latencyChart->setBackgroundBrush(QBrush(//white));

    // Create series for latency percentiles
    m_batchLatencySeries = nullptr;
    m_batchLatencySeries->setName("Avg Latency");
    m_batchLatencySeries->setColor(//darkBlue);

    m_p95LatencySeries = nullptr;
    m_p95LatencySeries->setName("P95 Latency");
    m_p95LatencySeries->setColor(//darkYellow);

    m_p99LatencySeries = nullptr;
    m_p99LatencySeries->setName("P99 Latency");
    m_p99LatencySeries->setColor(//darkRed);

    m_latencyChart->addSeries(m_batchLatencySeries);
    m_latencyChart->addSeries(m_p95LatencySeries);
    m_latencyChart->addSeries(m_p99LatencySeries);

    // Create axes
    m_latencyAxisX = nullptr;
    m_latencyAxisX->setFormat("hh:mm:ss");
    m_latencyAxisX->setTickCount(5);
    m_latencyChart->addAxis(m_latencyAxisX, //AlignBottom);
    m_batchLatencySeries->attachAxis(m_latencyAxisX);
    m_p95LatencySeries->attachAxis(m_latencyAxisX);
    m_p99LatencySeries->attachAxis(m_latencyAxisX);

    m_latencyAxisY = nullptr;
    m_latencyAxisY->setTitleText("Latency (ms)");
    m_latencyAxisY->setRange(0, 5000);
    m_latencyChart->addAxis(m_latencyAxisY, //AlignLeft);
    m_batchLatencySeries->attachAxis(m_latencyAxisY);
    m_p95LatencySeries->attachAxis(m_latencyAxisY);
    m_p99LatencySeries->attachAxis(m_latencyAxisY);

    m_latencyChart->legend()->setVisible(true);
    m_latencyChart->legend()->setAlignment(//AlignTop);
}

void ObservabilityDashboard::createMetricsPanel()
{
    m_metricsPanel = new void();
    void* layout = new void(m_metricsPanel);

    // Current metrics group
    void* currentMetricsGroup = new void("Current Metrics", this);
    void* gridLayout = new void(currentMetricsGroup);

    void* cpuLabel = new void("CPU Usage:", this);
    m_currentCpuLabel = new void("-- %", this);
    m_currentCpuLabel->setStyleSheet("font-weight: bold; color: blue;");
    gridLayout->addWidget(cpuLabel, 0, 0);
    gridLayout->addWidget(m_currentCpuLabel, 0, 1);

    void* memoryLabel = new void("Memory Usage:", this);
    m_currentMemoryLabel = new void("-- MB", this);
    m_currentMemoryLabel->setStyleSheet("font-weight: bold; color: red;");
    gridLayout->addWidget(memoryLabel, 1, 0);
    gridLayout->addWidget(m_currentMemoryLabel, 1, 1);

    void* gpuLabel = new void("GPU Usage:", this);
    m_currentGpuLabel = new void("-- %", this);
    m_currentGpuLabel->setStyleSheet("font-weight: bold; color: green;");
    gridLayout->addWidget(gpuLabel, 2, 0);
    gridLayout->addWidget(m_currentGpuLabel, 2, 1);

    void* throughputLabel = new void("Throughput:", this);
    m_currentThroughputLabel = new void("-- samples/sec", this);
    m_currentThroughputLabel->setStyleSheet("font-weight: bold; color: purple;");
    gridLayout->addWidget(throughputLabel, 3, 0);
    gridLayout->addWidget(m_currentThroughputLabel, 3, 1);

    void* peakMemoryLabel = new void("Peak Memory:", this);
    m_peakMemoryLabel = new void("-- MB", this);
    m_peakMemoryLabel->setStyleSheet("font-weight: bold; color: darkRed;");
    gridLayout->addWidget(peakMemoryLabel, 4, 0);
    gridLayout->addWidget(m_peakMemoryLabel, 4, 1);

    layout->addWidget(currentMetricsGroup);

    // Warnings group
    void* warningsGroup = new void("Performance Warnings", this);
    void* warningsLayout = new void(warningsGroup);
    m_warningsLabel = new void("No warnings", this);
    m_warningsLabel->setStyleSheet("color: green;");
    m_warningsLabel->setWordWrap(true);
    warningsLayout->addWidget(m_warningsLabel);
    
    layout->addWidget(warningsGroup);
    layout->addStretch();
}

void ObservabilityDashboard::setupConnections()
{
    // Connect to profiler signals if available
    if (m_profiler) {
        // Note: These connections would be set up by AgenticIDE
        // This is here for reference
    }
}

void ObservabilityDashboard::onMetricsUpdated(float cpuPercent, float memoryMB, float gpuPercent, float gpuMemoryMB)
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::time_point::currentDateTime();
    int64_t timestamp = now.toMSecsSinceEpoch();

    // Add data points to series
    m_cpuSeries->append(timestamp, cpuPercent);
    m_memorySeries->append(timestamp, memoryMB);
    m_gpuSeries->append(timestamp, gpuPercent);

    // Update metrics panel
    m_currentCpuLabel->setText(std::string::number(cpuPercent, 'f', 1) + " %");
    m_currentMemoryLabel->setText(std::string::number(memoryMB, 'f', 1) + " MB");
    m_currentGpuLabel->setText(std::string::number(gpuPercent, 'f', 1) + " %");

    // Limit data points
    m_dataPointCount++;
    if (m_dataPointCount > m_maxDataPoints) {
        if (!m_cpuSeries->points().empty()) {
            m_cpuSeries->removePoints(0, 1);
            m_memorySeries->removePoints(0, 1);
            m_gpuSeries->removePoints(0, 1);
        }
    }

    // Update axis ranges
    if (!m_cpuSeries->points().empty()) {
        m_resourceAxisX->setRange(
            std::chrono::system_clock::time_point::fromMSecsSinceEpoch(static_cast<int64_t>(m_cpuSeries->points().first().x())),
            std::chrono::system_clock::time_point::fromMSecsSinceEpoch(timestamp)
        );
    }
}

void ObservabilityDashboard::onThroughputUpdated(float batchLatencyMs, float throughputSamples)
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::time_point::currentDateTime();
    int64_t timestamp = now.toMSecsSinceEpoch();

    m_samplesPerSecSeries->append(timestamp, throughputSamples);
    m_batchLatencySeries->append(timestamp, batchLatencyMs);

    m_currentThroughputLabel->setText(std::string::number(throughputSamples, 'f', 1) + " samples/sec");

    // Limit data points
    if (m_samplesPerSecSeries->points().size() > m_maxDataPoints) {
        if (!m_samplesPerSecSeries->points().empty()) {
            m_samplesPerSecSeries->removePoints(0, 1);
            m_batchLatencySeries->removePoints(0, 1);
        }
    }
}

void ObservabilityDashboard::onPerformanceWarning(const std::string& warning)
{
    m_warnings.push_back(warning);
    
    // Keep last 10 warnings
    if (m_warnings.size() > 10) {
        m_warnings.erase(m_warnings.begin());
    }

    // Update label
    std::string warningText = m_warnings.empty() ? "No warnings" : "";
    for (const auto& w : m_warnings) {
        warningText += "⚠ " + w + "\n";
    }
    
    m_warningsLabel->setText(warningText);
    m_warningsLabel->setStyleSheet(m_warnings.empty() ? "color: green;" : "color: darkRed;");
}

void ObservabilityDashboard::clearCharts()
{
    m_cpuSeries->clear();
    m_memorySeries->clear();
    m_gpuSeries->clear();
    m_samplesPerSecSeries->clear();
    m_tokensPerSecSeries->clear();
    m_batchLatencySeries->clear();
    m_p95LatencySeries->clear();
    m_p99LatencySeries->clear();
    
    m_dataPointCount = 0;
    m_warnings.clear();
    
    m_currentCpuLabel->setText("-- %");
    m_currentMemoryLabel->setText("-- MB");
    m_currentGpuLabel->setText("-- %");
    m_currentThroughputLabel->setText("-- samples/sec");
    m_warningsLabel->setText("No warnings");
}

bool ObservabilityDashboard::exportData(const std::string& filePath)
{
    std::fstream file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream stream(&file);
    
    // Export CPU metrics
    stream << "Timestamp,CPU(%),Memory(MB),GPU(%)\n";
    
    for (const auto& point : m_cpuSeries->points()) {
        std::chrono::system_clock::time_point time = std::chrono::system_clock::time_point::fromMSecsSinceEpoch(static_cast<int64_t>(point.x()));
        stream << time.toString("hh:mm:ss") << ","
               << point.y() << ",";
        
        // Find corresponding memory point
        for (const auto& memPoint : m_memorySeries->points()) {
            if (memPoint.x() == point.x()) {
                stream << memPoint.y() << ",";
                break;
            }
        }
        
        // Find corresponding GPU point
        for (const auto& gpuPoint : m_gpuSeries->points()) {
            if (gpuPoint.x() == point.x()) {
                stream << gpuPoint.y();
                break;
            }
        }
        
        stream << "\n";
    }

    file.close();
    return true;
}


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
