// RawrXD Bottleneck Analyzer Implementation
// Phase P.2: Automatic bottleneck detection and optimization recommendations

#include "BottleneckAnalyzer.hpp"
#include "PerformanceProfiler.hpp"
#include "ObservabilityPlatform.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <thread>
#include <fstream>

namespace RawrXD {
namespace Performance {

BottleneckAnalyzer::BottleneckAnalyzer(PerformanceProfiler* profiler,
                                        ObservabilityPlatform* observability)
    : running_(false)
    , initialized_(false)
    , profiler_(profiler)
    , observability_(observability)
{
}

BottleneckAnalyzer::~BottleneckAnalyzer() {
    shutdown();
}

bool BottleneckAnalyzer::initialize(const BottleneckAnalyzerConfig& config) {
    if (initialized_) {
        return true;
    }

    config_ = config;
    running_ = true;

    // Start analysis thread
    analysisThread_ = std::thread(&BottleneckAnalyzer::analysisLoop, this);

    initialized_ = true;
    return true;
}

bool BottleneckAnalyzer::shutdown() {
    if (!initialized_) {
        return true;
    }

    running_ = false;

    if (analysisThread_.joinable()) {
        analysisThread_.join();
    }

    initialized_ = false;
    return true;
}

// Analysis
std::vector<Bottleneck> BottleneckAnalyzer::analyzeCurrentState() {
    std::vector<Bottleneck> bottlenecks;

    // Analyze all resource types
    auto cpuBottlenecks = analyzeCPUBottlenecks();
    bottlenecks.insert(bottlenecks.end(), cpuBottlenecks.begin(), cpuBottlenecks.end());

    auto memoryBottlenecks = analyzeMemoryBottlenecks();
    bottlenecks.insert(bottlenecks.end(), memoryBottlenecks.begin(), memoryBottlenecks.end());

    auto gpuBottlenecks = analyzeGPUBottlenecks();
    bottlenecks.insert(bottlenecks.end(), gpuBottlenecks.begin(), gpuBottlenecks.end());

    auto ioBottlenecks = analyzeIOBottlenecks();
    bottlenecks.insert(bottlenecks.end(), ioBottlenecks.begin(), ioBottlenecks.end());

    auto lockBottlenecks = analyzeLockContention();
    bottlenecks.insert(bottlenecks.end(), lockBottlenecks.begin(), lockBottlenecks.end());

    auto cacheBottlenecks = analyzeCacheEfficiency();
    bottlenecks.insert(bottlenecks.end(), cacheBottlenecks.begin(), cacheBottlenecks.end());

    // Update active bottlenecks
    {
        std::lock_guard<std::mutex> lock(mutex_);
        activeBottlenecks_ = bottlenecks;
    }

    // Notify callbacks
    if (bottleneckCallback_) {
        for (const auto& bottleneck : bottlenecks) {
            bottleneckCallback_(bottleneck);
        }
    }

    return bottlenecks;
}

std::vector<Bottleneck> BottleneckAnalyzer::analyzeTimeRange(
    std::chrono::steady_clock::time_point start,
    std::chrono::steady_clock::time_point end) {
    // Would analyze historical data
    return analyzeCurrentState();
}

// Real-time detection
void BottleneckAnalyzer::startRealTimeDetection() {
    // Analysis loop already running
}

void BottleneckAnalyzer::stopRealTimeDetection() {
    running_ = false;
}

std::vector<Bottleneck> BottleneckAnalyzer::getActiveBottlenecks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeBottlenecks_;
}

// Baseline management
void BottleneckAnalyzer::recordBaseline(const std::string& name) {
    PerformanceBaseline baseline;
    baseline.name = name;
    baseline.recordedAt = std::chrono::steady_clock::now();

    if (profiler_) {
        auto cpuProfile = profiler_->getCPUProfile();
        baseline.avgCpuPercent = cpuProfile.totalUsagePercent;

        auto memProfile = profiler_->getMemoryProfile();
        baseline.avgMemoryPercent = 100.0f * memProfile.currentUsage /
                                    std::max(memProfile.heapSize, size_t(1));

        auto gpuProfile = profiler_->getGPUProfile();
        baseline.avgGpuPercent = gpuProfile.utilizationPercent;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        baselines_[name] = baseline;
    }
}

PerformanceBaseline BottleneckAnalyzer::getBaseline(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = baselines_.find(name);
    if (it != baselines_.end()) {
        return it->second;
    }

    return PerformanceBaseline();
}

std::vector<std::string> BottleneckAnalyzer::getBaselineNames() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::string> names;
    for (const auto& pair : baselines_) {
        names.push_back(pair.first);
    }
    return names;
}

void BottleneckAnalyzer::compareToBaseline(const std::string& baselineName) {
    auto baseline = getBaseline(baselineName);
    if (baseline.name.empty()) {
        return;
    }

    // Compare current metrics to baseline
    // Would generate comparison report
}

// Recommendations
std::vector<OptimizationRecommendation> BottleneckAnalyzer::generateRecommendations(
    const std::vector<Bottleneck>& bottlenecks) {
    std::vector<OptimizationRecommendation> recommendations;

    for (const auto& bottleneck : bottlenecks) {
        auto recs = getRecommendationsForBottleneck(bottleneck);
        recommendations.insert(recommendations.end(), recs.begin(), recs.end());
    }

    // Sort by priority and confidence
    std::sort(recommendations.begin(), recommendations.end(),
        [](const OptimizationRecommendation& a, const OptimizationRecommendation& b) {
            if (static_cast<int>(a.priority) != static_cast<int>(b.priority)) {
                return static_cast<int>(a.priority) > static_cast<int>(b.priority);
            }
            return a.confidence > b.confidence;
        });

    // Limit to max recommendations
    if (recommendations.size() > config_.maxRecommendations) {
        recommendations.resize(config_.maxRecommendations);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        recommendations_ = recommendations;
    }

    return recommendations;
}

std::vector<OptimizationRecommendation> BottleneckAnalyzer::getTopRecommendations(uint32_t count) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (recommendations_.size() <= count) {
        return recommendations_;
    }

    return std::vector<OptimizationRecommendation>(
        recommendations_.begin(), recommendations_.begin() + count);
}

// Specific analyzers
std::vector<Bottleneck> BottleneckAnalyzer::analyzeCPUBottlenecks() {
    std::vector<Bottleneck> bottlenecks;

    if (!profiler_) {
        return bottlenecks;
    }

    auto cpuProfile = profiler_->getCPUProfile();

    if (cpuProfile.totalUsagePercent > config_.cpuThreshold) {
        Bottleneck bottleneck;
        bottleneck.type = BottleneckType::CPU_BOUND;
        bottleneck.severity = calculateSeverity(BottleneckType::CPU_BOUND,
                                                 cpuProfile.totalUsagePercent);
        bottleneck.component = "CPU";
        bottleneck.description = "CPU usage exceeds threshold";
        bottleneck.impactPercent = calculateImpact(BottleneckType::CPU_BOUND,
                                                    cpuProfile.totalUsagePercent);
        bottleneck.currentValue = cpuProfile.totalUsagePercent;
        bottleneck.thresholdValue = config_.cpuThreshold;
        bottleneck.detectedAt = std::chrono::steady_clock::now();
        bottleneck.context["user_time"] = std::to_string(cpuProfile.userTimePercent);
        bottleneck.context["system_time"] = std::to_string(cpuProfile.systemTimePercent);

        bottlenecks.push_back(bottleneck);
    }

    return bottlenecks;
}

std::vector<Bottleneck> BottleneckAnalyzer::analyzeMemoryBottlenecks() {
    std::vector<Bottleneck> bottlenecks;

    if (!profiler_) {
        return bottlenecks;
    }

    auto memProfile = profiler_->getMemoryProfile();
    float memoryPercent = 100.0f * memProfile.currentUsage /
                          std::max(memProfile.heapSize, size_t(1));

    if (memoryPercent > config_.memoryThreshold) {
        Bottleneck bottleneck;
        bottleneck.type = BottleneckType::MEMORY_BOUND;
        bottleneck.severity = calculateSeverity(BottleneckType::MEMORY_BOUND, memoryPercent);
        bottleneck.component = "Memory";
        bottleneck.description = "Memory usage exceeds threshold";
        bottleneck.impactPercent = calculateImpact(BottleneckType::MEMORY_BOUND, memoryPercent);
        bottleneck.currentValue = memoryPercent;
        bottleneck.thresholdValue = config_.memoryThreshold;
        bottleneck.detectedAt = std::chrono::steady_clock::now();
        bottleneck.context["current_usage"] = std::to_string(memProfile.currentUsage);
        bottleneck.context["heap_size"] = std::to_string(memProfile.heapSize);

        bottlenecks.push_back(bottleneck);
    }

    return bottlenecks;
}

std::vector<Bottleneck> BottleneckAnalyzer::analyzeGPUBottlenecks() {
    std::vector<Bottleneck> bottlenecks;

    if (!profiler_) {
        return bottlenecks;
    }

    auto gpuProfile = profiler_->getGPUProfile();

    if (gpuProfile.utilizationPercent > config_.gpuThreshold) {
        Bottleneck bottleneck;
        bottleneck.type = BottleneckType::GPU_BOUND;
        bottleneck.severity = calculateSeverity(BottleneckType::GPU_BOUND,
                                                 gpuProfile.utilizationPercent);
        bottleneck.component = "GPU";
        bottleneck.description = "GPU utilization exceeds threshold";
        bottleneck.impactPercent = calculateImpact(BottleneckType::GPU_BOUND,
                                                    gpuProfile.utilizationPercent);
        bottleneck.currentValue = gpuProfile.utilizationPercent;
        bottleneck.thresholdValue = config_.gpuThreshold;
        bottleneck.detectedAt = std::chrono::steady_clock::now();
        bottleneck.context["memory_utilization"] = std::to_string(gpuProfile.memoryUtilizationPercent);
        bottleneck.context["temperature"] = std::to_string(gpuProfile.temperature);

        bottlenecks.push_back(bottleneck);
    }

    return bottlenecks;
}

std::vector<Bottleneck> BottleneckAnalyzer::analyzeIOBottlenecks() {
    std::vector<Bottleneck> bottlenecks;

    if (!profiler_) {
        return bottlenecks;
    }

    auto netProfile = profiler_->getNetworkProfile();

    // Check for high I/O wait (simplified)
    float ioWaitPercent = 0.0f; // Would calculate from profile

    if (ioWaitPercent > config_.ioWaitThreshold) {
        Bottleneck bottleneck;
        bottleneck.type = BottleneckType::IO_BOUND;
        bottleneck.severity = calculateSeverity(BottleneckType::IO_BOUND, ioWaitPercent);
        bottleneck.component = "I/O";
        bottleneck.description = "I/O wait time exceeds threshold";
        bottleneck.impactPercent = calculateImpact(BottleneckType::IO_BOUND, ioWaitPercent);
        bottleneck.currentValue = ioWaitPercent;
        bottleneck.thresholdValue = config_.ioWaitThreshold;
        bottleneck.detectedAt = std::chrono::steady_clock::now();

        bottlenecks.push_back(bottleneck);
    }

    return bottlenecks;
}

std::vector<Bottleneck> BottleneckAnalyzer::analyzeLockContention() {
    // Would analyze lock contention from profiler
    return std::vector<Bottleneck>();
}

std::vector<Bottleneck> BottleneckAnalyzer::analyzeCacheEfficiency() {
    // Would analyze cache efficiency
    return std::vector<Bottleneck>();
}

std::vector<Bottleneck> BottleneckAnalyzer::analyzeSchedulerEfficiency() {
    // Would analyze scheduler efficiency
    return std::vector<Bottleneck>();
}

// Trend analysis
BottleneckAnalyzer::Trend BottleneckAnalyzer::analyzeTrend(BottleneckType type) const {
    Trend trend;
    trend.isImproving = true;
    trend.changeRate = 0.0f;
    trend.prediction = "Stable";

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = history_.find(type);
    if (it == history_.end() || it->second.size() < 2) {
        return trend;
    }

    const auto& data = it->second;

    // Calculate trend
    double sum = 0.0;
    for (const auto& point : data) {
        sum += point.second;
    }
    double avg = sum / data.size();

    // Compare recent to older
    double recent = data.back().second;
    double older = data.front().second;

    trend.isImproving = recent < older;
    trend.changeRate = static_cast<float>((recent - older) / older * 100.0);

    if (trend.changeRate > 10.0f) {
        trend.prediction = "Degrading rapidly";
    } else if (trend.changeRate > 5.0f) {
        trend.prediction = "Degrading";
    } else if (trend.changeRate < -10.0f) {
        trend.prediction = "Improving rapidly";
    } else if (trend.changeRate < -5.0f) {
        trend.prediction = "Improving";
    }

    return trend;
}

// Reports
std::string BottleneckAnalyzer::generateReport() const {
    std::stringstream report;

    report << "# Performance Bottleneck Report\n\n";

    auto bottlenecks = getActiveBottlenecks();
    report << "## Active Bottlenecks (" << bottlenecks.size() << ")\n\n";

    for (const auto& bottleneck : bottlenecks) {
        report << "### " << bottleneck.component << "\n";
        report << "- **Type**: " << static_cast<int>(bottleneck.type) << "\n";
        report << "- **Severity**: " << static_cast<int>(bottleneck.severity) << "\n";
        report << "- **Impact**: " << std::fixed << std::setprecision(2)
               << bottleneck.impactPercent << "%\n";
        report << "- **Description**: " << bottleneck.description << "\n";
        report << "- **Current Value**: " << bottleneck.currentValue << "\n";
        report << "- **Threshold**: " << bottleneck.thresholdValue << "\n\n";
    }

    return report.str();
}

std::string BottleneckAnalyzer::generateRecommendationReport() const {
    std::stringstream report;

    report << "# Optimization Recommendations\n\n";

    std::lock_guard<std::mutex> lock(mutex_);

    report << "## Top Recommendations (" << recommendations_.size() << ")\n\n";

    for (size_t i = 0; i < recommendations_.size(); i++) {
        const auto& rec = recommendations_[i];
        report << "### " << (i + 1) << ". " << rec.title << "\n";
        report << "- **Category**: " << rec.category << "\n";
        report << "- **Expected Improvement**: " << std::fixed << std::setprecision(2)
               << rec.expectedImprovementPercent << "%\n";
        report << "- **Confidence**: " << std::fixed << std::setprecision(2)
               << rec.confidence * 100.0f << "%\n";
        report << "- **Priority**: " << static_cast<int>(rec.priority) << "\n";
        report << "- **Description**: " << rec.description << "\n\n";
    }

    return report.str();
}

bool BottleneckAnalyzer::saveReport(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    file << generateReport();
    return true;
}

// Configuration
bool BottleneckAnalyzer::updateConfig(const BottleneckAnalyzerConfig& config) {
    config_ = config;
    return true;
}

// Callbacks
void BottleneckAnalyzer::setBottleneckCallback(BottleneckCallback callback) {
    bottleneckCallback_ = callback;
}

// Internal methods
void BottleneckAnalyzer::analysisLoop() {
    while (running_) {
        // Run analysis
        auto bottlenecks = analyzeCurrentState();

        // Generate recommendations
        if (!bottlenecks.empty()) {
            generateRecommendations(bottlenecks);
        }

        // Update history
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto now = std::chrono::steady_clock::now();

            for (const auto& bottleneck : bottlenecks) {
                history_[bottleneck.type].push_back({now, bottleneck.currentValue});

                // Trim history
                auto cutoff = now - std::chrono::hours(24);
                auto& data = history_[bottleneck.type];
                data.erase(std::remove_if(data.begin(), data.end(),
                    [cutoff](const auto& point) { return point.first < cutoff; }),
                    data.end());
            }
        }

        // Adaptive thresholds
        if (config_.useAdaptiveThresholds) {
            updateAdaptiveThresholds();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(config_.analysisIntervalMs));
    }
}

void BottleneckAnalyzer::updateAdaptiveThresholds() {
    // Would adjust thresholds based on historical data
}

Severity BottleneckAnalyzer::calculateSeverity(BottleneckType type, float value) {
    float threshold = 0.0f;

    switch (type) {
        case BottleneckType::CPU_BOUND:
            threshold = config_.cpuThreshold;
            break;
        case BottleneckType::MEMORY_BOUND:
            threshold = config_.memoryThreshold;
            break;
        case BottleneckType::GPU_BOUND:
            threshold = config_.gpuThreshold;
            break;
        default:
            threshold = 80.0f;
    }

    float excess = value - threshold;

    if (excess > 20.0f) {
        return Severity::CRITICAL;
    } else if (excess > 10.0f) {
        return Severity::HIGH;
    } else if (excess > 5.0f) {
        return Severity::MEDIUM;
    }

    return Severity::LOW;
}

float BottleneckAnalyzer::calculateImpact(BottleneckType type, float value) {
    // Calculate performance impact percentage
    return std::min(value / 2.0f, 100.0f);
}

std::vector<OptimizationRecommendation> BottleneckAnalyzer::getRecommendationsForBottleneck(
    const Bottleneck& bottleneck) {
    std::vector<OptimizationRecommendation> recommendations;

    switch (bottleneck.type) {
        case BottleneckType::CPU_BOUND:
            {
                OptimizationRecommendation rec;
                rec.id = "cpu-1";
                rec.title = "Enable Work Stealing Scheduler";
                rec.description = "Distribute load more evenly across CPU cores";
                rec.category = "Scheduling";
                rec.expectedImprovementPercent = 15.0f;
                rec.confidence = 0.8f;
                rec.priority = Severity::HIGH;
                rec.effort = OptimizationRecommendation::EffortLevel::EASY;
                rec.risk = OptimizationRecommendation::RiskLevel::LOW;
                recommendations.push_back(rec);
            }
            break;

        case BottleneckType::MEMORY_BOUND:
            {
                OptimizationRecommendation rec;
                rec.id = "mem-1";
                rec.title = "Enable KV Cache Compression";
                rec.description = "Compress KV cache entries to reduce memory usage";
                rec.category = "Memory";
                rec.expectedImprovementPercent = 25.0f;
                rec.confidence = 0.9f;
                rec.priority = Severity::HIGH;
                rec.effort = OptimizationRecommendation::EffortLevel::EASY;
                rec.risk = OptimizationRecommendation::RiskLevel::LOW;
                recommendations.push_back(rec);
            }
            break;

        case BottleneckType::GPU_BOUND:
            {
                OptimizationRecommendation rec;
                rec.id = "gpu-1";
                rec.title = "Enable Model Quantization";
                rec.description = "Use quantized models to reduce GPU memory and compute";
                rec.category = "Model Optimization";
                rec.expectedImprovementPercent = 30.0f;
                rec.confidence = 0.85f;
                rec.priority = Severity::HIGH;
                rec.effort = OptimizationRecommendation::EffortLevel::MEDIUM;
                rec.risk = OptimizationRecommendation::RiskLevel::MEDIUM;
                recommendations.push_back(rec);
            }
            break;

        default:
            break;
    }

    return recommendations;
}

// OptimizationEngine Implementation

OptimizationEngine::OptimizationEngine(BottleneckAnalyzer* analyzer)
    : analyzer_(analyzer)
    , autoOptimizationEnabled_(false)
{
}

bool OptimizationEngine::applyRecommendation(const OptimizationRecommendation& recommendation) {
    // Would apply the optimization
    return true;
}

bool OptimizationEngine::applyRecommendations(
    const std::vector<OptimizationRecommendation>& recommendations) {
    for (const auto& rec : recommendations) {
        if (!applyRecommendation(rec)) {
            return false;
        }
    }
    return true;
}

bool OptimizationEngine::validateOptimization(const OptimizationRecommendation& recommendation) {
    // Would validate the optimization worked
    return true;
}

bool OptimizationEngine::rollbackOptimization(const std::string& recommendationId) {
    // Would rollback the optimization
    return true;
}

std::string OptimizationEngine::startABTest(const OptimizationRecommendation& recommendation) {
    // Would start A/B test
    return "test-" + recommendation.id;
}

bool OptimizationEngine::stopABTest(const std::string& testId, bool apply) {
    // Would stop A/B test
    return true;
}

void OptimizationEngine::enableAutoOptimization(bool enable) {
    autoOptimizationEnabled_ = enable;
}

bool OptimizationEngine::isAutoOptimizationEnabled() const {
    return autoOptimizationEnabled_;
}

// RegressionDetector Implementation

RegressionDetector::RegressionDetector(BottleneckAnalyzer* analyzer)
    : analyzer_(analyzer)
    , alertThreshold_(10.0f)
{
}

bool RegressionDetector::detectRegression(const PerformanceBaseline& baseline) {
    // Would compare current performance to baseline
    return false;
}

std::vector<Bottleneck> RegressionDetector::getRegressions() const {
    // Would return detected regressions
    return std::vector<Bottleneck>();
}

void RegressionDetector::setAlertThreshold(float threshold) {
    alertThreshold_ = threshold;
}

void RegressionDetector::setAlertCallback(std::function<void(const Bottleneck&)> callback) {
    alertCallback_ = callback;
}

} // namespace Performance
} // namespace RawrXD
