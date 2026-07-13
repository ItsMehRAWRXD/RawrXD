// RawrXD Bottleneck Analyzer
// Phase P.2: Automatic bottleneck detection and optimization recommendations
// Identifies performance bottlenecks and suggests fixes

#pragma once

#include <vector>
#include <map>
#include <string>
#include <memory>
#include <chrono>

namespace RawrXD {
namespace Performance {

// Forward declarations
class PerformanceProfiler;
class ObservabilityPlatform;

// Bottleneck types
enum class BottleneckType {
    CPU_BOUND,          // CPU saturation
    MEMORY_BOUND,       // Memory pressure
    GPU_BOUND,          // GPU saturation
    IO_BOUND,           // Disk/network I/O
    LOCK_CONTENTION,    // Lock contention
    CACHE_MISS,         // Cache misses
    SCHEDULING,         // Scheduler issues
    NETWORK_LATENCY,    // Network delays
    MODEL_LOADING,      // Model loading delays
    KV_CACHE_MISS       // KV cache misses
};

// Bottleneck severity
enum class Severity {
    LOW,        // Minor impact
    MEDIUM,     // Noticeable impact
    HIGH,       // Significant impact
    CRITICAL    // Severe impact
};

// Detected bottleneck
struct Bottleneck {
    BottleneckType type;
    Severity severity;
    std::string component;
    std::string description;
    float impactPercent;        // Performance impact (0-100)
    
    // Metrics
    double currentValue;
    double thresholdValue;
    double baselineValue;
    
    // Timing
    std::chrono::steady_clock::time_point detectedAt;
    std::chrono::seconds duration;
    
    // Context
    std::map<std::string, std::string> context;
    std::vector<std::string> affectedOperations;
};

// Optimization recommendation
struct OptimizationRecommendation {
    std::string id;
    std::string title;
    std::string description;
    std::string category;
    
    // Impact
    float expectedImprovementPercent;
    float confidence;
    Severity priority;
    
    // Implementation
    std::string implementation;
    std::string codeExample;
    std::vector<std::string> prerequisites;
    
    // Effort
    enum class EffortLevel {
        TRIVIAL,    // Minutes
        EASY,       // Hours
        MEDIUM,     // Days
        HARD        // Weeks
    } effort;
    
    // Risk
    enum class RiskLevel {
        NONE,       // No risk
        LOW,        // Minimal risk
        MEDIUM,     // Some risk
        HIGH        // Significant risk
    } risk;
    
    // Validation
    std::vector<std::string> validationSteps;
    std::string rollbackProcedure;
};

// Performance baseline
struct PerformanceBaseline {
    std::string name;
    std::chrono::steady_clock::time_point recordedAt;
    
    // Metrics
    double avgLatencyMs;
    double p99LatencyMs;
    double throughputRps;
    double errorRate;
    
    // Resource usage
    float avgCpuPercent;
    float avgMemoryPercent;
    float avgGpuPercent;
    
    // Component metrics
    std::map<std::string, double> componentMetrics;
};

// Analyzer configuration
struct BottleneckAnalyzerConfig {
    // Detection thresholds
    float cpuThreshold = 80.0f;
    float memoryThreshold = 85.0f;
    float gpuThreshold = 90.0f;
    float ioWaitThreshold = 20.0f;
    float cacheMissThreshold = 30.0f;
    float lockContentionThreshold = 10.0f;
    
    // Timing
    uint32_t analysisIntervalMs = 5000;
    uint32_t minBottleneckDurationMs = 10000;
    uint32_t baselineWindowMinutes = 60;
    
    // Sensitivity
    float sensitivity = 1.0f;  // 0.5 = less sensitive, 2.0 = more sensitive
    bool useAdaptiveThresholds = true;
    
    // Recommendations
    uint32_t maxRecommendations = 10;
    bool includeExperimental = false;
    float minConfidence = 0.6f;
};

// Bottleneck analyzer
class BottleneckAnalyzer {
public:
    BottleneckAnalyzer(PerformanceProfiler* profiler, ObservabilityPlatform* observability);
    ~BottleneckAnalyzer();
    
    // Lifecycle
    bool initialize(const BottleneckAnalyzerConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Analysis
    std::vector<Bottleneck> analyzeCurrentState();
    std::vector<Bottleneck> analyzeTimeRange(
        std::chrono::steady_clock::time_point start,
        std::chrono::steady_clock::time_point end);
    
    // Real-time detection
    void startRealTimeDetection();
    void stopRealTimeDetection();
    std::vector<Bottleneck> getActiveBottlenecks() const;
    
    // Baseline management
    void recordBaseline(const std::string& name);
    PerformanceBaseline getBaseline(const std::string& name) const;
    std::vector<std::string> getBaselineNames() const;
    void compareToBaseline(const std::string& baselineName);
    
    // Recommendations
    std::vector<OptimizationRecommendation> generateRecommendations(
        const std::vector<Bottleneck>& bottlenecks);
    std::vector<OptimizationRecommendation> getTopRecommendations(uint32_t count);
    
    // Specific analyzers
    std::vector<Bottleneck> analyzeCPUBottlenecks();
    std::vector<Bottleneck> analyzeMemoryBottlenecks();
    std::vector<Bottleneck> analyzeGPUBottlenecks();
    std::vector<Bottleneck> analyzeIOBottlenecks();
    std::vector<Bottleneck> analyzeLockContention();
    std::vector<Bottleneck> analyzeCacheEfficiency();
    std::vector<Bottleneck> analyzeSchedulerEfficiency();
    
    // Trend analysis
    struct Trend {
        bool isImproving;
        float changeRate;
        std::string prediction;
        std::chrono::seconds timeToThreshold;
    };
    Trend analyzeTrend(BottleneckType type) const;
    
    // Reports
    std::string generateReport() const;
    std::string generateRecommendationReport() const;
    bool saveReport(const std::string& filename) const;
    
    // Configuration
    BottleneckAnalyzerConfig getConfig() const { return config_; }
    bool updateConfig(const BottleneckAnalyzerConfig& config);
    
    // Callbacks
    using BottleneckCallback = std::function<void(const Bottleneck&)>;
    void setBottleneckCallback(BottleneckCallback callback);
    
private:
    // Internal methods
    void analysisLoop();
    void updateAdaptiveThresholds();
    
    Severity calculateSeverity(BottleneckType type, float value);
    float calculateImpact(BottleneckType type, float value);
    
    std::vector<OptimizationRecommendation> getRecommendationsForBottleneck(
        const Bottleneck& bottleneck);
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread analysisThread_;
    mutable std::mutex mutex_;
    
    // Dependencies
    PerformanceProfiler* profiler_;
    ObservabilityPlatform* observability_;
    
    // Configuration
    BottleneckAnalyzerConfig config_;
    
    // State
    std::vector<Bottleneck> activeBottlenecks_;
    std::map<std::string, PerformanceBaseline> baselines_;
    std::vector<OptimizationRecommendation> recommendations_;
    
    // History for trend analysis
    std::map<BottleneckType, std::vector<std::pair<std::chrono::steady_clock::time_point, double>>> history_;
    
    // Callbacks
    BottleneckCallback bottleneckCallback_;
};

// Optimization engine
class OptimizationEngine {
public:
    OptimizationEngine(BottleneckAnalyzer* analyzer);
    
    // Apply optimizations
    bool applyRecommendation(const OptimizationRecommendation& recommendation);
    bool applyRecommendations(const std::vector<OptimizationRecommendation>& recommendations);
    
    // Validation
    bool validateOptimization(const OptimizationRecommendation& recommendation);
    bool rollbackOptimization(const std::string& recommendationId);
    
    // A/B testing
    std::string startABTest(const OptimizationRecommendation& recommendation);
    bool stopABTest(const std::string& testId, bool apply);
    
    // Auto-optimization
    void enableAutoOptimization(bool enable);
    bool isAutoOptimizationEnabled() const;
    
private:
    BottleneckAnalyzer* analyzer_;
    bool autoOptimizationEnabled_;
};

// Performance regression detector
class RegressionDetector {
public:
    RegressionDetector(BottleneckAnalyzer* analyzer);
    
    // Detection
    bool detectRegression(const PerformanceBaseline& baseline);
    std::vector<Bottleneck> getRegressions() const;
    
    // Alerts
    void setAlertThreshold(float threshold);
    void setAlertCallback(std::function<void(const Bottleneck&)> callback);
    
private:
    BottleneckAnalyzer* analyzer_;
    float alertThreshold_;
    std::function<void(const Bottleneck&)> alertCallback_;
};

} // namespace Performance
} // namespace RawrXD
