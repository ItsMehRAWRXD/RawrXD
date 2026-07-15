/**
 * BenchmarkFramework.hpp
 *
 * Phase H Batch 3/5: Benchmark Framework
 *
 * Comprehensive benchmarking framework with statistical analysis,
 * regression detection, and performance comparison.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>
#include <optional>

namespace Performance {

// ============================================================================
// Forward Declarations
// ============================================================================

class BenchmarkCase;
class BenchmarkSuite;
class BenchmarkRunner;
class BenchmarkReporter;

// ============================================================================
// Benchmark Types
// ============================================================================

enum class BenchmarkType {
    MICRO,          // Microbenchmark (single operation)
    MACRO,          // Macrobenchmark (full workflow)
    STRESS,         // Stress test (high load)
    SOAK,           // Soak test (long duration)
    SPIKE,          // Spike test (sudden load)
    ENDURANCE       // Endurance test (extended duration)
};

enum class BenchmarkStatus {
    PENDING,
    RUNNING,
    PASSED,
    FAILED,
    SKIPPED,
    TIMEOUT
};

// ============================================================================
// Benchmark Configuration
// ============================================================================

/**
 * Configuration for benchmark execution.
 */
struct BenchmarkConfig {
    // Execution
    uint32_t warmupIterations = 3;
    uint32_t minIterations = 10;
    uint32_t maxIterations = 1000;
    uint64_t minDurationMs = 1000;
    uint64_t maxDurationMs = 60000;
    
    // Statistical
    double confidenceLevel = 0.95;
    double outlierThreshold = 3.0;  // Standard deviations
    bool detectOutliers = true;
    
    // Comparison
    double regressionThreshold = 0.05;  // 5% regression threshold
    double improvementThreshold = 0.05; // 5% improvement threshold
    
    // Environment
    bool isolateCores = false;
    bool disableTurbo = false;
    bool pinThreads = false;
    std::vector<uint32_t> cpuAffinity;
    
    // Reporting
    bool verbose = false;
    bool saveRawData = false;
    std::string outputFormat = "json";
};

// ============================================================================
// Benchmark Result
// ============================================================================

/**
 * Single benchmark measurement.
 */
struct BenchmarkMeasurement {
    uint64_t iteration;
    uint64_t durationNs;
    uint64_t cpuCycles;
    uint64_t instructions;
    uint64_t cacheMisses;
    uint64_t branchMisses;
    size_t memoryUsed;
    std::map<std::string, double> customMetrics;
};

/**
 * Statistical summary of benchmark results.
 */
struct BenchmarkStatistics {
    uint64_t iterations;
    
    // Duration
    double meanNs;
    double medianNs;
    double stdDevNs;
    double minNs;
    double maxNs;
    double p50Ns;
    double p90Ns;
    double p95Ns;
    double p99Ns;
    double p999Ns;
    
    // Throughput
    double throughputOpsPerSec;
    
    // Confidence interval
    double confidenceIntervalLow;
    double confidenceIntervalHigh;
    
    // Outliers
    uint64_t outlierCount;
    double outlierPercentage;
    
    // Stability
    double relativeStandardError;  // CV%
    bool isStable;
    
    std::string ToJson() const;
};

/**
 * Complete benchmark result.
 */
struct BenchmarkResult {
    std::string name;
    std::string description;
    BenchmarkType type;
    BenchmarkStatus status;
    
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    uint64_t totalDurationMs;
    
    BenchmarkStatistics statistics;
    std::vector<BenchmarkMeasurement> rawMeasurements;
    
    // Comparison
    std::optional<BenchmarkStatistics> baseline;
    double regressionVsBaseline;     // Negative = improvement
    bool isRegression;
    bool isImprovement;
    
    // Error
    std::string errorMessage;
    
    // Metadata
    std::map<std::string, std::string> metadata;
    
    std::string ToJson() const;
};

// ============================================================================
// Benchmark Case
// ============================================================================

/**
 * Single benchmark case.
 */
class BenchmarkCase {
public:
    using SetupFunc = std::function<void()>;
    using TeardownFunc = std::function<void()>;
    using BenchmarkFunc = std::function<void()>;
    using IterationFunc = std::function<void(uint64_t iteration)>;
    using CustomMetricFunc = std::function<std::map<std::string, double>()>;
    
    BenchmarkCase(const std::string& name, const std::string& description);
    
    // Configuration
    BenchmarkCase& SetType(BenchmarkType type);
    BenchmarkCase& SetConfig(const BenchmarkConfig& config);
    BenchmarkCase& SetBaseline(const BenchmarkResult& baseline);
    
    // Callbacks
    BenchmarkCase& SetSetup(SetupFunc func);
    BenchmarkCase& SetTeardown(TeardownFunc func);
    BenchmarkCase& SetBenchmark(BenchmarkFunc func);
    BenchmarkCase& SetIteration(IterationFunc func);
    BenchmarkCase& SetCustomMetrics(CustomMetricFunc func);
    
    // Parameterized benchmarks
    template<typename T>
    BenchmarkCase& AddParameter(const std::string& name, const std::vector<T>& values);
    
    // Metadata
    BenchmarkCase& SetMetadata(const std::string& key, const std::string& value);
    
    // Accessors
    std::string GetName() const { return name_; }
    std::string GetDescription() const { return description_; }
    BenchmarkType GetType() const { return type_; }
    BenchmarkConfig GetConfig() const { return config_; }
    
    // Execution
    BenchmarkResult Run();
    
private:
    std::string name_;
    std::string description_;
    BenchmarkType type_ = BenchmarkType::MICRO;
    BenchmarkConfig config_;
    std::optional<BenchmarkResult> baseline_;
    
    SetupFunc setup_;
    TeardownFunc teardown_;
    BenchmarkFunc benchmark_;
    IterationFunc iteration_;
    CustomMetricFunc customMetrics_;
    
    std::map<std::string, std::vector<std::string>> parameters_;
    std::map<std::string, std::string> metadata_;
    
    BenchmarkStatistics CalculateStatistics(
        const std::vector<BenchmarkMeasurement>& measurements) const;
    std::vector<BenchmarkMeasurement> DetectOutliers(
        const std::vector<BenchmarkMeasurement>& measurements) const;
};

// ============================================================================
// Benchmark Suite
// ============================================================================

/**
 * Collection of benchmark cases.
 */
class BenchmarkSuite {
public:
    explicit BenchmarkSuite(const std::string& name);
    
    // Add benchmarks
    void AddBenchmark(std::shared_ptr<BenchmarkCase> benchmark);
    void AddBenchmarks(const std::vector<std::shared_ptr<BenchmarkCase>>& benchmarks);
    
    // Configuration
    void SetDefaultConfig(const BenchmarkConfig& config);
    void SetFilter(const std::string& pattern);  // Regex filter
    
    // Accessors
    std::string GetName() const { return name_; }
    std::vector<std::shared_ptr<BenchmarkCase>> GetBenchmarks() const;
    std::vector<std::shared_ptr<BenchmarkCase>> GetFilteredBenchmarks() const;
    
    // Execution
    std::vector<BenchmarkResult> RunAll();
    BenchmarkResult Run(const std::string& benchmarkName);
    
private:
    std::string name_;
    std::vector<std::shared_ptr<BenchmarkCase>> benchmarks_;
    BenchmarkConfig defaultConfig_;
    std::string filterPattern_;
};

// ============================================================================
// Benchmark Runner
// ============================================================================

/**
 * Benchmark execution engine.
 */
class BenchmarkRunner {
public:
    struct Config {
        uint32_t parallelBenchmarks = 1;
        bool stopOnFailure = false;
        bool shuffle = false;
        uint32_t seed = 0;
    };
    
    explicit BenchmarkRunner(const Config& config = Config{});
    
    // Execution
    std::vector<BenchmarkResult> RunSuite(BenchmarkSuite& suite);
    BenchmarkResult RunCase(BenchmarkCase& benchmark);
    
    // Parallel execution
    std::vector<BenchmarkResult> RunParallel(
        const std::vector<std::shared_ptr<BenchmarkCase>>& benchmarks);
    
    // Progress
    using ProgressCallback = std::function<void(const std::string& benchmarkName,
                                                 uint64_t current,
                                                 uint64_t total)>;
    void SetProgressCallback(ProgressCallback callback);
    
private:
    Config config_;
    ProgressCallback progressCallback_;
    
    void PrepareEnvironment();
    void RestoreEnvironment();
    void PinThread(uint32_t cpu);
};

// ============================================================================
// Benchmark Reporter
// ============================================================================

/**
 * Benchmark result reporting.
 */
class BenchmarkReporter {
public:
    enum class Format {
        CONSOLE,
        JSON,
        CSV,
        HTML,
        XML,
        MARKDOWN
    };
    
    explicit BenchmarkReporter(Format format = Format::CONSOLE);
    
    // Report generation
    std::string GenerateReport(const std::vector<BenchmarkResult>& results);
    std::string GenerateReport(const BenchmarkResult& result);
    
    // Comparison
    std::string GenerateComparisonReport(
        const std::vector<BenchmarkResult>& current,
        const std::vector<BenchmarkResult>& baseline);
    
    // Trend analysis
    std::string GenerateTrendReport(
        const std::map<std::string, std::vector<BenchmarkResult>>& history);
    
    // Export
    void ExportToFile(const std::string& filepath,
                      const std::vector<BenchmarkResult>& results);
    void ExportToFile(const std::string& filepath,
                      const BenchmarkResult& result);
    
    // Console output
    void PrintResults(const std::vector<BenchmarkResult>& results);
    void PrintResult(const BenchmarkResult& result);
    void PrintSummary(const std::vector<BenchmarkResult>& results);
    
private:
    Format format_;
    
    std::string FormatConsole(const std::vector<BenchmarkResult>& results);
    std::string FormatJson(const std::vector<BenchmarkResult>& results);
    std::string FormatCsv(const std::vector<BenchmarkResult>& results);
    std::string FormatHtml(const std::vector<BenchmarkResult>& results);
    std::string FormatXml(const std::vector<BenchmarkResult>& results);
    std::string FormatMarkdown(const std::vector<BenchmarkResult>& results);
};

// ============================================================================
// Regression Detector
// ============================================================================

/**
 * Performance regression detection.
 */
class RegressionDetector {
public:
    struct Regression {
        std::string benchmarkName;
        double baselineMean;
        double currentMean;
        double regressionPercent;
        bool statisticallySignificant;
        double pValue;
    };
    
    struct Config {
        double threshold = 0.05;  // 5% threshold
        double confidenceLevel = 0.95;
        bool requireStatisticalSignificance = true;
    };
    
    explicit RegressionDetector(const Config& config = Config{});
    
    // Detect regressions
    std::vector<Regression> DetectRegressions(
        const std::vector<BenchmarkResult>& current,
        const std::vector<BenchmarkResult>& baseline);
    
    bool IsRegression(const BenchmarkResult& current,
                      const BenchmarkResult& baseline);
    
    // Statistical tests
    double CalculatePValue(const std::vector<double>& baseline,
                           const std::vector<double>& current);
    bool IsStatisticallySignificant(const BenchmarkResult& current,
                                    const BenchmarkResult& baseline);
    
private:
    Config config_;
    
    double WelchTTest(const std::vector<double>& a, const std::vector<double>& b);
};

// ============================================================================
// Benchmark Database
// ============================================================================

/**
 * Persistent storage for benchmark results.
 */
class BenchmarkDatabase {
public:
    explicit BenchmarkDatabase(const std::string& dbPath);
    ~BenchmarkDatabase();
    
    bool Initialize();
    void Close();
    
    // Store results
    void StoreResult(const BenchmarkResult& result);
    void StoreResults(const std::vector<BenchmarkResult>& results);
    
    // Query results
    std::vector<BenchmarkResult> GetResults(const std::string& benchmarkName);
    std::vector<BenchmarkResult> GetResults(const std::string& benchmarkName,
                                            const std::chrono::system_clock::time_point& since);
    std::vector<BenchmarkResult> GetResults(const std::string& benchmarkName,
                                            const std::string& gitCommit);
    
    // Baseline management
    void SetBaseline(const std::string& benchmarkName, const BenchmarkResult& result);
    std::optional<BenchmarkResult> GetBaseline(const std::string& benchmarkName);
    
    // History
    std::map<std::string, std::vector<BenchmarkResult>> GetHistory(
        const std::chrono::system_clock::time_point& since);
    
    // Trends
    std::vector<std::pair<std::chrono::system_clock::time_point, double>> GetTrend(
        const std::string& benchmarkName);
    
private:
    std::string dbPath_;
    void* dbHandle_;  // SQLite handle
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define BENCHMARK(name, description) \
    static void BM_##name(); \
    static auto _benchmark_##name = []() { \
        auto bm = std::make_shared<Performance::BenchmarkCase>(#name, description); \
        bm->SetBenchmark(BM_##name); \
        return bm; \
    }(); \
    static void BM_##name()

#define BENCHMARK_WITH_SETUP(name, description) \
    static void BM_##name(); \
    static void BM_##name##_setup(); \
    static void BM_##name##_teardown(); \
    static auto _benchmark_##name = []() { \
        auto bm = std::make_shared<Performance::BenchmarkCase>(#name, description); \
        bm->SetBenchmark(BM_##name); \
        bm->SetSetup(BM_##name##_setup); \
        bm->SetTeardown(BM_##name##_teardown); \
        return bm; \
    }(); \
    static void BM_##name()

} // namespace Performance
