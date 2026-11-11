// RawrXD Distributed Benchmark Suite
// Phase O.5: Validate distributed scaling behavior
// Measures throughput, latency, and efficiency across cluster configurations

#pragma once

#include <vector>
#include <map>
#include <string>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <random>

namespace RawrXD {
namespace Distributed {

// Forward declarations
class ClusterManager;
class DistributedScheduler;
class ModelResidencyManager;
class DistributedKVCache;

// Benchmark types
enum class BenchmarkType {
    THROUGHPUT,         // Max requests per second
    LATENCY,           // Response time under load
    SCALABILITY,       // Performance vs node count
    FAILOVER,          // Recovery time during failures
    LOAD_BALANCE,      // Work distribution efficiency
    MEMORY_EFFICIENCY, // Cache hit rates, memory usage
    NETWORK_OVERHEAD,   // Communication costs
    END_TO_END         // Full pipeline performance
};

// Benchmark configuration
struct BenchmarkConfig {
    BenchmarkType type;
    std::string name;
    std::string description;
    
    // Duration settings
    uint32_t warmupSeconds = 30;
    uint32_t durationSeconds = 300;  // 5 minutes default
    uint32_t cooldownSeconds = 10;
    
    // Load settings
    uint32_t concurrentClients = 100;
    uint32_t requestsPerSecond = 0;  // 0 = unlimited
    uint32_t totalRequests = 10000;
    
    // Request distribution
    enum class RequestDistribution {
        UNIFORM,        // Even distribution
        POISSON,        // Poisson arrival process
        BURST,          // Bursty traffic
        DIURNAL         // Day/night pattern
    } distribution = RequestDistribution::POISSON;
    
    // Model settings
    std::vector<std::string> models;
    std::vector<float> modelWeights;  // Selection probability
    
    // Payload settings
    uint32_t minPromptTokens = 10;
    uint32_t maxPromptTokens = 512;
    uint32_t minCompletionTokens = 10;
    uint32_t maxCompletionTokens = 256;
    
    // Cluster settings
    std::vector<std::string> targetNodes;  // Empty = all nodes
    bool pinToNodes = false;
    
    // Failure injection (for failover tests)
    bool enableFailureInjection = false;
    uint32_t failureIntervalSeconds = 60;
    float failureProbability = 0.1f;
    
    // Metrics collection
    bool collectLatencyHistogram = true;
    bool collectPerNodeMetrics = true;
    bool collectCacheMetrics = true;
    uint32_t metricsIntervalMs = 1000;
};

// Benchmark result
struct BenchmarkResult {
    std::string benchmarkId;
    BenchmarkConfig config;
    bool completed;
    std::string errorMessage;
    
    // Timing
    std::chrono::steady_clock::time_point startedAt;
    std::chrono::steady_clock::time_point completedAt;
    std::chrono::milliseconds totalDuration;
    
    // Request statistics
    uint64_t totalRequests;
    uint64_t successfulRequests;
    uint64_t failedRequests;
    uint64_t timeoutRequests;
    uint64_t cancelledRequests;
    
    // Throughput
    double requestsPerSecond;
    double tokensPerSecond;
    double tokensPerSecondPerNode;
    
    // Latency statistics (milliseconds)
    double minLatencyMs;
    double maxLatencyMs;
    double meanLatencyMs;
    double medianLatencyMs;
    double p50LatencyMs;
    double p95LatencyMs;
    double p99LatencyMs;
    double p999LatencyMs;
    double stdDevLatencyMs;
    
    // Latency histogram (buckets in ms)
    std::map<uint32_t, uint64_t> latencyHistogram;  // bucket -> count
    
    // Per-node results
    struct NodeResult {
        std::string nodeId;
        uint64_t requestsHandled;
        double avgLatencyMs;
        double throughput;
        double cpuUtilization;
        double memoryUtilization;
        double gpuUtilization;
    };
    std::vector<NodeResult> nodeResults;
    
    // Cache statistics
    double cacheHitRate;
    uint64_t cacheHits;
    uint64_t cacheMisses;
    size_t peakCacheUsage;
    
    // Scalability metrics
    double speedupRatio;        // Actual vs ideal speedup
    double efficiency;          // Speedup / node count
    double serialFraction;      // Amdahl's law
    
    // Resource utilization
    double avgCpuUtilization;
    double avgMemoryUtilization;
    double avgGpuUtilization;
    double avgNetworkUtilization;
    
    // Failover metrics (if applicable)
    uint32_t failuresInjected;
    double avgRecoveryTimeMs;
    uint32_t successfulFailovers;
};

// Scaling test configuration
struct ScalingTestConfig {
    uint32_t minNodes = 1;
    uint32_t maxNodes = 8;
    uint32_t stepSize = 1;
    uint32_t durationPerConfig = 60;  // Seconds per node count
    
    bool scaleUp = true;
    bool scaleDown = true;
    bool measureEfficiency = true;
};

// Scaling test result
struct ScalingTestResult {
    std::map<uint32_t, BenchmarkResult> resultsByNodeCount;
    
    // Analysis
    double maxSpeedup;
    uint32_t optimalNodeCount;
    double maxEfficiency;
    
    // Amdahl's law fit
    double serialFraction;
    double parallelFraction;
    double theoreticalMaxSpeedup;
    
    // Gustafson's law
    double scaledSpeedup;
    
    // Recommendations
    std::string recommendedConfig;
    std::string bottleneckAnalysis;
};

// Load pattern generator
class LoadPatternGenerator {
public:
    LoadPatternGenerator(const BenchmarkConfig& config);
    
    // Generate next request timing
    std::chrono::milliseconds getNextDelay();
    
    // Generate request parameters
    struct RequestParams {
        std::string modelId;
        uint32_t promptTokens;
        uint32_t completionTokens;
        std::string targetNode;
    };
    RequestParams generateRequest();
    
    // Pattern types
    void setUniformPattern();
    void setPoissonPattern(double lambda);
    void setBurstPattern(uint32_t burstSize, uint32_t burstIntervalMs);
    void setDiurnalPattern(double peakRps, uint32_t peakHour);
    
private:
    BenchmarkConfig config_;
    std::mt19937 rng_;
    std::exponential_distribution<double> expDist_;
    std::uniform_int_distribution<uint32_t> tokenDist_;
    std::discrete_distribution<uint32_t> modelDist_;
    
    // Burst pattern state
    uint32_t burstRemaining_ = 0;
    std::chrono::steady_clock::time_point lastBurst_;
};

// Metrics collector
class MetricsCollector {
public:
    MetricsCollector(uint32_t intervalMs);
    ~MetricsCollector();
    
    void start();
    void stop();
    
    // Record metrics
    void recordLatency(double latencyMs);
    void recordThroughput(double rps);
    void recordCacheHit(bool hit);
    void recordNodeMetric(const std::string& nodeId, const std::string& metric, double value);
    
    // Get collected metrics
    std::vector<double> getLatencies() const;
    double getAverageLatency() const;
    double getPercentileLatency(double percentile) const;
    
    std::map<std::string, std::vector<std::pair<std::chrono::steady_clock::time_point, double>>>
        getTimeSeries() const;
    
    void reset();
    
private:
    void collectionLoop();
    
    uint32_t intervalMs_;
    std::atomic<bool> running_;
    std::thread collectorThread_;
    
    mutable std::mutex latenciesMutex_;
    std::vector<double> latencies_;
    
    mutable std::mutex metricsMutex_;
    std::map<std::string, std::map<std::string, std::vector<std::pair<std::chrono::steady_clock::time_point, double>>>>
        nodeMetrics_;
    
    std::atomic<uint64_t> cacheHits_{0};
    std::atomic<uint64_t> cacheMisses_{0};
};

// Failure injector
class FailureInjector {
public:
    FailureInjector(std::shared_ptr<ClusterManager> clusterManager);
    
    void configure(float probability, uint32_t intervalSeconds);
    void start();
    void stop();
    
    // Manual failure injection
    bool injectNodeFailure(const std::string& nodeId);
    bool injectNetworkPartition(const std::string& nodeId);
    bool injectSlowNode(const std::string& nodeId, uint32_t delayMs);
    
    // Recovery
    bool recoverNode(const std::string& nodeId);
    bool recoverNetwork(const std::string& nodeId);
    bool restoreNodeSpeed(const std::string& nodeId);
    
    // Statistics
    uint32_t getInjectedFailures() const { return injectedFailures_; }
    uint32_t getSuccessfulRecoveries() const { return successfulRecoveries_; }
    
private:
    void injectionLoop();
    
    std::shared_ptr<ClusterManager> clusterManager_;
    std::atomic<bool> running_;
    std::atomic<float> probability_{0.0f};
    std::atomic<uint32_t> intervalSeconds_{60};
    std::thread injectorThread_;
    
    std::atomic<uint32_t> injectedFailures_{0};
    std::atomic<uint32_t> successfulRecoveries_{0};
    
    std::set<std::string> failedNodes_;
    mutable std::mutex failedNodesMutex_;
};

// Distributed Benchmark Runner class
class DistributedBenchmark {
public:
    DistributedBenchmark(
        std::shared_ptr<ClusterManager> clusterManager,
        std::shared_ptr<DistributedScheduler> scheduler,
        std::shared_ptr<ModelResidencyManager> residencyManager,
        std::shared_ptr<DistributedKVCache> kvCache);
    ~DistributedBenchmark();
    
    // Initialization
    bool initialize();
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Benchmark execution
    std::string startBenchmark(const BenchmarkConfig& config);
    bool stopBenchmark(const std::string& benchmarkId);
    bool pauseBenchmark(const std::string& benchmarkId);
    bool resumeBenchmark(const std::string& benchmarkId);
    
    // Status
    enum class BenchmarkState {
        PENDING,
        WARMUP,
        RUNNING,
        COOLDOWN,
        COMPLETED,
        FAILED,
        CANCELLED
    };
    BenchmarkState getBenchmarkState(const std::string& benchmarkId) const;
    float getBenchmarkProgress(const std::string& benchmarkId) const;
    
    // Results
    BenchmarkResult getResult(const std::string& benchmarkId) const;
    std::vector<BenchmarkResult> getAllResults() const;
    bool exportResults(const std::string& benchmarkId, const std::string& filePath);
    
    // Scaling tests
    std::string startScalingTest(const ScalingTestConfig& config);
    ScalingTestResult getScalingResult(const std::string& testId) const;
    
    // Comparison
    struct ComparisonResult {
        std::string baselineId;
        std::string comparisonId;
        double latencyChangePercent;
        double throughputChangePercent;
        double efficiencyChangePercent;
        bool isRegression;
        std::string recommendation;
    };
    ComparisonResult compareResults(const std::string& baselineId, 
                                     const std::string& comparisonId) const;
    
    // Baseline management
    bool setBaseline(const std::string& benchmarkId);
    BenchmarkResult getBaseline() const;
    bool hasBaseline() const { return hasBaseline_; }
    
    // Predefined benchmarks
    static BenchmarkConfig createThroughputBenchmark();
    static BenchmarkConfig createLatencyBenchmark();
    static BenchmarkConfig createScalabilityBenchmark();
    static BenchmarkConfig createFailoverBenchmark();
    static BenchmarkConfig createCacheEfficiencyBenchmark();
    static BenchmarkConfig createEndToEndBenchmark();
    
    // Quick tests
    BenchmarkResult runQuickSmokeTest();
    BenchmarkResult runLoadTest(uint32_t durationSeconds, uint32_t rps);
    BenchmarkResult runStressTest(uint32_t durationSeconds);
    
    // Reporting
    std::string generateReport(const std::string& benchmarkId);
    std::string generateComparisonReport(const std::string& baselineId,
                                          const std::string& comparisonId);
    
private:
    // Internal methods
    void benchmarkLoop(const std::string& benchmarkId, const BenchmarkConfig& config);
    void warmupPhase(const std::string& benchmarkId, const BenchmarkConfig& config);
    void runPhase(const std::string& benchmarkId, const BenchmarkConfig& config);
    void cooldownPhase(const std::string& benchmarkId, const BenchmarkConfig& config);
    
    void executeRequest(const std::string& benchmarkId, 
                        const LoadPatternGenerator::RequestParams& params);
    
    void calculateResults(const std::string& benchmarkId);
    void calculatePercentiles(BenchmarkResult& result);
    void calculateScalabilityMetrics(BenchmarkResult& result);
    
    std::string generateBenchmarkId();
    
    // Threading
    std::atomic<bool> initialized_;
    mutable std::mutex benchmarksMutex_;
    mutable std::mutex resultsMutex_;
    
    // Active benchmarks
    struct ActiveBenchmark {
        std::string id;
        BenchmarkConfig config;
        BenchmarkState state;
        std::chrono::steady_clock::time_point startTime;
        std::atomic<float> progress{0.0f};
        std::vector<std::thread> workerThreads;
        std::atomic<bool> paused{false};
        std::atomic<bool> cancelled{false};
    };
    std::map<std::string, std::unique_ptr<ActiveBenchmark>> activeBenchmarks_;
    
    // Results
    std::map<std::string, BenchmarkResult> results_;
    
    // Baseline
    bool hasBaseline_;
    std::string baselineId_;
    
    // Dependencies
    std::shared_ptr<ClusterManager> clusterManager_;
    std::shared_ptr<DistributedScheduler> scheduler_;
    std::shared_ptr<ModelResidencyManager> residencyManager_;
    std::shared_ptr<DistributedKVCache> kvCache_;
    
    // Components
    std::unique_ptr<MetricsCollector> metricsCollector_;
    std::unique_ptr<FailureInjector> failureInjector_;
    
    // ID counter
    std::atomic<uint64_t> benchmarkIdCounter_{0};
};

// Performance regression detector
class RegressionDetector {
public:
    RegressionDetector();
    
    void setThresholds(double latencyThresholdPercent = 10.0,
                       double throughputThresholdPercent = -10.0,
                       double errorRateThreshold = 0.01);
    
    struct RegressionReport {
        bool hasRegression;
        std::vector<std::string> issues;
        double severityScore;
        std::string recommendation;
    };
    
    RegressionReport analyze(const BenchmarkResult& baseline,
                             const BenchmarkResult& current);
    
private:
    double latencyThreshold_;
    double throughputThreshold_;
    double errorRateThreshold_;
};

} // namespace Distributed
} // namespace RawrXD
