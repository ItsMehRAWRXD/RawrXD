// RawrXD Distributed Benchmark Implementation
// Phase O.5: Validate distributed scaling behavior

#include "DistributedBenchmark.hpp"
#include "ClusterManager.hpp"
#include "DistributedScheduler.hpp"
#include "ModelResidencyManager.hpp"
#include "DistributedKVCache.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>

namespace RawrXD {
namespace Distributed {

// LoadPatternGenerator Implementation
LoadPatternGenerator::LoadPatternGenerator(const BenchmarkConfig& config)
    : config_(config)
    , rng_(std::random_device{}())
    , expDist_(1.0)
    , tokenDist_(config.minPromptTokens, config.maxPromptTokens)
{
    // Initialize model distribution
    if (!config.modelWeights.empty()) {
        std::vector<double> weights(config.modelWeights.begin(), config.modelWeights.end());
        modelDist_ = std::discrete_distribution<uint32_t>(weights.begin(), weights.end());
    }
}

std::chrono::milliseconds LoadPatternGenerator::getNextDelay() {
    switch (config_.distribution) {
        case BenchmarkConfig::RequestDistribution::UNIFORM:
            if (config_.requestsPerSecond > 0) {
                return std::chrono::milliseconds(1000 / config_.requestsPerSecond);
            }
            return std::chrono::milliseconds(0);
            
        case BenchmarkConfig::RequestDistribution::POISSON:
            if (config_.requestsPerSecond > 0) {
                double lambda = 1000.0 / config_.requestsPerSecond;
                expDist_ = std::exponential_distribution<double>(1.0 / lambda);
                return std::chrono::milliseconds(static_cast<long long>(expDist_(rng_)));
            }
            return std::chrono::milliseconds(0);
            
        case BenchmarkConfig::RequestDistribution::BURST:
            if (burstRemaining_ > 0) {
                burstRemaining_--;
                return std::chrono::milliseconds(0);
            } else {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - lastBurst_).count();
                if (elapsed >= 1000) { // 1 second burst interval
                    burstRemaining_ = 10; // Burst size
                    lastBurst_ = now;
                }
                return std::chrono::milliseconds(100);
            }
            
        default:
            return std::chrono::milliseconds(1000);
    }
}

LoadPatternGenerator::RequestParams LoadPatternGenerator::generateRequest() {
    RequestParams params;
    
    // Select model
    if (!config_.models.empty()) {
        uint32_t modelIndex = modelDist_(rng_) % config_.models.size();
        params.modelId = config_.models[modelIndex];
    }
    
    // Generate token counts
    params.promptTokens = tokenDist_(rng_);
    params.completionTokens = std::uniform_int_distribution<uint32_t>(
        config_.minCompletionTokens, config_.maxCompletionTokens)(rng_);
    
    return params;
}

// MetricsCollector Implementation
MetricsCollector::MetricsCollector(uint32_t intervalMs)
    : intervalMs_(intervalMs)
    , running_(false)
{
}

MetricsCollector::~MetricsCollector() {
    stop();
}

void MetricsCollector::start() {
    running_ = true;
    collectorThread_ = std::thread(&MetricsCollector::collectionLoop, this);
}

void MetricsCollector::stop() {
    running_ = false;
    if (collectorThread_.joinable()) {
        collectorThread_.join();
    }
}

void MetricsCollector::recordLatency(double latencyMs) {
    std::lock_guard<std::mutex> lock(latenciesMutex_);
    latencies_.push_back(latencyMs);
}

void MetricsCollector::recordThroughput(double rps) {
    // Would record throughput sample
}

void MetricsCollector::recordCacheHit(bool hit) {
    if (hit) {
        cacheHits_++;
    } else {
        cacheMisses_++;
    }
}

void MetricsCollector::recordNodeMetric(const std::string& nodeId, const std::string& metric, double value) {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    auto timestamp = std::chrono::steady_clock::now();
    nodeMetrics_[nodeId][metric].push_back({timestamp, value});
}

std::vector<double> MetricsCollector::getLatencies() const {
    std::lock_guard<std::mutex> lock(latenciesMutex_);
    return latencies_;
}

double MetricsCollector::getAverageLatency() const {
    std::lock_guard<std::mutex> lock(latenciesMutex_);
    if (latencies_.empty()) {
        return 0.0;
    }
    double sum = std::accumulate(latencies_.begin(), latencies_.end(), 0.0);
    return sum / latencies_.size();
}

double MetricsCollector::getPercentileLatency(double percentile) const {
    std::lock_guard<std::mutex> lock(latenciesMutex_);
    if (latencies_.empty()) {
        return 0.0;
    }
    
    std::vector<double> sorted = latencies_;
    std::sort(sorted.begin(), sorted.end());
    
    size_t index = static_cast<size_t>((percentile / 100.0) * sorted.size());
    index = std::min(index, sorted.size() - 1);
    return sorted[index];
}

void MetricsCollector::collectionLoop() {
    while (running_) {
        // Periodic collection would happen here
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs_));
    }
}

void MetricsCollector::reset() {
    std::lock_guard<std::mutex> lock(latenciesMutex_);
    std::lock_guard<std::mutex> metricsLock(metricsMutex_);
    latencies_.clear();
    nodeMetrics_.clear();
    cacheHits_ = 0;
    cacheMisses_ = 0;
}

// FailureInjector Implementation
FailureInjector::FailureInjector(std::shared_ptr<ClusterManager> clusterManager)
    : clusterManager_(clusterManager)
    , running_(false)
{
}

void FailureInjector::configure(float probability, uint32_t intervalSeconds) {
    probability_ = probability;
    intervalSeconds_ = intervalSeconds;
}

void FailureInjector::start() {
    running_ = true;
    injectorThread_ = std::thread(&FailureInjector::injectionLoop, this);
}

void FailureInjector::stop() {
    running_ = false;
    if (injectorThread_.joinable()) {
        injectorThread_.join();
    }
}

void FailureInjector::injectionLoop() {
    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    
    while (running_) {
        if (dist(rng) < probability_) {
            // Inject failure
            auto nodes = clusterManager_->getAllNodes();
            if (!nodes.empty()) {
                std::uniform_int_distribution<size_t> nodeDist(0, nodes.size() - 1);
                auto& node = nodes[nodeDist(rng)];
                
                injectNodeFailure(node.nodeId);
                injectedFailures_++;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds_.load()));
    }
}

bool FailureInjector::injectNodeFailure(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(failedNodesMutex_);
    failedNodes_.insert(nodeId);
    return true;
}

bool FailureInjector::injectNetworkPartition(const std::string& nodeId) {
    return injectNodeFailure(nodeId);
}

bool FailureInjector::injectSlowNode(const std::string& nodeId, uint32_t delayMs) {
    // Would configure network delay
    return true;
}

bool FailureInjector::recoverNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(failedNodesMutex_);
    failedNodes_.erase(nodeId);
    successfulRecoveries_++;
    return true;
}

bool FailureInjector::recoverNetwork(const std::string& nodeId) {
    return recoverNode(nodeId);
}

bool FailureInjector::restoreNodeSpeed(const std::string& nodeId) {
    return true;
}

// DistributedBenchmark Implementation
DistributedBenchmark::DistributedBenchmark(
    std::shared_ptr<ClusterManager> clusterManager,
    std::shared_ptr<DistributedScheduler> scheduler,
    std::shared_ptr<ModelResidencyManager> residencyManager,
    std::shared_ptr<DistributedKVCache> kvCache)
    : initialized_(false)
    , hasBaseline_(false)
    , clusterManager_(clusterManager)
    , scheduler_(scheduler)
    , residencyManager_(residencyManager)
    , kvCache_(kvCache)
    , benchmarkIdCounter_(0)
{
}

DistributedBenchmark::~DistributedBenchmark() {
    shutdown();
}

bool DistributedBenchmark::initialize() {
    if (initialized_) {
        return true;
    }
    
    metricsCollector_ = std::make_unique<MetricsCollector>(1000);
    failureInjector_ = std::make_unique<FailureInjector>(clusterManager_);
    
    initialized_ = true;
    return true;
}

bool DistributedBenchmark::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    // Stop all benchmarks
    for (auto& pair : activeBenchmarks_) {
        stopBenchmark(pair.first);
    }
    
    metricsCollector_.reset();
    failureInjector_.reset();
    
    initialized_ = false;
    return true;
}

std::string DistributedBenchmark::startBenchmark(const BenchmarkConfig& config) {
    if (!initialized_) {
        return "";
    }
    
    std::string benchmarkId = generateBenchmarkId();
    
    auto benchmark = std::make_unique<ActiveBenchmark>();
    benchmark->id = benchmarkId;
    benchmark->config = config;
    benchmark->state = BenchmarkState::PENDING;
    benchmark->startTime = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(benchmarksMutex_);
        activeBenchmarks_[benchmarkId] = std::move(benchmark);
    }
    
    // Start benchmark thread
    std::thread benchmarkThread(&DistributedBenchmark::benchmarkLoop, this, benchmarkId, config);
    
    {
        std::lock_guard<std::mutex> lock(benchmarksMutex_);
        activeBenchmarks_[benchmarkId]->workerThreads.push_back(std::move(benchmarkThread));
    }
    
    return benchmarkId;
}

bool DistributedBenchmark::stopBenchmark(const std::string& benchmarkId) {
    std::lock_guard<std::mutex> lock(benchmarksMutex_);
    
    auto it = activeBenchmarks_.find(benchmarkId);
    if (it == activeBenchmarks_.end()) {
        return false;
    }
    
    it->second->cancelled = true;
    
    // Wait for threads to complete
    for (auto& thread : it->second->workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    return true;
}

bool DistributedBenchmark::pauseBenchmark(const std::string& benchmarkId) {
    std::lock_guard<std::mutex> lock(benchmarksMutex_);
    
    auto it = activeBenchmarks_.find(benchmarkId);
    if (it == activeBenchmarks_.end()) {
        return false;
    }
    
    it->second->paused = true;
    return true;
}

bool DistributedBenchmark::resumeBenchmark(const std::string& benchmarkId) {
    std::lock_guard<std::mutex> lock(benchmarksMutex_);
    
    auto it = activeBenchmarks_.find(benchmarkId);
    if (it == activeBenchmarks_.end()) {
        return false;
    }
    
    it->second->paused = false;
    return true;
}

DistributedBenchmark::BenchmarkState DistributedBenchmark::getBenchmarkState(
    const std::string& benchmarkId) const {
    std::lock_guard<std::mutex> lock(benchmarksMutex_);
    
    auto it = activeBenchmarks_.find(benchmarkId);
    if (it != activeBenchmarks_.end()) {
        return it->second->state;
    }
    
    return BenchmarkState::FAILED;
}

float DistributedBenchmark::getBenchmarkProgress(const std::string& benchmarkId) const {
    std::lock_guard<std::mutex> lock(benchmarksMutex_);
    
    auto it = activeBenchmarks_.find(benchmarkId);
    if (it != activeBenchmarks_.end()) {
        return it->second->progress.load();
    }
    
    return 0.0f;
}

BenchmarkResult DistributedBenchmark::getResult(const std::string& benchmarkId) const {
    std::lock_guard<std::mutex> lock(resultsMutex_);
    
    auto it = results_.find(benchmarkId);
    if (it != results_.end()) {
        return it->second;
    }
    
    return BenchmarkResult();
}

std::vector<BenchmarkResult> DistributedBenchmark::getAllResults() const {
    std::lock_guard<std::mutex> lock(resultsMutex_);
    
    std::vector<BenchmarkResult> results;
    for (const auto& pair : results_) {
        results.push_back(pair.second);
    }
    return results;
}

bool DistributedBenchmark::exportResults(const std::string& benchmarkId, const std::string& filePath) {
    auto result = getResult(benchmarkId);
    if (result.benchmarkId.empty()) {
        return false;
    }
    
    std::ofstream file(filePath);
    if (!file.is_open()) {
        return false;
    }
    
    // Write JSON results
    file << "{\n";
    file << "  \"benchmarkId\": \"" << result.benchmarkId << "\",\n";
    file << "  \"completed\": " << (result.completed ? "true" : "false") << ",\n";
    file << "  \"totalRequests\": " << result.totalRequests << ",\n";
    file << "  \"successfulRequests\": " << result.successfulRequests << ",\n";
    file << "  \"requestsPerSecond\": " << result.requestsPerSecond << ",\n";
    file << "  \"meanLatencyMs\": " << result.meanLatencyMs << ",\n";
    file << "  \"p95LatencyMs\": " << result.p95LatencyMs << ",\n";
    file << "  \"p99LatencyMs\": " << result.p99LatencyMs << "\n";
    file << "}\n";
    
    return true;
}

// Scaling tests
std::string DistributedBenchmark::startScalingTest(const ScalingTestConfig& config) {
    // Would run benchmarks at different node counts
    return "";
}

ScalingTestResult DistributedBenchmark::getScalingResult(const std::string& testId) const {
    // Would return scaling analysis
    return ScalingTestResult();
}

// Comparison
DistributedBenchmark::ComparisonResult DistributedBenchmark::compareResults(
    const std::string& baselineId, const std::string& comparisonId) const {
    
    ComparisonResult result;
    result.baselineId = baselineId;
    result.comparisonId = comparisonId;
    
    auto baseline = getResult(baselineId);
    auto comparison = getResult(comparisonId);
    
    if (baseline.benchmarkId.empty() || comparison.benchmarkId.empty()) {
        result.recommendation = "Invalid benchmark IDs";
        return result;
    }
    
    // Calculate changes
    result.latencyChangePercent = ((comparison.meanLatencyMs - baseline.meanLatencyMs) / 
                                   baseline.meanLatencyMs) * 100.0;
    result.throughputChangePercent = ((comparison.requestsPerSecond - baseline.requestsPerSecond) / 
                                    baseline.requestsPerSecond) * 100.0;
    result.efficiencyChangePercent = ((comparison.efficiency - baseline.efficiency) / 
                                     baseline.efficiency) * 100.0;
    
    // Determine if regression
    result.isRegression = result.latencyChangePercent > 10.0 || 
                         result.throughputChangePercent < -10.0;
    
    // Generate recommendation
    if (result.isRegression) {
        result.recommendation = "Performance regression detected. Review changes.";
    } else {
        result.recommendation = "Performance improved or maintained.";
    }
    
    return result;
}

// Baseline management
bool DistributedBenchmark::setBaseline(const std::string& benchmarkId) {
    auto result = getResult(benchmarkId);
    if (result.benchmarkId.empty()) {
        return false;
    }
    
    baselineId_ = benchmarkId;
    hasBaseline_ = true;
    return true;
}

BenchmarkResult DistributedBenchmark::getBaseline() const {
    if (!hasBaseline_) {
        return BenchmarkResult();
    }
    return getResult(baselineId_);
}

// Predefined benchmarks
BenchmarkConfig DistributedBenchmark::createThroughputBenchmark() {
    BenchmarkConfig config;
    config.type = BenchmarkType::THROUGHPUT;
    config.name = "Throughput Test";
    config.description = "Maximum requests per second";
    config.durationSeconds = 300;
    config.concurrentClients = 100;
    config.requestsPerSecond = 0; // Unlimited
    return config;
}

BenchmarkConfig DistributedBenchmark::createLatencyBenchmark() {
    BenchmarkConfig config;
    config.type = BenchmarkType::LATENCY;
    config.name = "Latency Test";
    config.description = "Response time under load";
    config.durationSeconds = 300;
    config.concurrentClients = 50;
    config.requestsPerSecond = 10;
    return config;
}

BenchmarkConfig DistributedBenchmark::createScalabilityBenchmark() {
    BenchmarkConfig config;
    config.type = BenchmarkType::SCALABILITY;
    config.name = "Scalability Test";
    config.description = "Performance vs node count";
    config.durationSeconds = 60;
    config.concurrentClients = 100;
    return config;
}

BenchmarkConfig DistributedBenchmark::createFailoverBenchmark() {
    BenchmarkConfig config;
    config.type = BenchmarkType::FAILOVER;
    config.name = "Failover Test";
    config.description = "Recovery time during failures";
    config.durationSeconds = 300;
    config.concurrentClients = 50;
    config.enableFailureInjection = true;
    config.failureIntervalSeconds = 60;
    config.failureProbability = 0.1f;
    return config;
}

BenchmarkConfig DistributedBenchmark::createCacheEfficiencyBenchmark() {
    BenchmarkConfig config;
    config.type = BenchmarkType::MEMORY_EFFICIENCY;
    config.name = "Cache Efficiency Test";
    config.description = "Cache hit rates and memory usage";
    config.durationSeconds = 300;
    config.concurrentClients = 50;
    config.collectCacheMetrics = true;
    return config;
}

BenchmarkConfig DistributedBenchmark::createEndToEndBenchmark() {
    BenchmarkConfig config;
    config.type = BenchmarkType::END_TO_END;
    config.name = "End-to-End Test";
    config.description = "Full pipeline performance";
    config.durationSeconds = 600;
    config.concurrentClients = 100;
    config.collectPerNodeMetrics = true;
    config.collectCacheMetrics = true;
    return config;
}

// Quick tests
BenchmarkResult DistributedBenchmark::runQuickSmokeTest() {
    BenchmarkConfig config;
    config.type = BenchmarkType::THROUGHPUT;
    config.name = "Smoke Test";
    config.durationSeconds = 30;
    config.concurrentClients = 10;
    config.totalRequests = 100;
    
    std::string id = startBenchmark(config);
    
    // Wait for completion
    while (getBenchmarkState(id) == BenchmarkState::RUNNING ||
           getBenchmarkState(id) == BenchmarkState::WARMUP) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return getResult(id);
}

BenchmarkResult DistributedBenchmark::runLoadTest(uint32_t durationSeconds, uint32_t rps) {
    BenchmarkConfig config;
    config.type = BenchmarkType::THROUGHPUT;
    config.name = "Load Test";
    config.durationSeconds = durationSeconds;
    config.requestsPerSecond = rps;
    config.concurrentClients = 50;
    
    std::string id = startBenchmark(config);
    
    while (getBenchmarkState(id) == BenchmarkState::RUNNING) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return getResult(id);
}

BenchmarkResult DistributedBenchmark::runStressTest(uint32_t durationSeconds) {
    BenchmarkConfig config;
    config.type = BenchmarkType::THROUGHPUT;
    config.name = "Stress Test";
    config.durationSeconds = durationSeconds;
    config.concurrentClients = 200;
    config.requestsPerSecond = 0; // Unlimited
    
    std::string id = startBenchmark(config);
    
    while (getBenchmarkState(id) == BenchmarkState::RUNNING) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return getResult(id);
}

// Reporting
std::string DistributedBenchmark::generateReport(const std::string& benchmarkId) {
    auto result = getResult(benchmarkId);
    if (result.benchmarkId.empty()) {
        return "Benchmark not found";
    }
    
    std::stringstream report;
    report << "# Benchmark Report: " << result.config.name << "\n\n";
    report << "## Summary\n\n";
    report << "- **Status**: " << (result.completed ? "Completed" : "Failed") << "\n";
    report << "- **Total Requests**: " << result.totalRequests << "\n";
    report << "- **Successful**: " << result.successfulRequests << "\n";
    report << "- **Failed**: " << result.failedRequests << "\n";
    report << "- **Throughput**: " << std::fixed << std::setprecision(2) << result.requestsPerSecond << " req/s\n\n";
    
    report << "## Latency Statistics\n\n";
    report << "| Metric | Value (ms) |\n";
    report << "|--------|------------|\n";
    report << "| Min | " << result.minLatencyMs << " |\n";
    report << "| Mean | " << result.meanLatencyMs << " |\n";
    report << "| Median | " << result.medianLatencyMs << " |\n";
    report << "| P95 | " << result.p95LatencyMs << " |\n";
    report << "| P99 | " << result.p99LatencyMs << " |\n";
    report << "| Max | " << result.maxLatencyMs << " |\n\n";
    
    return report.str();
}

std::string DistributedBenchmark::generateComparisonReport(const std::string& baselineId,
                                                             const std::string& comparisonId) {
    auto comparison = compareResults(baselineId, comparisonId);
    
    std::stringstream report;
    report << "# Performance Comparison Report\n\n";
    report << "## Changes\n\n";
    report << "| Metric | Change |\n";
    report << "|--------|--------|\n";
    report << "| Latency | " << std::showpos << std::fixed << std::setprecision(2) 
          << comparison.latencyChangePercent << "% |\n";
    report << "| Throughput | " << comparison.throughputChangePercent << "% |\n";
    report << "| Efficiency | " << comparison.efficiencyChangePercent << "% |\n\n";
    
    report << "## Recommendation\n\n";
    report << comparison.recommendation << "\n";
    
    return report.str();
}

// Internal methods
void DistributedBenchmark::benchmarkLoop(const std::string& benchmarkId, const BenchmarkConfig& config) {
    // Warmup phase
    warmupPhase(benchmarkId, config);
    
    // Run phase
    runPhase(benchmarkId, config);
    
    // Cooldown phase
    cooldownPhase(benchmarkId, config);
    
    // Calculate results
    calculateResults(benchmarkId);
}

void DistributedBenchmark::warmupPhase(const std::string& benchmarkId, const BenchmarkConfig& config) {
    {
        std::lock_guard<std::mutex> lock(benchmarksMutex_);
        auto it = activeBenchmarks_.find(benchmarkId);
        if (it != activeBenchmarks_.end()) {
            it->second->state = BenchmarkState::WARMUP;
        }
    }
    
    // Run warmup
    std::this_thread::sleep_for(std::chrono::seconds(config.warmupSeconds));
}

void DistributedBenchmark::runPhase(const std::string& benchmarkId, const BenchmarkConfig& config) {
    {
        std::lock_guard<std::mutex> lock(benchmarksMutex_);
        auto it = activeBenchmarks_.find(benchmarkId);
        if (it != activeBenchmarks_.end()) {
            it->second->state = BenchmarkState::RUNNING;
        }
    }
    
    // Start failure injection if enabled
    if (config.enableFailureInjection) {
        failureInjector_->configure(config.failureProbability, config.failureIntervalSeconds);
        failureInjector_->start();
    }
    
    // Start metrics collection
    metricsCollector_->start();
    
    // Create load generator
    LoadPatternGenerator generator(config);
    
    // Run load
    auto startTime = std::chrono::steady_clock::now();
    uint64_t requestsSent = 0;
    
    while (true) {
        // Check if should stop
        {
            std::lock_guard<std::mutex> lock(benchmarksMutex_);
            auto it = activeBenchmarks_.find(benchmarkId);
            if (it == activeBenchmarks_.end() || it->second->cancelled) {
                break;
            }
            if (it->second->paused) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
        }
        
        // Check duration
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime).count();
        if (elapsed >= config.durationSeconds) {
            break;
        }
        
        // Check request limit
        if (config.totalRequests > 0 && requestsSent >= config.totalRequests) {
            break;
        }
        
        // Generate and execute request
        auto params = generator.generateRequest();
        
        TaskSpec task;
        task.type = TaskType::INFERENCE;
        task.modelId = params.modelId;
        task.payloadSize = params.promptTokens * sizeof(float);
        
        auto start = std::chrono::steady_clock::now();
        
        // Submit task
        auto future = scheduler_->submitTask(task);
        
        // Wait for completion (simplified)
        if (future.wait_for(std::chrono::seconds(30)) == std::future_status::ready) {
            auto result = future.get();
            auto end = std::chrono::steady_clock::now();
            auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            
            metricsCollector_->recordLatency(static_cast<double>(latency));
        }
        
        requestsSent++;
        
        // Update progress
        float progress = static_cast<float>(elapsed) / config.durationSeconds;
        {
            std::lock_guard<std::mutex> lock(benchmarksMutex_);
            auto it = activeBenchmarks_.find(benchmarkId);
            if (it != activeBenchmarks_.end()) {
                it->second->progress = progress;
            }
        }
        
        // Rate limiting
        auto delay = generator.getNextDelay();
        if (delay > std::chrono::milliseconds(0)) {
            std::this_thread::sleep_for(delay);
        }
    }
    
    // Stop failure injection
    if (config.enableFailureInjection) {
        failureInjector_->stop();
    }
    
    // Stop metrics collection
    metricsCollector_->stop();
}

void DistributedBenchmark::cooldownPhase(const std::string& benchmarkId, const BenchmarkConfig& config) {
    {
        std::lock_guard<std::mutex> lock(benchmarksMutex_);
        auto it = activeBenchmarks_.find(benchmarkId);
        if (it != activeBenchmarks_.end()) {
            it->second->state = BenchmarkState::COOLDOWN;
        }
    }
    
    std::this_thread::sleep_for(std::chrono::seconds(config.cooldownSeconds));
}

void DistributedBenchmark::executeRequest(const std::string& benchmarkId, 
                                          const LoadPatternGenerator::RequestParams& params) {
    // Request execution is handled in runPhase
}

void DistributedBenchmark::completeTask(const std::string& taskId, const ExecutionResult& result) {
    // Task completion is handled by scheduler
}

void DistributedBenchmark::failTask(const std::string& taskId, const std::string& error) {
    // Task failure is handled by scheduler
}

void DistributedBenchmark::calculateResults(const std::string& benchmarkId) {
    BenchmarkResult result;
    result.benchmarkId = benchmarkId;
    result.completed = true;
    result.completedAt = std::chrono::steady_clock::now();
    
    // Get collected metrics
    auto latencies = metricsCollector_->getLatencies();
    
    result.totalRequests = latencies.size();
    result.successfulRequests = latencies.size(); // Simplified
    
    if (!latencies.empty()) {
        result.minLatencyMs = *std::min_element(latencies.begin(), latencies.end());
        result.maxLatencyMs = *std::max_element(latencies.begin(), latencies.end());
        result.meanLatencyMs = metricsCollector_->getAverageLatency();
        result.medianLatencyMs = metricsCollector_->getPercentileLatency(50.0);
        result.p50LatencyMs = result.medianLatencyMs;
        result.p95LatencyMs = metricsCollector_->getPercentileLatency(95.0);
        result.p99LatencyMs = metricsCollector_->getPercentileLatency(99.0);
        result.p999LatencyMs = metricsCollector_->getPercentileLatency(99.9);
        
        // Calculate standard deviation
        double sum = std::accumulate(latencies.begin(), latencies.end(), 0.0);
        double mean = sum / latencies.size();
        double sq_sum = std::inner_product(latencies.begin(), latencies.end(), 
                                           latencies.begin(), 0.0);
        result.stdDevLatencyMs = std::sqrt(sq_sum / latencies.size() - mean * mean);
    }
    
    // Calculate throughput
    auto activeBenchmark = activeBenchmarks_.find(benchmarkId);
    if (activeBenchmark != activeBenchmarks_.end()) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            result.completedAt - activeBenchmark->second->startTime).count();
        if (duration > 0) {
            result.requestsPerSecond = static_cast<double>(result.totalRequests) / duration;
        }
    }
    
    // Store results
    {
        std::lock_guard<std::mutex> lock(resultsMutex_);
        results_[benchmarkId] = result;
    }
    
    // Update benchmark state
    {
        std::lock_guard<std::mutex> lock(benchmarksMutex_);
        auto it = activeBenchmarks_.find(benchmarkId);
        if (it != activeBenchmarks_.end()) {
            it->second->state = BenchmarkState::COMPLETED;
            it->second->progress = 1.0f;
        }
    }
}

void DistributedBenchmark::calculatePercentiles(BenchmarkResult& result) {
    // Percentiles are calculated in calculateResults
}

void DistributedBenchmark::calculateScalabilityMetrics(BenchmarkResult& result) {
    // Would calculate speedup and efficiency
    auto nodes = clusterManager_->getAllNodes();
    uint32_t nodeCount = static_cast<uint32_t>(nodes.size());
    
    if (nodeCount > 0) {
        result.tokensPerSecondPerNode = result.tokensPerSecond / nodeCount;
    }
}

std::string DistributedBenchmark::generateBenchmarkId() {
    uint64_t id = benchmarkIdCounter_.fetch_add(1);
    
    std::stringstream ss;
    ss << "bench-" << std::hex << std::setw(16) << std::setfill('0') << id;
    return ss.str();
}

} // namespace Distributed
} // namespace RawrXD
