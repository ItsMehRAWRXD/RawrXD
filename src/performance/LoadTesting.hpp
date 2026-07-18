/**
 * LoadTesting.hpp
 *
 * Phase H Batch 4/5: Load Testing & Stress Testing
 *
 * Comprehensive load testing with configurable load patterns,
 * resource exhaustion testing, and chaos engineering.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>
#include <atomic>
#include <random>

namespace Performance {

// ============================================================================
// Forward Declarations
// ============================================================================

class LoadPattern;
class LoadGenerator;
class LoadTestScenario;
class LoadTestRunner;

// ============================================================================
// Load Pattern Types
// ============================================================================

enum class LoadPatternType {
    CONSTANT,       // Constant load
    RAMP_UP,        // Gradually increasing load
    RAMP_DOWN,      // Gradually decreasing load
    SPIKE,          // Sudden spike in load
    STRESS,         // Stress test pattern
    SOAK,           // Long-duration constant load
    WAVE,           // Oscillating load
    RANDOM,         // Random load variations
    CUSTOM          // User-defined pattern
};

// ============================================================================
// Load Configuration
// ============================================================================

/**
 * Configuration for load generation.
 */
struct LoadConfig {
    // Concurrency
    uint32_t virtualUsers = 100;
    uint32_t rampUpSeconds = 60;
    uint32_t durationSeconds = 300;
    uint32_t rampDownSeconds = 30;
    
    // Throughput
    double targetThroughput = 1000.0;  // requests/sec
    double maxThroughput = 10000.0;
    
    // Timing
    uint32_t thinkTimeMinMs = 100;
    uint32_t thinkTimeMaxMs = 500;
    std::string thinkTimeDistribution = "uniform";  // uniform, exponential, normal
    
    // Failure handling
    uint32_t maxErrors = 100;
    double errorThreshold = 0.05;  // 5% error rate threshold
    bool stopOnErrorThreshold = false;
    
    // Resource limits
    uint64_t maxMemoryMB = 8192;
    double maxCpuPercent = 90.0;
    uint32_t maxConnections = 1000;
};

// ============================================================================
// Load Pattern
// ============================================================================

/**
 * Defines how load varies over time.
 */
class LoadPattern {
public:
    virtual ~LoadPattern() = default;
    
    virtual LoadPatternType GetType() const = 0;
    virtual std::string GetName() const = 0;
    
    // Get target load at specific time
    virtual uint32_t GetTargetUsers(uint32_t elapsedSeconds) const = 0;
    virtual double GetTargetThroughput(uint32_t elapsedSeconds) const = 0;
    
    // Pattern duration
    virtual uint32_t GetDurationSeconds() const = 0;
};

/**
 * Constant load pattern.
 */
class ConstantLoadPattern : public LoadPattern {
public:
    ConstantLoadPattern(uint32_t users, double throughput, uint32_t duration);
    
    LoadPatternType GetType() const override { return LoadPatternType::CONSTANT; }
    std::string GetName() const override { return "Constant"; }
    uint32_t GetTargetUsers(uint32_t elapsedSeconds) const override;
    double GetTargetThroughput(uint32_t elapsedSeconds) const override;
    uint32_t GetDurationSeconds() const override;
    
private:
    uint32_t users_;
    double throughput_;
    uint32_t duration_;
};

/**
 * Ramp up pattern.
 */
class RampUpPattern : public LoadPattern {
public:
    RampUpPattern(uint32_t startUsers, uint32_t endUsers, 
                  uint32_t rampDuration, uint32_t holdDuration);
    
    LoadPatternType GetType() const override { return LoadPatternType::RAMP_UP; }
    std::string GetName() const override { return "RampUp"; }
    uint32_t GetTargetUsers(uint32_t elapsedSeconds) const override;
    double GetTargetThroughput(uint32_t elapsedSeconds) const override;
    uint32_t GetDurationSeconds() const override;
    
private:
    uint32_t startUsers_;
    uint32_t endUsers_;
    uint32_t rampDuration_;
    uint32_t holdDuration_;
};

/**
 * Spike pattern.
 */
class SpikePattern : public LoadPattern {
public:
    SpikePattern(uint32_t baselineUsers, uint32_t spikeUsers,
                 uint32_t spikeDuration, uint32_t baselineDuration);
    
    LoadPatternType GetType() const override { return LoadPatternType::SPIKE; }
    std::string GetName() const override { return "Spike"; }
    uint32_t GetTargetUsers(uint32_t elapsedSeconds) const override;
    double GetTargetThroughput(uint32_t elapsedSeconds) const override;
    uint32_t GetDurationSeconds() const override;
    
private:
    uint32_t baselineUsers_;
    uint32_t spikeUsers_;
    uint32_t spikeDuration_;
    uint32_t baselineDuration_;
    uint32_t totalDuration_;
};

/**
 * Wave pattern.
 */
class WavePattern : public LoadPattern {
public:
    WavePattern(uint32_t minUsers, uint32_t maxUsers, 
                uint32_t periodSeconds, uint32_t cycles);
    
    LoadPatternType GetType() const override { return LoadPatternType::WAVE; }
    std::string GetName() const override { return "Wave"; }
    uint32_t GetTargetUsers(uint32_t elapsedSeconds) const override;
    double GetTargetThroughput(uint32_t elapsedSeconds) const override;
    uint32_t GetDurationSeconds() const override;
    
private:
    uint32_t minUsers_;
    uint32_t maxUsers_;
    uint32_t periodSeconds_;
    uint32_t cycles_;
};

// ============================================================================
// Virtual User
// ============================================================================

/**
 * Simulated user for load testing.
 */
class VirtualUser {
public:
    using ActionFunc = std::function<bool(VirtualUser*)>;
    using SetupFunc = std::function<void(VirtualUser*)>;
    using TeardownFunc = std::function<void(VirtualUser*)>;
    
    VirtualUser(uint32_t id, const LoadConfig& config);
    
    // Lifecycle
    void Setup();
    void Execute(ActionFunc action);
    void Teardown();
    
    // State
    bool IsActive() const { return active_; }
    void Deactivate() { active_ = false; }
    
    // Metrics
    uint64_t GetRequestCount() const { return requestCount_; }
    uint64_t GetErrorCount() const { return errorCount_; }
    double GetAverageResponseTimeMs() const;
    
    // Session data
    void SetSessionData(const std::string& key, const std::string& value);
    std::string GetSessionData(const std::string& key) const;
    
    // Think time
    void Think();
    
private:
    uint32_t id_;
    LoadConfig config_;
    std::atomic<bool> active_{true};
    
    std::atomic<uint64_t> requestCount_{0};
    std::atomic<uint64_t> errorCount_{0};
    std::atomic<uint64_t> totalResponseTimeMs_{0};
    
    std::map<std::string, std::string> sessionData_;
    mutable std::mutex sessionMutex_;
    
    std::mt19937 rng_;
};

// ============================================================================
// Load Generator
// ============================================================================

/**
 * Generates load using virtual users.
 */
class LoadGenerator {
public:
    struct Metrics {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        double requestsPerSecond;
        double averageResponseTimeMs;
        double p50ResponseTimeMs;
        double p95ResponseTimeMs;
        double p99ResponseTimeMs;
        double errorRate;
        uint32_t activeUsers;
        uint32_t targetUsers;
    };
    
    explicit LoadGenerator(const LoadConfig& config);
    ~LoadGenerator();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Set action
    void SetAction(VirtualUser::ActionFunc action);
    void SetSetup(VirtualUser::SetupFunc setup);
    void SetTeardown(VirtualUser::TeardownFunc teardown);
    
    // Execute pattern
    void ExecutePattern(const LoadPattern& pattern);
    
    // Control
    void Start();
    void Stop();
    void Pause();
    void Resume();
    void AdjustLoad(uint32_t targetUsers);
    
    // Metrics
    Metrics GetCurrentMetrics() const;
    std::vector<Metrics> GetMetricsHistory() const;
    
    // Status
    bool IsRunning() const { return running_; }
    bool IsPaused() const { return paused_; }
    
private:
    LoadConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> stopRequested_{false};
    
    VirtualUser::ActionFunc action_;
    VirtualUser::SetupFunc setup_;
    VirtualUser::TeardownFunc teardown_;
    
    std::vector<std::unique_ptr<VirtualUser>> users_;
    std::vector<std::thread> userThreads_;
    
    std::vector<Metrics> metricsHistory_;
    mutable std::mutex metricsMutex_;
    
    void UserLoop(VirtualUser* user);
    void MetricsCollectorLoop();
    std::thread metricsThread_;
};

// ============================================================================
// Load Test Result
// ============================================================================

/**
 * Result of a load test.
 */
struct LoadTestResult {
    std::string scenarioName;
    LoadPatternType patternType;
    
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    uint64_t durationSeconds;
    
    // Aggregate metrics
    uint64_t totalRequests;
    uint64_t successfulRequests;
    uint64_t failedRequests;
    double averageRequestsPerSecond;
    double peakRequestsPerSecond;
    
    // Response times
    double averageResponseTimeMs;
    double minResponseTimeMs;
    double maxResponseTimeMs;
    double p50ResponseTimeMs;
    double p95ResponseTimeMs;
    double p99ResponseTimeMs;
    
    // Error analysis
    double errorRate;
    std::map<std::string, uint64_t> errorTypes;
    
    // Resource usage
    double averageCpuPercent;
    double peakCpuPercent;
    uint64_t averageMemoryMB;
    uint64_t peakMemoryMB;
    
    // Time series data
    std::vector<std::pair<uint64_t, double>> responseTimeSeries;
    std::vector<std::pair<uint64_t, double>> throughputTimeSeries;
    std::vector<std::pair<uint64_t, uint32_t>> userCountTimeSeries;
    
    // Success criteria
    bool passed;
    std::vector<std::string> failures;
    
    std::string ToJson() const;
};

// ============================================================================
// Load Test Scenario
// ============================================================================

/**
 * Defines a load test scenario.
 */
class LoadTestScenario {
public:
    struct SuccessCriteria {
        double maxAverageResponseTimeMs = 1000.0;
        double maxP95ResponseTimeMs = 2000.0;
        double maxErrorRate = 0.05;
        double minThroughput = 100.0;
        double maxCpuPercent = 80.0;
        double maxMemoryMB = 4096.0;
    };
    
    LoadTestScenario(const std::string& name, const std::string& description);
    
    // Configuration
    void SetLoadConfig(const LoadConfig& config);
    void SetPattern(std::unique_ptr<LoadPattern> pattern);
    void SetSuccessCriteria(const SuccessCriteria& criteria);
    
    // Actions
    void SetAction(VirtualUser::ActionFunc action);
    void SetSetup(VirtualUser::SetupFunc setup);
    void SetTeardown(VirtualUser::TeardownFunc teardown);
    
    // Accessors
    std::string GetName() const { return name_; }
    std::string GetDescription() const { return description_; }
    LoadConfig GetLoadConfig() const { return loadConfig_; }
    LoadPattern* GetPattern() const { return pattern_.get(); }
    SuccessCriteria GetSuccessCriteria() const { return successCriteria_; }
    
    VirtualUser::ActionFunc GetAction() const { return action_; }
    VirtualUser::SetupFunc GetSetup() const { return setup_; }
    VirtualUser::TeardownFunc GetTeardown() const { return teardown_; }
    
private:
    std::string name_;
    std::string description_;
    LoadConfig loadConfig_;
    std::unique_ptr<LoadPattern> pattern_;
    SuccessCriteria successCriteria_;
    
    VirtualUser::ActionFunc action_;
    VirtualUser::SetupFunc setup_;
    VirtualUser::TeardownFunc teardown_;
};

// ============================================================================
// Load Test Runner
// ============================================================================

/**
 * Executes load test scenarios.
 */
class LoadTestRunner {
public:
    struct Config {
        bool collectResourceMetrics = true;
        uint32_t metricsIntervalMs = 1000;
        bool saveRawData = false;
        std::string outputDirectory = "./load_test_results";
    };
    
    explicit LoadTestRunner(const Config& config = Config{});
    ~LoadTestRunner();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Execute scenario
    LoadTestResult RunScenario(LoadTestScenario& scenario);
    
    // Execute multiple scenarios
    std::vector<LoadTestResult> RunScenarios(
        const std::vector<std::shared_ptr<LoadTestScenario>>& scenarios);
    
    // Progress callback
    using ProgressCallback = std::function<void(const std::string& scenario,
                                                 uint32_t elapsedSeconds,
                                                 uint32_t totalSeconds,
                                                 const LoadGenerator::Metrics& metrics)>;
    void SetProgressCallback(ProgressCallback callback);
    
    // Results
    std::vector<LoadTestResult> GetResults() const;
    void ExportResults(const std::string& filepath) const;
    
private:
    Config config_;
    ProgressCallback progressCallback_;
    std::vector<LoadTestResult> results_;
    mutable std::mutex resultsMutex_;
    
    void CollectResourceMetrics(LoadTestResult& result);
    bool CheckSuccessCriteria(const LoadTestResult& result,
                              const LoadTestScenario::SuccessCriteria& criteria);
};

// ============================================================================
// Stress Testing
// ============================================================================

/**
 * Resource exhaustion and stress testing.
 */
class StressTester {
public:
    enum class StressType {
        CPU,            // CPU exhaustion
        MEMORY,         // Memory exhaustion
        DISK,           // Disk I/O exhaustion
        NETWORK,        // Network exhaustion
        HANDLES,        // Handle exhaustion
        THREADS,        // Thread exhaustion
        CONNECTIONS     // Connection exhaustion
    };
    
    struct StressConfig {
        StressType type;
        uint64_t targetResource;
        uint64_t stepSize;
        uint32_t stepDurationSeconds;
        uint32_t maxDurationSeconds;
        bool recoverAfterTest;
    };
    
    struct StressResult {
        bool success;
        std::string errorMessage;
        
        uint64_t maxResourceAchieved;
        uint64_t targetResource;
        double resourceUtilizationPercent;
        
        uint64_t durationSeconds;
        bool systemRecovered;
        uint64_t recoveryTimeMs;
        
        std::vector<std::pair<uint64_t, uint64_t>> resourceTimeline;
    };
    
    explicit StressTester(const StressConfig& config);
    ~StressTester();
    
    // Stress tests
    StressResult RunCpuStress(uint32_t threads, uint64_t durationSeconds);
    StressResult RunMemoryStress(uint64_t targetMB, uint64_t stepMB);
    StressResult RunDiskStress(const std::string& path, uint64_t targetMBps);
    StressResult RunNetworkStress(const std::string& target, uint32_t connections);
    
    // Combined stress
    StressResult RunCombinedStress(const std::vector<StressConfig>& configs);
    
    // Monitoring
    void StartMonitoring();
    void StopMonitoring();
    std::map<std::string, double> GetCurrentResourceUsage() const;
    
private:
    StressConfig config_;
    std::atomic<bool> monitoring_{false};
    std::thread monitorThread_;
    
    void MonitorLoop();
    bool CheckSystemHealth();
    bool WaitForRecovery(uint64_t timeoutMs);
};

// ============================================================================
// Chaos Engineering
// ============================================================================

/**
 * Chaos engineering for resilience testing.
 */
class ChaosEngineering {
public:
    enum class FailureType {
        NETWORK_LATENCY,        // Add network latency
        NETWORK_PACKET_LOSS,    // Drop packets
        NETWORK_PARTITION,      // Partition network
        CPU_SPIKE,              // Spike CPU usage
        MEMORY_PRESSURE,        // Consume memory
        DISK_FILL,              // Fill disk
        PROCESS_KILL,           // Kill process
        SERVICE_RESTART,        // Restart service
        CLOCK_SKEW,             // Skew system clock
        DNS_FAILURE             // DNS resolution failure
    };
    
    struct ChaosExperiment {
        std::string name;
        std::string description;
        std::vector<FailureType> failures;
        uint32_t durationSeconds;
        uint32_t rampUpSeconds;
        uint32_t rollbackSeconds;
        std::map<std::string, std::string> parameters;
    };
    
    struct ChaosResult {
        std::string experimentName;
        bool success;
        std::string errorMessage;
        
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
        
        std::vector<std::string> failuresInjected;
        std::vector<std::string> systemResponses;
        
        bool systemRecovered;
        uint64_t recoveryTimeMs;
        
        std::map<std::string, std::string> observations;
    };
    
    ChaosEngineering();
    ~ChaosEngineering();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Experiments
    ChaosResult RunExperiment(const ChaosExperiment& experiment);
    
    // Individual failures
    bool InjectNetworkLatency(uint32_t latencyMs, double jitterPercent);
    bool InjectPacketLoss(double lossPercent);
    bool InjectCpuSpike(uint32_t targetPercent, uint32_t durationSeconds);
    bool InjectMemoryPressure(uint64_t targetMB);
    
    // Rollback
    bool RollbackAll();
    bool Rollback(FailureType type);
    
    // Safety
    void SetSafetyChecks(bool enabled);
    void AddAbortCondition(std::function<bool()> condition);
    
private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> safetyChecks_{true};
    std::vector<std::function<bool()>> abortConditions_;
    std::map<FailureType, bool> activeFailures_;
    mutable std::mutex failuresMutex_;
    
    bool ShouldAbort() const;
    void RecordFailure(FailureType type);
    void ClearFailure(FailureType type);
};

} // namespace Performance
