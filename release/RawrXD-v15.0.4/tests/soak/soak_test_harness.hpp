#pragma once
/**
 * RawrXD Phase 7A: 24-Hour Soak Test Harness
 * Production-grade stability validation for sovereign inference runtime
 */

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <atomic>
#include <memory>
#include <functional>
#include <fstream>
#include <mutex>

// Forward declarations for DX12 integration
struct ID3D12Device;
struct ID3D12Resource;

namespace RawrXD {
namespace SoakTest {

// =============================================================================
// CONFIGURATION
// =============================================================================

struct SoakConfig {
    // Test duration
    uint32_t durationHours = 24;
    uint32_t warmupMinutes = 5;
    
    // Sampling intervals
    uint32_t healthCheckIntervalSec = 60;
    uint32_t telemetrySnapshotIntervalSec = 300;
    uint32_t residencyProbeIntervalSec = 30;
    
    // TPS drift detection
    double tpsBaselineWindowMinutes = 10.0;
    double tpsVarianceThresholdPercent = 5.0;
    double tpsDegradationThresholdPercent = 10.0;
    
    // Memory thresholds
    uint64_t maxHeapGrowthBytes = 512 * 1024 * 1024;  // 512MB
    uint64_t maxVRAMGrowthBytes = 1ULL * 1024 * 1024 * 1024;  // 1GB
    double maxFragmentationPercent = 15.0;
    
    // Thermal thresholds
    double maxGPUTempCelsius = 85.0;
    double maxGPUClockDropPercent = 20.0;
    
    // Fault injection (optional)
    bool enableFaultInjection = false;
    uint32_t faultInjectionIntervalHours = 6;
    
    // Model configuration
    std::string modelPath;
    uint32_t contextLength = 4096;
    uint32_t batchSize = 1;
    
    // Output
    std::string outputDir = "soak_reports";
    std::string testName = "soak_test";
};

// =============================================================================
// TELEMETRY DATA STRUCTURES
// =============================================================================

struct MemorySnapshot {
    std::chrono::system_clock::time_point timestamp;
    
    // System memory
    uint64_t workingSetBytes = 0;
    uint64_t privateBytes = 0;
    uint64_t heapCommittedBytes = 0;
    uint64_t heapAllocatedBytes = 0;
    double heapFragmentationPercent = 0.0;
    
    // GPU memory
    uint64_t gpuDedicatedBytesUsed = 0;
    uint64_t gpuSharedBytesUsed = 0;
    uint64_t gpuTotalBytes = 0;
    double gpuUtilizationPercent = 0.0;
    
    // Growth tracking
    uint64_t heapGrowthSinceStart = 0;
    uint64_t vramGrowthSinceStart = 0;
};

struct GPUSnapshot {
    std::chrono::system_clock::time_point timestamp;
    
    // Temperature
    double temperatureCelsius = 0.0;
    double hotspotTempCelsius = 0.0;
    
    // Clocks
    uint32_t coreClockMHz = 0;
    uint32_t memoryClockMHz = 0;
    uint32_t baseCoreClockMHz = 0;  // For drop detection
    double clockDropPercent = 0.0;
    
    // Power
    double powerDrawWatts = 0.0;
    double powerLimitWatts = 0.0;
    
    // Throttling flags
    bool isThermalThrottling = false;
    bool isPowerThrottling = false;
    bool isCurrentThrottling = false;
};

struct TPSSnapshot {
    std::chrono::system_clock::time_point timestamp;
    uint64_t iteration = 0;
    
    // Token metrics
    uint64_t tokensGenerated = 0;
    uint64_t totalTokens = 0;
    double tokensPerSecond = 0.0;
    double tokensPerSecondAvg = 0.0;
    double tokensPerSecondP95 = 0.0;
    double tokensPerSecondP99 = 0.0;
    
    // Latency metrics
    double timeToFirstTokenMs = 0.0;
    double avgTokenLatencyMs = 0.0;
    double maxTokenLatencyMs = 0.0;
    
    // Drift detection
    double tpsBaseline = 0.0;
    double tpsVariancePercent = 0.0;
    bool isDegraded = false;
};

struct ResidencySnapshot {
    std::chrono::system_clock::time_point timestamp;
    
    // Residency state
    uint64_t residentBytes = 0;
    uint64_t evictedBytes = 0;
    uint64_t pendingUploadBytes = 0;
    uint64_t pendingEvictionBytes = 0;
    
    // Upload queue
    uint32_t uploadQueueDepth = 0;
    double uploadThroughputMBps = 0.0;
    double avgUploadLatencyMs = 0.0;
    
    // Thrash detection
    uint32_t evictionCount = 0;
    uint32_t reuploadCount = 0;
    double thrashRatio = 0.0;  // reuploads / evictions
    bool isThrashing = false;
};

struct HealthStatus {
    std::chrono::system_clock::time_point timestamp;
    
    bool memoryHealthy = true;
    bool gpuHealthy = true;
    bool tpsHealthy = true;
    bool residencyHealthy = true;
    bool thermalHealthy = true;
    
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    
    bool isHealthy() const {
        return memoryHealthy && gpuHealthy && tpsHealthy && 
               residencyHealthy && thermalHealthy;
    }
};

// =============================================================================
// SOAK TEST HARNESS
// =============================================================================

class SoakTestHarness {
public:
    explicit SoakTestHarness(const SoakConfig& config);
    ~SoakTestHarness();

    // Test lifecycle
    bool Initialize();
    bool Run();
    void Shutdown();
    
    // Status
    bool IsRunning() const { return running_.load(); }
    double GetProgressPercent() const;
    HealthStatus GetCurrentHealth() const;
    
    // Results
    struct TestResults {
        bool passed = false;
        std::chrono::seconds duration;
        uint64_t totalTokensGenerated = 0;
        double avgTPS = 0.0;
        double minTPS = 0.0;
        double maxTPS = 0.0;
        uint64_t peakHeapBytes = 0;
        uint64_t peakVRAMBytes = 0;
        uint32_t faultCount = 0;
        uint32_t recoveryCount = 0;
        std::vector<std::string> failureReasons;
    };
    TestResults GetResults() const { return results_; }

private:
    SoakConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shouldStop_{false};
    TestResults results_;
    
    // Threading
    std::mutex telemetryMutex_;
    
    // Telemetry history
    std::vector<MemorySnapshot> memoryHistory_;
    std::vector<GPUSnapshot> gpuHistory_;
    std::vector<TPSSnapshot> tpsHistory_;
    std::vector<ResidencySnapshot> residencyHistory_;
    std::vector<HealthStatus> healthHistory_;
    
    // Baseline tracking
    double tpsBaseline_ = 0.0;
    uint64_t initialHeapBytes_ = 0;
    uint64_t initialVRAMBytes_ = 0;
    
    // Core loops
    void InferenceLoop();
    void HealthCheckLoop();
    void TelemetryLoop();
    void ResidencyProbeLoop();
    void FaultInjectionLoop();
    
    // Sampling
    MemorySnapshot SampleMemory();
    GPUSnapshot SampleGPU();
    TPSSnapshot SampleTPS();
    ResidencySnapshot SampleResidency();
    HealthStatus EvaluateHealth();
    
    // Analysis
    bool DetectMemoryLeak();
    bool DetectGPUFragmentation();
    bool DetectTPSDegradation();
    bool DetectResidencyThrash();
    bool DetectThermalThrottling();
    
    // Fault handling
    bool RecoverFromFault(const std::string& fault);
    void InjectFault();
    
    // Reporting
    void GenerateReport();
    void WriteTelemetryCSV();
    void WriteHealthLog();
    void WriteSummaryMarkdown();
};

// =============================================================================
// DX12 RESIDENCY PROBE
// =============================================================================

class DX12ResidencyProbe {
public:
    bool Initialize(ID3D12Device* device);
    void Shutdown();
    
    struct ResidencyInfo {
        uint64_t residentBytes = 0;
        uint64_t evictedBytes = 0;
        uint64_t budgetBytes = 0;
        uint64_t currentUsageBytes = 0;
        double utilizationPercent = 0.0;
    };
    
    ResidencyInfo QueryResidency();
    bool ForceEvict(uint64_t bytes);
    bool MakeResident(ID3D12Resource* resource);
    
private:
    ID3D12Device* device_ = nullptr;
    void* residencyManager_ = nullptr;  // IDXGIResource or custom
};

// =============================================================================
// TPS DRIFT DETECTOR
// =============================================================================

class TPSDriftDetector {
public:
    explicit TPSDriftDetector(double windowMinutes);
    
    void RecordSample(double tps);
    void SetBaseline(double baseline);
    
    double GetCurrentVariance() const;
    double GetCurrentAverage() const;
    bool IsDegraded(double thresholdPercent) const;
    bool IsStable(double varianceThresholdPercent) const;
    
    void Reset();
    
private:
    double windowMinutes_;
    std::vector<std::pair<std::chrono::system_clock::time_point, double>> samples_;
    double baseline_ = 0.0;
    mutable std::mutex mutex_;
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// Platform-specific memory sampling
MemorySnapshot SampleProcessMemory();
MemorySnapshot SampleHeapMemory();

// Platform-specific GPU sampling
GPUSnapshot SampleGPUStats();
bool InitializeGPUMonitoring();
void ShutdownGPUMonitoring();

// Thermal monitoring
bool InitializeThermalMonitoring();
GPUSnapshot SampleThermalStats();

// Report generation
void GenerateSoakReport(const SoakTestHarness::TestResults& results,
                        const std::string& outputPath);

} // namespace SoakTest
} // namespace RawrXD
