// ============================================================================
// VAL-071: Dual GPU Validation Gate
// ============================================================================
// Validates multi-GPU inference with proper load balancing and synchronization
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"
#include <vector>
#include <string>

namespace RawrXD {
namespace Validation {

// GPU Device Info
struct GPUDevice {
    int deviceId;
    std::string name;
    size_t totalMemory;
    size_t freeMemory;
    float utilization;
    float temperature;
    bool isActive;
};

// Dual GPU Configuration
struct DualGPUConfig {
    int primaryDevice;
    int secondaryDevice;
    size_t splitRatio;  // Percentage on primary (0-100)
    bool enableP2P;     // Peer-to-peer access
    bool enableNCCL;    // NCCL for multi-GPU
};

// Dual GPU Validation Gate
class VAL071_DualGPU_Gate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-071"; }
    std::string GetName() const override { return "Dual GPU Validation"; }
    std::string GetDescription() const override {
        return "Validates multi-GPU inference with load balancing and synchronization";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { 
        return {"VAL-047", "VAL-039"}; 
    }
    
    // Dual GPU specific methods
    std::vector<GPUDevice> EnumerateGPUs();
    bool TestP2PAccess(int device1, int device2);
    bool TestMemorySplit(const DualGPUConfig& config);
    bool TestLoadBalancing(const DualGPUConfig& config);
    bool TestSynchronization(const DualGPUConfig& config);
    bool TestFailover(const DualGPUConfig& config);
    float MeasureThroughput(const DualGPUConfig& config);
    float MeasureLatency(const DualGPUConfig& config);
    
private:
    std::vector<GPUDevice> detectedGPUs_;
    DualGPUConfig config_;
    bool InitializeCUDA();
    void CleanupCUDA();
};

// GPU Performance Metrics
struct GPUPerformanceMetrics {
    float tokensPerSecond;
    float latencyMs;
    float memoryUtilization;
    float computeUtilization;
    float powerDrawWatts;
    float temperatureCelsius;
    size_t memoryBandwidthGBps;
};

// Multi-GPU Benchmark Result
struct MultiGPUBenchmarkResult {
    GPUPerformanceMetrics primaryGPU;
    GPUPerformanceMetrics secondaryGPU;
    float combinedThroughput;
    float scalingEfficiency;  // Percentage of theoretical max
    bool p2pEnabled;
    bool ncclEnabled;
};

} // namespace Validation
} // namespace RawrXD
