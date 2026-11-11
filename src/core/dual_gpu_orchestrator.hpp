// Dual GPU Orchestrator Header
// Multi-GPU support for RawrXD inference engine

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <queue>
#include <future>
#include <mutex>
#include <atomic>
#include <functional>
#include <unordered_map>

namespace RawrXD {
namespace GPU {

// GPU device information
struct GPUDeviceInfo {
    int device_id = -1;
    std::string name;
    size_t memory_total = 0;
    size_t memory_free = 0;
    int compute_capability_major = 0;
    int compute_capability_minor = 0;
    bool is_primary = false;
    bool is_available = false;
    
    std::string GetSummary() const;
};

// Work types for GPU execution
enum class GPUWorkType {
    INFERENCE,
    TRAINING,
    MEMORY_COPY,
    CUSTOM_KERNEL,
    TENSOR_OPERATION
};

// Work item for GPU execution
struct GPUWorkItem {
    GPUWorkType type = GPUWorkType::INFERENCE;
    int preferred_device = -1;  // -1 = auto-select
    
    // Data pointers
    void* input_data = nullptr;
    void* output_data = nullptr;
    size_t data_size = 0;
    
    // Work parameters
    std::vector<int> dimensions;
    std::string kernel_name;
    
    // Callback for async completion
    std::function<void(struct GPUResult)> callback;
};

// Result from GPU execution
struct GPUResult {
    bool success = false;
    int device_id = -1;
    std::string error_message;
    void* output_data = nullptr;
    size_t output_size = 0;
    uint64_t execution_time_ms = 0;
};

// Performance metrics
struct GPUPerformanceMetrics {
    int device_id = -1;
    uint64_t tasks_completed = 0;
    uint64_t average_task_time_ms = 0;
    size_t memory_used_bytes = 0;
    size_t memory_total_bytes = 0;
    float utilization_percent = 0.0f;
};

// Load balancing strategies
enum class LoadBalanceStrategy {
    ROUND_ROBIN,        // Alternate between GPUs
    MEMORY_BASED,     // Select based on available memory
    PERFORMANCE_BASED, // Select based on performance history
    TASK_SPECIFIC     // Use preferred device from work item
};

// Dual GPU Orchestrator
class DualGPUOrchestrator {
public:
    static DualGPUOrchestrator& Instance();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return impl_ && impl_->initialized_; }
    
    // Device management
    std::vector<GPUDeviceInfo> GetDeviceInfo() const;
    size_t GetDeviceCount() const;
    
    // Memory management
    void* AllocateMemory(size_t size, int preferred_device = -1);
    void FreeMemory(void* ptr);
    void FreeAllMemory();
    
    // Work submission
    void SubmitWork(const GPUWorkItem& work);
    std::future<GPUResult> SubmitWorkAsync(const GPUWorkItem& work);
    
    // Load balancing
    void SetLoadBalanceStrategy(LoadBalanceStrategy strategy);
    LoadBalanceStrategy GetLoadBalanceStrategy() const;
    
    // Synchronization
    void SynchronizeDevice(int device);
    void SynchronizeAll();
    
    // Performance metrics
    GPUPerformanceMetrics GetPerformanceMetrics(int device) const;
    std::vector<GPUPerformanceMetrics> GetAllPerformanceMetrics() const;
    
    // Utility
    int SelectDeviceForWork(const GPUWorkItem& work);
    int SelectDeviceForAllocation(size_t size, int preferred_device);
    
private:
    DualGPUOrchestrator();
    ~DualGPUOrchestrator();
    
    DualGPUOrchestrator(const DualGPUOrchestrator&) = delete;
    DualGPUOrchestrator& operator=(const DualGPUOrchestrator&) = delete;
    
    bool DetectGPUs();
    int SelectDeviceByPerformance();
    
    void PrimaryWorkerLoop();
    void SecondaryWorkerLoop();
    GPUResult ExecuteWorkOnDevice(const GPUWorkItem& work, int device);
    
    GPUResult ExecuteInference(const GPUWorkItem& work);
    GPUResult ExecuteTraining(const GPUWorkItem& work);
    GPUResult ExecuteMemoryCopy(const GPUWorkItem& work);
    GPUResult ExecuteCustomKernel(const GPUWorkItem& work);
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace GPU
} // namespace RawrXD
