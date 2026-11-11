// =============================================================================
// RawRamXD GPU Fabric Extension - Multi-GPU Memory Unification
// =============================================================================
// Extends RawRamXD to treat multiple GPUs as a unified memory fabric
// Enables tensor sharding, cross-GPU migration, and federated inference
// =============================================================================

#ifndef RAWRAMXD_GPUFABRIC_HPP
#define RAWRAMXD_GPUFABRIC_HPP

#include "RawRamXD.hpp"
#include <d3d12.h>
#include <dxgi1_6.h>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <functional>

namespace rawramxd {

// =============================================================================
// GPU Device Representation
// =============================================================================

struct GPUDevice {
    uint32_t gpuId;                          // Unique GPU identifier
    std::wstring name;                      // GPU name
    uint64_t dedicatedVRAM;                 // Dedicated VRAM in bytes
    uint64_t sharedMemory;                  // Shared system memory
    uint32_t computeUnits;                  // Number of compute units
    uint32_t clockSpeedMHz;                 // Base clock speed
    
    // DX12 handles
    IDXGIAdapter4* adapter = nullptr;
    ID3D12Device* device = nullptr;
    ID3D12CommandQueue* commandQueue = nullptr;
    
    // Memory management
    uint64_t allocatedBytes = 0;
    uint64_t reservedBytes = 0;
    std::atomic<float> utilization{0.0f};
    std::atomic<float> temperature{0.0f};
    std::atomic<bool> healthy{true};
    
    // Peer access (can access other GPU memory directly)
    std::vector<uint32_t> peerAccessibleGPUs;
};

// =============================================================================
// GPU Memory Region - Subdivision of GPU VRAM
// =============================================================================

struct GPUMemoryRegion {
    uint32_t gpuId;
    uint64_t baseAddress;
    uint64_t size;
    uint64_t usedBytes;
    
    // Residency tracking
    std::vector<Handle> residentHandles;
    std::mutex regionMutex;
    
    // Performance characteristics
    float bandwidthGBps;
    float latencyUs;
};

// =============================================================================
// Tensor Sharding Configuration
// =============================================================================

enum class ShardStrategy : uint8_t {
    LAYER_WISE = 0,         // Each GPU gets full layers
    TENSOR_PARALLEL = 1,    // Split tensors across GPUs (Megatron-style)
    PIPELINE_PARALLEL = 2,  // Pipeline stages across GPUs
    HYBRID = 3             // Mix of strategies
};

struct ShardConfig {
    ShardStrategy strategy;
    uint32_t numGPUs;
    std::vector<uint32_t> gpuIds;
    
    // Layer assignment for pipeline parallelism
    std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> layerRanges;
    
    // Tensor split dimensions for tensor parallelism
    uint32_t splitDim = 0;
    uint32_t numSplits = 1;
};

struct TensorShard {
    Handle handle;                          // Original tensor handle
    uint32_t gpuId;                         // Which GPU owns this shard
    uint64_t offset;                        // Offset within original tensor
    uint64_t size;                          // Size of this shard
    uint32_t shardIndex;                    // Index in sharded set
    uint32_t totalShards;                   // Total number of shards
    
    // Cross-GPU synchronization
    std::atomic<bool> ready{false};
    ID3D12Fence* completionFence = nullptr;
    uint64_t fenceValue = 0;
};

// =============================================================================
// Cross-GPU Migration
// =============================================================================

enum class MigrationPath : uint8_t {
    GPU_TO_GPU_DIRECT = 0,      // P2P copy (fastest)
    GPU_TO_GPU_VIA_RAM = 1,     // Staging through system RAM
    GPU_TO_GPU_VIA_NVME = 2     // Spill to disk (slowest)
};

struct GPUMigrationRequest {
    Handle handle;
    uint32_t sourceGPU;
    uint32_t targetGPU;
    MigrationPath path;
    MigrationPriority priority;
    std::function<void(bool)> callback;
    
    // Timing
    std::chrono::steady_clock::time_point submitTime;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point completeTime;
};

// =============================================================================
// GPU Fabric Statistics
// =============================================================================

struct GPUFabricStats {
    // Per-GPU stats
    struct GPUStats {
        uint64_t totalVRAM;
        uint64_t usedVRAM;
        uint64_t freeVRAM;
        float utilization;
        float temperature;
        uint64_t bytesMigratedIn;
        uint64_t bytesMigratedOut;
        uint32_t activeCompute;
        bool healthy;
    };
    std::vector<GPUStats> gpuStats;
    
    // Fabric-wide stats
    uint64_t totalFabricVRAM;
    uint64_t totalUsedVRAM;
    uint64_t crossGPUMigrations;
    double avgCrossGPULatencyMs;
    uint32_t activeShards;
    uint32_t failedMigrations;
};

// =============================================================================
// GPU Fabric - Multi-GPU Memory Management
// =============================================================================

class RawRamXDGPUFabric {
public:
    static RawRamXDGPUFabric& instance();
    
    // Initialization
    bool initialize();
    void shutdown();
    
    // GPU Discovery
    uint32_t enumerateGPUs();
    uint32_t getGPUCount() const { return static_cast<uint32_t>(gpus_.size()); }
    const GPUDevice* getGPU(uint32_t gpuId) const;
    std::vector<const GPUDevice*> getHealthyGPUs() const;
    
    // Memory allocation across GPUs
    Handle allocateSharded(size_t totalSize, const ShardConfig& config, const char* name);
    Handle allocateOnGPU(size_t size, uint32_t gpuId, const char* name);
    bool migrateBetweenGPUs(Handle handle, uint32_t targetGPU, MigrationPriority priority);
    
    // Tensor sharding
    std::vector<TensorShard> shardTensor(Handle handle, const ShardConfig& config);
    bool gatherTensor(const std::vector<TensorShard>& shards, Handle outputHandle);
    bool allGather(const std::vector<TensorShard>& shards, std::vector<Handle>& outputs);
    bool allReduce(const std::vector<TensorShard>& shards, std::function<void(void*, void*, size_t)> op);
    
    // Residency management
    bool ensureOnGPU(Handle handle, uint32_t gpuId);
    bool evictFromGPU(Handle handle, uint32_t gpuId);
    Tier getResidentTier(Handle handle) const;
    std::vector<uint32_t> getResidentGPUs(Handle handle) const;
    
    // Load balancing
    void setLoadBalancer(std::function<uint32_t(const std::vector<GPUDevice*>&)> balancer);
    uint32_t selectGPUForAllocation(size_t size);
    void rebalanceLoad();
    
    // Fault tolerance
    void markGPUFailed(uint32_t gpuId);
    bool recoverGPU(uint32_t gpuId);
    bool migrateOffFailedGPU(uint32_t failedGPUId);
    
    // Synchronization
    bool synchronizeGPU(uint32_t gpuId);
    bool synchronizeAllGPUs();
    bool waitForShard(const TensorShard& shard);
    
    // Peer access
    bool enablePeerAccess(uint32_t gpuA, uint32_t gpuB);
    bool disablePeerAccess(uint32_t gpuA, uint32_t gpuB);
    bool isPeerAccessible(uint32_t gpuA, uint32_t gpuB) const;
    
    // Telemetry
    GPUFabricStats getStats() const;
    void dumpGPUState();
    void traceMigrations(std::function<void(const GPUMigrationRequest&)> callback);
    
    // Integration with base RawRamXD
    void registerWithFabric(RawRamXDFabric* fabric);
    
private:
    RawRamXDGPUFabric() = default;
    ~RawRamXDGPUFabric();
    RawRamXDGPUFabric(const RawRamXDGPUFabric&) = delete;
    RawRamXDGPUFabric& operator=(const RawRamXDGPUFabric&) = delete;
    
    // Internal methods
    bool initializeGPU(uint32_t index, IDXGIAdapter4* adapter);
    void shutdownGPU(uint32_t gpuId);
    MigrationPath selectMigrationPath(uint32_t sourceGPU, uint32_t targetGPU);
    void executeMigration(const GPUMigrationRequest& request);
    void migrationWorker();
    void monitoringWorker();
    
    // Members
    std::vector<std::unique_ptr<GPUDevice>> gpus_;
    std::unordered_map<Handle, std::vector<TensorShard>> shardMap_;
    std::unordered_map<Handle, uint32_t> handleToGPU_;
    
    // Threading
    std::atomic<bool> running_{false};
    std::thread migrationThread_;
    std::thread monitorThread_;
    
    // Migration queue
    std::queue<GPUMigrationRequest> migrationQueue_;
    std::mutex migrationMutex_;
    std::condition_variable migrationCV_;
    
    // Load balancing
    std::function<uint32_t(const std::vector<GPUDevice*>&)> loadBalancer_;
    
    // Stats
    mutable std::mutex statsMutex_;
    GPUFabricStats stats_;
    
    // DXGI factory
    IDXGIFactory6* dxgiFactory_ = nullptr;
};

// =============================================================================
// Federated Inference - Multi-GPU Coordination
// =============================================================================

class FederatedInferenceEngine {
public:
    FederatedInferenceEngine(RawRamXDGPUFabric* fabric);
    ~FederatedInferenceEngine();
    
    bool initialize(const ShardConfig& config);
    
    // Layer execution across GPUs
    bool executeLayer(uint32_t layerIndex, 
                       const std::vector<Handle>& inputs,
                       std::vector<Handle>& outputs);
    
    // All-reduce for tensor parallelism
    bool allReduceActivations(std::vector<Handle>& activations);
    
    // Pipeline parallelism
    bool forwardPipeline(const std::vector<Handle>& inputTokens,
                         std::vector<Handle>& outputLogits);
    
    // Synchronization
    bool barrier();
    
private:
    RawRamXDGPUFabric* fabric_;
    ShardConfig config_;
    std::vector<ID3D12Fence*> fences_;
    uint64_t fenceValue_ = 0;
};

// =============================================================================
// C API for GPU Fabric
// =============================================================================

extern "C" {

// Lifecycle
bool rawramxd_gpu_init();
void rawramxd_gpu_shutdown();
uint32_t rawramxd_gpu_count();

// Allocation
uint64_t rawramxd_gpu_alloc_on(uint32_t gpu_id, size_t size, const char* name);
uint64_t rawramxd_gpu_alloc_sharded(size_t size, uint8_t strategy, uint32_t num_gpus, const uint32_t* gpu_ids);

// Migration
bool rawramxd_gpu_migrate(uint64_t handle, uint32_t target_gpu);
bool rawramxd_gpu_ensure_on(uint64_t handle, uint32_t gpu_id);

// Sharding
uint32_t rawramxd_gpu_shard_count(uint64_t handle);
bool rawramxd_gpu_gather(uint64_t handle, uint64_t output);

// Synchronization
bool rawramxd_gpu_sync(uint32_t gpu_id);
bool rawramxd_gpu_sync_all();

// Stats
void rawramxd_gpu_stats(void* stats_out);

} // extern "C"

} // namespace rawramxd

#endif // RAWRAMXD_GPUFABRIC_HPP
