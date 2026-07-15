// =============================================================================
// RawRamXD_Fabric.hpp - Heterogeneous Compute Fabric
// =============================================================================
// Treats every memory tier as a GPU-addressable compute target with residency,
// bandwidth, and scheduling costs. Unifies GPU VRAM, RAM, and storage as
// schedulable device nodes in a single fabric.
// =============================================================================

#ifndef RAWRAMXD_FABRIC_HPP
#define RAWRAMXD_FABRIC_HPP

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <queue>
#include <chrono>
#include <string>
#include <optional>
#include <variant>

// Platform includes
#ifdef _WIN32
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RawRamXD {
namespace Fabric {

// =============================================================================
// COMPUTE TARGET ABSTRACTION
// =============================================================================

enum class ComputeTargetType : uint8_t {
    GPU_VRAM = 0,           // Native GPU dedicated memory
    CPU_RAM = 1,            // System RAM (mapped compute tier)
    NVME_STORE = 2,         // NVMe SSD (streaming tier)
    SATA_SSD = 3,           // SATA SSD (slower storage)
    HDD_STORE = 4,          // Hard disk (archive tier)
    CXL_MEMORY = 5,         // Future: CXL memory pool
    REMOTE = 6,             // Future: Remote/RDMA memory
    TARGET_COUNT = 7
};

enum class ResidencyState : uint8_t {
    FREE = 0,               // Unallocated
    ALLOCATED = 1,          // Reserved but not resident
    RESIDENT = 2,           // Fully resident on device
    MIGRATING = 3,          // In transit between devices
    PREFETCHED = 4,         // Staged for upcoming use
    EVICTING = 5,           // Being evicted
    PINNED = 6,             // Locked in place
    COMPRESSED = 7          // Compressed resident
};

enum class CapabilityFlags : uint32_t {
    NONE = 0,
    COMPUTE = 1 << 0,       // Can execute compute kernels
    DMA_SOURCE = 1 << 1,    // Can be source of DMA
    DMA_TARGET = 1 << 2,    // Can be target of DMA
    PEER_ACCESS = 1 << 3,   // Supports peer GPU access
    ZERO_COPY = 1 << 4,     // Supports zero-copy from CPU
    COMPRESSION = 1 << 5,   // Supports compression
    PREFETCH = 1 << 6,      // Supports prefetch prediction
    MIGRATION = 1 << 7      // Supports live migration
};

inline CapabilityFlags operator|(CapabilityFlags a, CapabilityFlags b) {
    return static_cast<CapabilityFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline CapabilityFlags operator&(CapabilityFlags a, CapabilityFlags b) {
    return static_cast<CapabilityFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline bool HasCapability(CapabilityFlags flags, CapabilityFlags cap) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(cap)) != 0;
}

// =============================================================================
// COMPUTE TARGET (GPU-STYLE NODE)
// =============================================================================

struct ComputeTarget {
    uint32_t id;                            // Unique device ID
    ComputeTargetType type;                 // Device type
    std::string name;                       // Human-readable name
    
    // Capacity
    uint64_t capacityBytes;                 // Total capacity
    uint64_t allocatedBytes;                // Currently allocated
    uint64_t residentBytes;                 // Currently resident
    uint64_t availableBytes() const { return capacityBytes - residentBytes; }
    
    // Performance characteristics
    uint64_t bandwidthBps;                  // Peak bandwidth (bytes/sec)
    uint64_t latencyNs;                   // Access latency (nanoseconds)
    float computeScore;                   // Relative compute capability (0-1)
    float migrationCost;                  // Cost to migrate to/from (0-1)
    
    // Capabilities
    CapabilityFlags capabilities;
    
    // Residency state
    ResidencyState state;
    std::atomic<bool> isHealthy{true};
    std::atomic<bool> isActive{true};
    
    // Platform handles
    struct PlatformHandles {
#ifdef _WIN32
        ID3D12Device* d3dDevice = nullptr;
        ID3D12Heap* d3dHeap = nullptr;
        uint32_t nodeMask = 0;
#endif
        void* cpuBasePtr = nullptr;
        int fd = -1;                        // For mmap
    } platform;
    
    // Comparison for scheduling
    bool operator<(const ComputeTarget& other) const {
        // Higher compute score = lower value (priority)
        return computeScore > other.computeScore;
    }
};

// =============================================================================
// TENSOR HANDLE & RESIDENCY
// =============================================================================

using TensorHandle = uint64_t;
constexpr TensorHandle INVALID_HANDLE = 0;

enum class OperationType : uint8_t {
    INFERENCE = 0,          // Forward pass
    ATTENTION = 1,          // Attention computation
    FEEDFORWARD = 2,        // FFN/MLP
    EMBEDDING = 3,          // Token embedding
    SAMPLING = 4,           // Token sampling
    KV_CACHE = 5,           // KV cache access
    WEIGHT_LOAD = 6,        // Weight loading
    UNKNOWN = 7
};

struct AccessHeat {
    uint64_t lastUsedTimestamp;
    uint64_t accessCount;
    uint64_t bytesRead;
    uint64_t bytesWritten;
    float temperature;          // 0.0 = cold, 1.0 = hot
    
    void UpdateAccess(uint64_t bytes, bool isWrite) {
        accessCount++;
        if (isWrite) bytesWritten += bytes;
        else bytesRead += bytes;
        temperature = std::min(1.0f, temperature + 0.1f);
    }
    
    void Decay(float factor = 0.95f) {
        temperature *= factor;
    }
};

struct TensorResidency {
    TensorHandle handle;
    std::string name;
    
    // Current placement
    ComputeTarget* currentDevice;
    ResidencyState state;
    
    // Preferred placement
    ComputeTarget* preferredDevice;
    OperationType primaryOperation;
    
    // Size and layout
    uint64_t sizeBytes;
    uint64_t alignment;
    
    // Access tracking
    AccessHeat heat;
    
    // Migration state
    struct MigrationState {
        bool isMigrating;
        ComputeTarget* source;
        ComputeTarget* destination;
        uint64_t bytesTransferred;
        uint64_t bytesTotal;
        float progress;
    } migration;
    
    // Physical backing
    struct Backing {
        void* cpuPtr;
        uint64_t gpuAddress;
        int fd;
        uint64_t fileOffset;
    } backing;
    
    // Locking
    mutable std::mutex mutex;
    std::atomic<uint32_t> pinCount{0};
    
    bool IsPinned() const { return pinCount.load() > 0; }
    bool CanMigrate() const { 
        return !IsPinned() && 
               state != ResidencyState::MIGRATING && 
               state != ResidencyState::EVICTING;
    }
};

// =============================================================================
// SCHEDULING & PLACEMENT
// =============================================================================

enum class PlacementStrategy : uint8_t {
    LATENCY_OPTIMIZED = 0,      // Minimize access latency
    BANDWIDTH_OPTIMIZED = 1,    // Maximize bandwidth
    CAPACITY_OPTIMIZED = 2,     // Maximize capacity utilization
    COST_OPTIMIZED = 3,         // Minimize migration cost
    THERMAL_OPTIMIZED = 4       // Balance thermal load
};

struct PlacementDecision {
    ComputeTarget* targetDevice;
    PlacementStrategy strategy;
    float confidence;
    uint64_t estimatedLatencyNs;
    uint64_t estimatedBandwidthBps;
    float estimatedCost;
    
    bool isPrefetch;
    uint64_t prefetchDistance;
};

struct ScheduleRequest {
    TensorHandle handle;
    OperationType operation;
    uint64_t bytesRequired;
    uint64_t latencyBudgetNs;
    uint64_t bandwidthRequiredBps;
    PlacementStrategy strategy;
    bool allowMigration;
    bool allowEviction;
};

// =============================================================================
// FABRIC MANAGER
// =============================================================================

class FabricManager {
public:
    FabricManager();
    ~FabricManager();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Device registration
    bool RegisterComputeTarget(std::unique_ptr<ComputeTarget> device);
    bool UnregisterComputeTarget(uint32_t deviceId);
    ComputeTarget* GetDevice(uint32_t deviceId);
    ComputeTarget* GetDeviceByType(ComputeTargetType type);
    std::vector<ComputeTarget*> GetAllDevices();
    std::vector<ComputeTarget*> GetDevicesByCapability(CapabilityFlags cap);
    
    // Tensor lifecycle
    TensorHandle AllocateTensor(uint64_t size, uint64_t alignment = 256, 
                                 const std::string& name = "");
    bool FreeTensor(TensorHandle handle);
    TensorResidency* GetTensor(TensorHandle handle);
    
    // Residency operations
    bool EnsureResident(TensorHandle handle, OperationType operation);
    bool Migrate(TensorHandle handle, uint32_t targetDeviceId);
    bool Prefetch(TensorHandle handle, uint32_t targetDeviceId);
    bool Evict(TensorHandle handle);
    bool Pin(TensorHandle handle);
    bool Unpin(TensorHandle handle);
    
    // Scheduling
    PlacementDecision SelectPlacement(const ScheduleRequest& request);
    bool ExecuteOnDevice(TensorHandle handle, uint32_t deviceId, 
                         std::function<void(void* ptr, uint64_t size)> kernel);
    
    // Fabric queries
    uint64_t GetTotalCapacity(ComputeTargetType type);
    uint64_t GetAvailableCapacity(ComputeTargetType type);
    float GetFabricUtilization();
    std::string GetFabricTopology();
    
    // Health monitoring
    bool CheckDeviceHealth(uint32_t deviceId);
    bool MigrateFromFailedDevice(uint32_t failedDeviceId);
    
    // Statistics
    struct Stats {
        uint64_t totalAllocations;
        uint64_t totalMigrations;
        uint64_t totalPrefetches;
        uint64_t totalEvictions;
        uint64_t failedAllocations;
        uint64_t migrationBytes;
        double avgMigrationTimeMs;
        float fabricUtilization;
    };
    Stats GetStats() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// =============================================================================
// GPU FABRIC ENUMERATOR
// =============================================================================

class GPUFabricEnumerator {
public:
    struct GPUInfo {
        uint32_t deviceId;
        std::string name;
        uint64_t dedicatedVRAM;
        uint64_t sharedMemory;
        uint32_t nodeMask;
        bool supportsPeerAccess;
        std::vector<uint32_t> peerDeviceIds;
    };
    
    static std::vector<GPUInfo> EnumerateGPUs();
    static bool CheckPeerAccess(uint32_t gpu1, uint32_t gpu2);
    static uint64_t GetOptimalTransferChunk(uint64_t totalSize);
};

// =============================================================================
// MIGRATION ENGINE
// =============================================================================

class MigrationEngine {
public:
    MigrationEngine(FabricManager* fabric);
    
    struct MigrationTask {
        TensorHandle handle;
        ComputeTarget* source;
        ComputeTarget* destination;
        uint64_t priority;
        std::chrono::steady_clock::time_point enqueueTime;
        std::function<void(bool success)> completionCallback;
    };
    
    bool QueueMigration(const MigrationTask& task);
    bool ExecuteMigration(TensorHandle handle);
    void CancelMigration(TensorHandle handle);
    
    // Async DMA
    bool StartAsyncDMA(TensorHandle handle, ComputeTarget* src, ComputeTarget* dst);
    bool PollDMACompletion(TensorHandle handle);
    void WaitDMACompletion(TensorHandle handle);
    
    // Bandwidth optimization
    uint64_t CalculateOptimalChunkSize(ComputeTarget* src, ComputeTarget* dst);
    bool EnableP2PTransfer(uint32_t gpu1, uint32_t gpu2);

private:
    FabricManager* fabric_;
    std::queue<MigrationTask> pendingQueue_;
    std::unordered_map<TensorHandle, MigrationTask> activeMigrations_;
    std::mutex mutex_;
};

// =============================================================================
// PREFETCH PREDICTOR
// =============================================================================

class PrefetchPredictor {
public:
    PrefetchPredictor(FabricManager* fabric);
    
    // Pattern learning
    void RecordAccess(TensorHandle handle, uint64_t offset, uint64_t size);
    void RecordOperation(OperationType op, const std::vector<TensorHandle>& inputs);
    
    // Prediction
    std::vector<TensorHandle> PredictNextAccesses(uint32_t count);
    uint64_t PredictPrefetchDistance(TensorHandle handle);
    
    // Prefetch execution
    bool IssuePrefetch(TensorHandle handle, uint32_t targetDeviceId);
    bool IssuePrefetchBatch(const std::vector<TensorHandle>& handles, 
                            uint32_t targetDeviceId);
    
    // Model-specific patterns
    void RegisterModelPattern(const std::string& modelName, 
                              const std::vector<OperationType>& pattern);

private:
    FabricManager* fabric_;
    std::unordered_map<std::string, std::vector<OperationType>> modelPatterns_;
    std::unordered_map<TensorHandle, std::vector<uint64_t>> accessHistory_;
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

const char* ComputeTargetTypeToString(ComputeTargetType type);
const char* ResidencyStateToString(ResidencyState state);
const char* OperationTypeToString(OperationType op);

uint64_t GetDeviceBandwidthEstimate(ComputeTargetType type);
uint64_t GetDeviceLatencyEstimate(ComputeTargetType type);

// Migration cost calculation
float CalculateMigrationCost(ComputeTarget* src, ComputeTarget* dst, uint64_t bytes);
float CalculateAccessCost(ComputeTarget* device, OperationType op, uint64_t bytes);

} // namespace Fabric
} // namespace RawRamXD

#endif // RAWRAMXD_FABRIC_HPP
