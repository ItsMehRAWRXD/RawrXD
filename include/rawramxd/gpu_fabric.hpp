#pragma once
/**
 * RawRamXD GPU Fabric Architecture
 * Real implementation - NOT simulated
 * 
 * Treats every memory tier as a schedulable compute target:
 * - GPU VRAM: Native device memory with compute capabilities
 * - CPU RAM: Pinned/mapped accelerator tier
 * - NVMe: Memory-mapped streaming tier
 * - HDD: Archive tier
 */

#include <cstdint>
#include <cstring>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <functional>
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <cuda.h>
#include <cuda_runtime.h>

#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "cuda.lib")

namespace RawRamXD {

// =============================================================================
// COMPUTE TARGET TYPES
// =============================================================================

enum class ComputeTargetType : uint32_t {
    GPU_VRAM = 0,      // Native GPU device memory
    CPU_RAM = 1,       // Pinned host memory (accelerator tier)
    NVME_STORE = 2,    // Memory-mapped SSD
    HDD_STORE = 3,     // Archive storage
    CXL_MEMORY = 4,    // Future: CXL memory pools
    UNKNOWN = 0xFF
};

enum class ComputeCapability : uint64_t {
    NONE = 0,
    COMPUTE_SHADER = 1ULL << 0,      // Can execute compute shaders
    DMA_TRANSFER = 1ULL << 1,         // Supports async DMA
    PEER_ACCESS = 1ULL << 2,          // Can access other device memory
    UNIFIED_ADDRESS = 1ULL << 3,      // Shares address space with CPU
    PINNED_MEMORY = 1ULL << 4,        // Supports pinned host mappings
    MEMORY_MAPPED = 1ULL << 5,        // File-backed memory mapping
    PREFETCH = 1ULL << 6,             // Supports prefetch hints
    RESidency_MANAGED = 1ULL << 7,    // OS-managed residency
};

inline ComputeCapability operator|(ComputeCapability a, ComputeCapability b) {
    return static_cast<ComputeCapability>(
        static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

inline bool HasCapability(ComputeCapability flags, ComputeCapability cap) {
    return (static_cast<uint64_t>(flags) & static_cast<uint64_t>(cap)) != 0;
}

// =============================================================================
// COMPUTE TARGET (GPU-STYLE NODE)
// =============================================================================

struct ComputeTarget {
    uint32_t id;
    ComputeTargetType type;
    wchar_t name[256];
    
    // Capacity
    uint64_t capacityBytes;
    uint64_t availableBytes;
    uint64_t allocatedBytes;
    
    // Performance characteristics (measured, not assumed)
    uint64_t bandwidthBytesPerSec;    // Measured peak bandwidth
    uint64_t latencyNs;                // Measured access latency
    float computeScore;                // Relative compute capability
    
    // Residency management
    uint64_t pageSize;
    uint64_t alignment;
    
    // Capabilities
    ComputeCapability capabilities;
    
    // Device handles (platform-specific)
    union {
        struct {
            ID3D12Device* d3d12Device;
            ID3D12Heap* defaultHeap;
            uint32_t nodeMask;
        } gpu;
        
        struct {
            void* pinnedBase;
            size_t pinnedSize;
            HANDLE heapHandle;
        } ram;
        
        struct {
            HANDLE fileHandle;
            HANDLE mappingHandle;
            void* mappedBase;
            size_t mappedSize;
            wchar_t filePath[MAX_PATH];
        } storage;
    } platform;
    
    // Statistics
    std::atomic<uint64_t> bytesTransferred{0};
    std::atomic<uint64_t> transferCount{0};
    std::atomic<uint64_t> computeDispatches{0};
    
    // Thread safety
    mutable std::mutex allocationMutex;
    
    bool IsGPU() const { return type == ComputeTargetType::GPU_VRAM; }
    bool IsRAM() const { return type == ComputeTargetType::CPU_RAM; }
    bool IsStorage() const { return type == ComputeTargetType::NVME_STORE || 
                                    type == ComputeTargetType::HDD_STORE; }
    
    double GetUtilization() const {
        return capacityBytes > 0 ? 
            (double)allocatedBytes / (double)capacityBytes : 0.0;
    }
};

// =============================================================================
// TENSOR RESIDENCY
// =============================================================================

enum class ResidencyState : uint32_t {
    UNRESIDENT = 0,       // Not allocated anywhere
    RESIDENT = 1,         // Fully resident on target
    MIGRATING = 2,        // In transit between targets
    EVICTED = 3,          // Paged out to storage
    PREFETCHING = 4,      // Async loading in progress
};

enum class AccessHeat : uint32_t {
    COLD = 0,      // Never accessed
    WARM = 1,      // Infrequent access
    HOT = 2,       // Frequent access
    CRITICAL = 3,  // Always resident required
};

struct TensorResidency {
    uint64_t tensorId;
    uint64_t sizeBytes;
    uint32_t dimensions;
    uint32_t elementSize;
    
    // Current location
    ComputeTarget* currentTarget;
    void* currentAddress;
    ResidencyState state;
    
    // Preferred location (scheduler hint)
    ComputeTargetType preferredType;
    AccessHeat heat;
    
    // Access tracking
    std::atomic<uint64_t> lastAccessTime{0};
    std::atomic<uint64_t> accessCount{0};
    std::atomic<uint64_t> bytesRead{0};
    std::atomic<uint64_t> bytesWritten{0};
    
    // Migration tracking
    uint64_t migrationCount;
    uint64_t lastMigrationTime;
    
    // Thread safety
    mutable std::shared_mutex residencyMutex;
};

// =============================================================================
// FABRIC SCHEDULER
// =============================================================================

enum class OperationType : uint32_t {
    INFERENCE_FORWARD = 0,
    INFERENCE_BACKWARD = 1,
    ATTENTION_COMPUTE = 2,
    KV_CACHE_ACCESS = 3,
    WEIGHT_LOAD = 4,
    WEIGHT_SAVE = 5,
    PREFETCH = 6,
    EVICT = 7,
};

struct Operation {
    OperationType type;
    uint64_t tensorId;
    uint64_t sizeBytes;
    uint64_t bandwidthRequired;
    uint64_t latencyBudgetNs;
    bool computeRequired;
};

struct SchedulingDecision {
    ComputeTarget* target;
    bool requiresMigration;
    ComputeTarget* migrationSource;
    uint64_t estimatedLatencyNs;
    uint64_t estimatedBandwidth;
    float confidence;
};

class FabricScheduler {
public:
    FabricScheduler();
    ~FabricScheduler();
    
    // Target management
    bool RegisterTarget(std::unique_ptr<ComputeTarget> target);
    void UnregisterTarget(uint32_t targetId);
    ComputeTarget* GetTarget(uint32_t targetId);
    ComputeTarget* GetTargetByType(ComputeTargetType type);
    std::vector<ComputeTarget*> GetAllTargets();
    std::vector<ComputeTarget*> GetTargetsByCapability(ComputeCapability cap);
    
    // Tensor residency
    TensorResidency* RegisterTensor(uint64_t tensorId, uint64_t sizeBytes);
    void UnregisterTensor(uint64_t tensorId);
    TensorResidency* GetTensor(uint64_t tensorId);
    
    // Scheduling
    SchedulingDecision Schedule(const Operation& op);
    bool ExecuteMigration(TensorResidency* tensor, ComputeTarget* destination);
    
    // Residency management
    bool EnsureResident(uint64_t tensorId, OperationType op);
    bool Prefetch(uint64_t tensorId, ComputeTargetType preferred);
    bool Evict(uint64_t tensorId);
    
    // Statistics
    struct FabricStats {
        uint64_t totalTensors;
        uint64_t residentTensors;
        uint64_t migratingTensors;
        uint64_t totalMigrations;
        uint64_t totalBytesTransferred;
        double averageMigrationLatency;
        double fabricUtilization;
    };
    FabricStats GetStats() const;
    
private:
    std::vector<std::unique_ptr<ComputeTarget>> targets_;
    std::unordered_map<uint64_t, std::unique_ptr<TensorResidency>> tensors_;
    
    mutable std::shared_mutex targetsMutex_;
    mutable std::shared_mutex tensorsMutex_;
    
    // Scoring
    double ScoreTarget(const ComputeTarget* target, const Operation& op, 
                       const TensorResidency* tensor);
    double ScoreMigrationCost(const ComputeTarget* source, 
                               const ComputeTarget* dest, 
                               uint64_t sizeBytes);
    
    // Platform-specific implementations
    bool MigrateToGPU(TensorResidency* tensor, ComputeTarget* gpu);
    bool MigrateToRAM(TensorResidency* tensor, ComputeTarget* ram);
    bool MigrateToStorage(TensorResidency* tensor, ComputeTarget* storage);
};

// =============================================================================
// GPU FABRIC MANAGER
// =============================================================================

class GPUFabric {
public:
    static GPUFabric& Instance();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Device enumeration (real hardware)
    bool EnumerateDevices();
    
    // Memory allocation (tier-aware)
    void* Allocate(uint64_t sizeBytes, ComputeTargetType preferredType);
    void Free(void* ptr);
    
    // Tensor operations
    uint64_t RegisterTensor(void* data, uint64_t sizeBytes);
    void UnregisterTensor(uint64_t handle);
    
    // Residency operations
    bool Promote(uint64_t handle, ComputeTargetType targetType);
    bool Execute(uint64_t handle, OperationType op);
    bool Migrate(uint64_t handle, ComputeTargetType source, ComputeTargetType dest);
    
    // Compute operations
    bool DispatchCompute(uint64_t handle, const void* kernelArgs, size_t argsSize);
    bool Synchronize(ComputeTargetType targetType);
    
    // Information
    FabricScheduler* GetScheduler() { return scheduler_.get(); }
    std::vector<ComputeTarget*> GetDevices();
    
private:
    GPUFabric() = default;
    ~GPUFabric() = default;
    
    GPUFabric(const GPUFabric&) = delete;
    GPUFabric& operator=(const GPUFabric&) = delete;
    
    bool initialized_ = false;
    std::unique_ptr<FabricScheduler> scheduler_;
    
    // Platform handles
    IDXGIFactory6* dxgiFactory_ = nullptr;
    
    // Real device initialization
    bool InitializeGPUTarget(ComputeTarget* target, IDXGIAdapter4* adapter);
    bool InitializeRAMTarget(ComputeTarget* target);
    bool InitializeStorageTarget(ComputeTarget* target, const wchar_t* path);
};

// =============================================================================
// C API (for integration)
// =============================================================================

extern "C" {
    // Fabric lifecycle
    __declspec(dllexport) bool RawRamXD_Initialize();
    __declspec(dllexport) void RawRamXD_Shutdown();
    
    // Device enumeration
    __declspec(dllexport) uint32_t RawRamXD_GetDeviceCount();
    __declspec(dllexport) bool RawRamXD_GetDeviceInfo(uint32_t index, ComputeTarget* info);
    
    // Memory operations
    __declspec(dllexport) void* RawRamXD_Allocate(uint64_t size, ComputeTargetType type);
    __declspec(dllexport) void RawRamXD_Free(void* ptr);
    
    // Tensor operations
    __declspec(dllexport) uint64_t RawRamXD_RegisterTensor(void* data, uint64_t size);
    __declspec(dllexport) void RawRamXD_UnregisterTensor(uint64_t handle);
    
    // Residency
    __declspec(dllexport) bool RawRamXD_Promote(uint64_t handle, ComputeTargetType type);
    __declspec(dllexport) bool RawRamXD_Execute(uint64_t handle, OperationType op);
    
    // Information
    __declspec(dllexport) bool RawRamXD_GetResidency(uint64_t handle, TensorResidency* residency);
}

} // namespace RawRamXD
