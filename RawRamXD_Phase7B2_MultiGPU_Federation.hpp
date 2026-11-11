// =============================================================================
// RawRamXD_Phase7B2_MultiGPU_Federation.hpp
// Multi-GPU Fabric Federation - Unified Heterogeneous Memory Scheduler
// =============================================================================
// Extends Phase 7B.1 to support:
//   - Multiple GPUs (RX 7800 XT + RTX 4090 + RX 7900 XTX)
//   - Peer-to-peer GPU memory access
//   - Fabric federation across nodes
//   - Unified scheduling across all compute targets
// =============================================================================

#ifndef RAWRAMXD_PHASE7B2_MULTIGPU_FEDERATION_HPP
#define RAWRAMXD_PHASE7B2_MULTIGPU_FEDERATION_HPP

#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <memory>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <queue>
#include <functional>
#include <future>

#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")

namespace RawRamXD {

// =============================================================================
// Forward Declarations
// =============================================================================

class FabricNode;
class MultiGPUScheduler;
class PeerAccessManager;
class FabricFederation;

// =============================================================================
// Multi-GPU Types
// =============================================================================

enum class GPUVendor : uint8_t {
    AMD = 0,
    NVIDIA = 1,
    INTEL = 2,
    UNKNOWN = 3
};

enum class PeerAccessType : uint8_t {
    NONE = 0,           // No P2P access
    DIRECT = 1,         // Direct GPU-GPU DMA
    BRIDGE = 2,         // Through system RAM bridge
    NVLINK = 3,         // NVIDIA NVLink
    INFINITY = 4        // AMD Infinity Fabric
};

enum class FabricNodeType : uint8_t {
    LOCAL = 0,          // This machine
    REMOTE = 1,         // Network-connected node
    BRIDGE = 2          // Federation bridge node
};

enum class MigrationPath : uint8_t {
    DIRECT_P2P = 0,     // GPU0 -> GPU1 direct
    BRIDGE_RAM = 1,     // GPU0 -> RAM -> GPU1
    BRIDGE_NVME = 2,    // GPU0 -> NVMe -> GPU1
    REMOTE = 3          // Through network fabric
};

// =============================================================================
// GPU Device Extended Info (Phase 7B.2)
// =============================================================================

struct GPUDeviceInfo {
    uint32_t deviceId;
    GPUVendor vendor;
    wchar_t name[256];
    
    // Memory
    uint64_t vramTotalBytes;
    uint64_t vramAvailableBytes;
    uint64_t vramAllocatedBytes;
    
    // Performance
    uint64_t bandwidthBytesPerSec;
    uint32_t latencyNs;
    float computeScore;
    
    // Peer access
    std::vector<uint32_t> peerAccessibleDevices;  // Device IDs accessible via P2P
    PeerAccessType peerAccessType;
    
    // D3D12 handles
    ID3D12Device* d3d12Device;
    ID3D12CommandQueue* copyQueue;
    ID3D12CommandQueue* computeQueue;
    uint32_t nodeMask;
    
    // Fabric
    FabricNodeType nodeType;
    std::string nodeAddress;  // For remote nodes
};

// =============================================================================
// Fabric Node (Single compute node in federation)
// =============================================================================

class FabricNode {
public:
    FabricNode(uint32_t id, FabricNodeType type, const std::string& address = "");
    ~FabricNode();
    
    bool Initialize();
    void Shutdown();
    
    // Device management
    void RegisterGPU(GPUDeviceInfo* gpu);
    void UnregisterGPU(uint32_t deviceId);
    std::vector<GPUDeviceInfo*> GetGPUs() const;
    GPUDeviceInfo* GetGPU(uint32_t deviceId);
    
    // Memory allocation
    uint64_t AllocateVRAM(uint32_t gpuId, size_t size);
    void FreeVRAM(uint32_t gpuId, uint64_t handle);
    
    // Cross-GPU migration
    bool MigratePeerToPeer(uint32_t srcGpuId, uint64_t srcHandle,
                           uint32_t dstGpuId, uint64_t dstHandle,
                           size_t size, double* outLatencyMs);
    
    // Stats
    uint64_t GetTotalVRAM() const;
    uint64_t GetAvailableVRAM() const;
    uint64_t GetTotalAllocated() const;
    
    // Node info
    uint32_t GetId() const { return nodeId_; }
    FabricNodeType GetType() const { return nodeType_; }
    const std::string& GetAddress() const { return nodeAddress_; }
    bool IsOnline() const { return isOnline_; }

private:
    uint32_t nodeId_;
    FabricNodeType nodeType_;
    std::string nodeAddress_;
    bool isOnline_;
    
    std::unordered_map<uint32_t, GPUDeviceInfo*> gpus_;
    mutable std::mutex gpuMutex_;
    
    // Memory tracking per GPU
    std::unordered_map<uint32_t, uint64_t> allocatedPerGPU_;
};

// =============================================================================
// Peer Access Manager (P2P DMA between GPUs)
// =============================================================================

class PeerAccessManager {
public:
    PeerAccessManager();
    ~PeerAccessManager();
    
    bool Initialize(const std::vector<GPUDeviceInfo*>& gpus);
    void Shutdown();
    
    // Query P2P capabilities
    PeerAccessType QueryPeerAccess(uint32_t srcGpuId, uint32_t dstGpuId);
    bool CanAccessPeer(uint32_t srcGpuId, uint32_t dstGpuId);
    
    // Enable/disable P2P
    bool EnablePeerAccess(uint32_t srcGpuId, uint32_t dstGpuId);
    void DisablePeerAccess(uint32_t srcGpuId, uint32_t dstGpuId);
    
    // Get migration path
    MigrationPath GetOptimalMigrationPath(uint32_t srcGpuId, uint32_t dstGpuId, size_t size);
    
    // P2P copy
    bool ExecutePeerCopy(uint32_t srcGpuId, uint64_t srcHandle,
                         uint32_t dstGpuId, uint64_t dstHandle,
                         size_t size, ID3D12Fence* completionFence);

private:
    struct PeerLink {
        uint32_t srcGpu;
        uint32_t dstGpu;
        PeerAccessType accessType;
        bool enabled;
        uint64_t bandwidth;
    };
    
    std::unordered_map<uint64_t, PeerLink> peerLinks_;  // Key: (src << 32) | dst
    mutable std::mutex linkMutex_;
    
    bool initialized_;
};

// =============================================================================
// Multi-GPU Scheduler (Unified across all GPUs)
// =============================================================================

class MultiGPUScheduler {
public:
    MultiGPUScheduler();
    ~MultiGPUScheduler();
    
    bool Initialize(FabricFederation* federation);
    void Shutdown();
    
    // Scheduling policies
    enum class SchedulePolicy {
        ROUND_ROBIN = 0,        // Distribute evenly
        LOAD_BALANCED = 1,      // Based on available memory
        PERFORMANCE = 2,        // Prefer fastest GPU
        RESIDENCY = 3,          // Minimize migrations
        COST_OPTIMIZED = 4      // Minimize power/thermal
    };
    
    void SetPolicy(SchedulePolicy policy);
    
    // Tensor placement
    uint32_t SelectOptimalGPU(size_t tensorSize, const std::vector<uint32_t>& candidates);
    
    // Migration decisions
    bool ShouldMigrate(uint64_t tensorHandle, uint32_t currentGPU, uint32_t targetGPU);
    MigrationPath SelectMigrationPath(uint32_t srcGPU, uint32_t dstGPU, size_t size);
    
    // Execution
    void SubmitTensorOperation(uint64_t tensorHandle, uint32_t gpuId, 
                                std::function<void()> operation);
    
    // Stats
    struct SchedulerStats {
        uint64_t totalTensors;
        uint64_t migrationsInitiated;
        uint64_t migrationsCompleted;
        uint64_t migrationsFailed;
        double avgMigrationTimeMs;
        uint64_t p2pTransfers;
        uint64_t bridgeTransfers;
    };
    SchedulerStats GetStats() const;

private:
    FabricFederation* federation_;
    SchedulePolicy currentPolicy_;
    
    std::atomic<uint64_t> migrationsInitiated_{0};
    std::atomic<uint64_t> migrationsCompleted_{0};
    std::atomic<uint64_t> migrationsFailed_{0};
    std::atomic<uint64_t> p2pTransfers_{0};
    std::atomic<uint64_t> bridgeTransfers_{0};
    
    // Work queues per GPU
    std::unordered_map<uint32_t, std::queue<std::function<void()>>> workQueues_;
    std::mutex queueMutex_;
    
    bool initialized_;
};

// =============================================================================
// Fabric Federation (Multi-node fabric)
// =============================================================================

class FabricFederation {
public:
    static FabricFederation& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Node management
    bool RegisterNode(std::unique_ptr<FabricNode> node);
    void UnregisterNode(uint32_t nodeId);
    FabricNode* GetNode(uint32_t nodeId);
    std::vector<FabricNode*> GetAllNodes();
    FabricNode* GetLocalNode();
    
    // GPU management across federation
    std::vector<GPUDeviceInfo*> GetAllGPUs();
    GPUDeviceInfo* GetGPU(uint32_t nodeId, uint32_t deviceId);
    
    // Unified memory pool
    uint64_t GetTotalVRAM() const;
    uint64_t GetAvailableVRAM() const;
    uint64_t GetTotalAllocated() const;
    
    // Cross-node operations
    bool MigrateAcrossNodes(uint32_t srcNodeId, uint64_t srcHandle,
                            uint32_t dstNodeId, uint64_t dstHandle,
                            size_t size);
    
    // Subsystems
    PeerAccessManager* GetPeerAccessManager() { return peerAccessManager_.get(); }
    MultiGPUScheduler* GetScheduler() { return scheduler_.get(); }
    
    // Status
    bool IsInitialized() const { return initialized_; }
    uint32_t GetNodeCount() const;
    uint32_t GetGPUCount() const;

private:
    FabricFederation() = default;
    ~FabricFederation() = default;
    
    FabricFederation(const FabricFederation&) = delete;
    FabricFederation& operator=(const FabricFederation&) = delete;
    
    bool initialized_;
    std::unordered_map<uint32_t, std::unique_ptr<FabricNode>> nodes_;
    mutable std::mutex nodesMutex_;
    
    std::unique_ptr<PeerAccessManager> peerAccessManager_;
    std::unique_ptr<MultiGPUScheduler> scheduler_;
    
    uint32_t nextNodeId_;
};

// =============================================================================
// Tensor Handle (Extended for Multi-GPU)
// =============================================================================

struct FederatedTensorHandle {
    uint64_t globalId;
    uint32_t homeNode;
    uint32_t homeGPU;
    uint64_t localHandle;
    
    // Residency tracking
    uint32_t currentNode;
    uint32_t currentGPU;
    bool isResident;
    
    // Metadata
    size_t size;
    uint32_t accessCount;
    uint64_t lastAccessTick;
    float hotnessScore;
};

// =============================================================================
// C API for External Integration
// =============================================================================

extern "C" {
    // Federation
    __declspec(dllexport) bool RawRamXD_Federation_Initialize();
    __declspec(dllexport) void RawRamXD_Federation_Shutdown();
    __declspec(dllexport) uint32_t RawRamXD_Federation_GetNodeCount();
    __declspec(dllexport) uint32_t RawRamXD_Federation_GetGPUCount();
    
    // Node info
    __declspec(dllexport) bool RawRamXD_Node_GetInfo(uint32_t nodeId, 
                                                      wchar_t* name, 
                                                      size_t nameLen,
                                                      uint64_t* vramTotal,
                                                      uint64_t* vramAvailable);
    
    // GPU info
    __declspec(dllexport) bool RawRamXD_GPU_GetInfo(uint32_t gpuId,
                                                     wchar_t* name,
                                                     size_t nameLen,
                                                     GPUVendor* vendor,
                                                     uint64_t* vramTotal,
                                                     uint64_t* vramAvailable);
    
    // Allocation
    __declspec(dllexport) uint64_t RawRamXD_Allocate(uint32_t preferredGPU, size_t size);
    __declspec(dllexport) void RawRamXD_Free(uint64_t handle);
    
    // Migration
    __declspec(dllexport) bool RawRamXD_Migrate(uint64_t handle, uint32_t targetGPU);
    __declspec(dllexport) bool RawRamXD_MigratePeerToPeer(uint64_t handle, 
                                                          uint32_t srcGPU, 
                                                          uint32_t dstGPU);
    
    // Scheduling
    __declspec(dllexport) uint32_t RawRamXD_Scheduler_SelectGPU(size_t size);
    __declspec(dllexport) void RawRamXD_Scheduler_SetPolicy(int policy);
    
    // Stats
    __declspec(dllexport) uint64_t RawRamXD_Stats_GetTotalVRAM();
    __declspec(dllexport) uint64_t RawRamXD_Stats_GetAvailableVRAM();
    __declspec(dllexport) uint64_t RawRamXD_Stats_GetTotalAllocated();
}

} // namespace RawRamXD

#endif // RAWRAMXD_PHASE7B2_MULTIGPU_FEDERATION_HPP