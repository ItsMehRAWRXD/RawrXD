// ============================================================================
// enterprise/multi_gpu.h — Multi-GPU Inference Distribution Interface
// ============================================================================
// Declares MultiGPUManager singleton and supporting types. Full definitions
// live in src/core/multi_gpu.cpp (single compilation unit).
//
// RULE: NO INLINE DEFINITIONS HERE — .cpp already defines everything.
// ============================================================================

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <mutex>

namespace RawrXD::Enterprise {

// ============================================================================
// Link Types
// ============================================================================
enum class LinkType : uint32_t {
    PCIe = 0,
    NVLink,
    XGMI,
    None
};

// ============================================================================
// Dispatch Strategies
// ============================================================================
enum class DispatchStrategy : uint32_t {
    RoundRobin = 0,
    PCIeTopology,
    LoadBalanced,
    LayerParallel,
    TensorParallel,
    PipelineParallel,
    DataParallel,
    Hybrid
};

// ============================================================================
// GPU Device Info
// ============================================================================
struct GPUDeviceInfo {
    uint32_t deviceId;
    const char* name;
    const char* vendor;
    uint64_t vramBytes;
    uint64_t vramFreeBytes;
    uint32_t computeUnits;
    uint32_t pcieGen;
    uint32_t pcieLanes;
    float    pcieBandwidthGBs;
    bool     supportsP2P;
    bool     available;
};

// ============================================================================
// Topology Link
// ============================================================================
struct TopologyLink {
    uint32_t srcDevice;
    uint32_t dstDevice;
    LinkType type;
    float    bandwidthGBs;
    float    latencyUs;
};

// ============================================================================
// Multi-GPU Operation Result
// ============================================================================
struct MultiGPUResult {
    bool        success;
    int         code;
    std::string message;

    static MultiGPUResult ok(const char* msg);
    static MultiGPUResult error(const char* msg, int code);
};

// ============================================================================
// Layer Assignment
// ============================================================================
struct LayerAssignment {
    uint32_t         deviceId;
    uint32_t         startLayer;
    uint32_t         endLayer;
    uint64_t         vramBudgetBytes;
    DispatchStrategy strategy;
    uint32_t         tensorSplitFactor;
};

// ============================================================================
// GPU Load Statistics
// ============================================================================
struct GPULoadStats {
    uint32_t deviceId;
    float    utilization;
    uint64_t layersAssigned;
    uint64_t tensorsProcessed;
    uint64_t memoryUsedBytes;
    float    throughputToksPerSec;
};

// ============================================================================
// Dispatch Statistics
// ============================================================================
struct DispatchStats {
    uint32_t         totalDispatches;
    uint32_t         lastBatchId;
    float            lastElapsedMs;
    DispatchStrategy lastStrategy;
    uint32_t         lastAssignmentCount;
};

// ============================================================================
// Multi-GPU Manager Singleton
// ============================================================================
class MultiGPUManager {
public:
    static MultiGPUManager& Instance();

    // Lifecycle
    MultiGPUResult Initialize();
    void           Shutdown();

    // Device Enumeration
    MultiGPUResult              enumerateDevices();
    uint32_t                    GetDeviceCount() const;
    const GPUDeviceInfo&        GetDeviceInfo(uint32_t deviceId) const;
    const std::vector<GPUDeviceInfo>& GetAllDevices() const;

    // Topology
    MultiGPUResult                    DetectTopology();
    const std::vector<TopologyLink>&  GetTopologyLinks() const;
    bool                              SupportsP2P(uint32_t srcDevice,
                                                  uint32_t dstDevice) const;

    // Dispatch Configuration
    MultiGPUResult   SetStrategy(DispatchStrategy strategy);
    DispatchStrategy GetStrategy() const;
    const char*      GetStrategyName(DispatchStrategy strategy) const;

    // Load Monitoring
    std::vector<GPULoadStats> GetLoadStats() const;
    float                     GetTotalThroughput() const;
    uint64_t                  GetTotalVRAM() const;
    uint64_t                  GetFreeVRAM() const;

    // Health
    bool           AllDevicesHealthy() const;
    MultiGPUResult RunHealthCheck();

    // Dispatch Planning
    MultiGPUResult BuildLayerAssignments(uint32_t totalLayers,
                                         uint64_t modelBytes,
                                         DispatchStrategy strategy);
    MultiGPUResult DispatchBatch(uint32_t batchId,
                                 uint32_t totalLayers,
                                 uint64_t modelBytes,
                                 DispatchStrategy strategy);
    DispatchStats                 GetDispatchStats() const;
    const std::vector<LayerAssignment>& GetLayerAssignments() const;
    void                          ClearLayerAssignments();

    // Status Reports
    std::string GenerateStatusReport() const;
    std::string GenerateTopologyReport() const;

    // State query (used by local_ai_core.cpp)
    bool IsInitialized() const;

    // Callback types (raw function pointers only)
    using HealthChangeCallback   = void (*)(uint32_t deviceId, bool healthy);
    using DispatchCompleteCallback = void (*)(uint32_t batchId, float elapsedMs);

private:
    mutable std::mutex m_mutex;
    std::vector<GPUDeviceInfo>   m_devices;
    std::vector<TopologyLink>    m_topology;
    std::vector<LayerAssignment> m_assignments;
    DispatchStrategy             m_strategy;
    bool                         m_initialized;
    HealthChangeCallback         m_onHealthChange;
    DispatchCompleteCallback     m_onDispatchComplete;
    DispatchStats                m_dispatchStats;
};

} // namespace RawrXD::Enterprise
