// ============================================================================
// multi_gpu.h — Multi-GPU Inference Distribution Interface
// ============================================================================
// Declares layer-parallel dispatch across multiple GPUs using VRAM ratios.
// Supports AMD GPUs via HIP and NVIDIA via CUDA (via runtime detection).
//
// PATTERN:   No exceptions. No std::function. Raw function pointers only.
// THREADING: Singleton with std::mutex. Thread-safe.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>

namespace RawrXD::Enterprise {

// Forward declarations
struct GPUDeviceInfo;
struct LayerAssignment;
struct TopologyLink;
struct GPULoadStats;
struct DispatchStats;
struct MultiGPUResult;

// Dispatch strategies for multi-GPU inference
enum class DispatchStrategy {
    LayerParallel,    // Distribute transformer layers across GPUs
    TensorParallel,   // Split individual tensors across GPUs (requires high bandwidth)
    PipelineParallel, // Pipeline micro-batches across GPUs
    DataParallel,     // Replicate model on each GPU, split data
    Hybrid,           // Combination of above
    RoundRobin,       // Simple round-robin assignment
    LoadBased,        // Dynamic assignment based on current load
    MemoryAware       // Assign based on available memory
};

// Link types for GPU topology
enum class LinkType {
    None,    // No direct link
    PCIe,    // PCIe interconnect
    NVLink,  // NVIDIA NVLink
    XGMI     // AMD Infinity Fabric / XGMI
};

// GPU device information
struct GPUDeviceInfo {
    uint32_t deviceId;           // Device index (0-based)
    const char* name;            // Device name (e.g., "AMD Radeon RX 7800 XT")
    const char* vendor;          // "AMD" or "NVIDIA"
    uint64_t vramBytes;          // Total VRAM in bytes
    uint64_t vramFreeBytes;      // Available VRAM in bytes
    uint32_t computeUnits;       // Number of compute units/CUs/SMs
    int pcieGen;                 // PCIe generation (3, 4, 5)
    int pcieLanes;               // Number of PCIe lanes (x16, x8, etc.)
    float pcieBandwidthGBs;      // Theoretical PCIe bandwidth GB/s
    bool supportsP2P;            // Peer-to-peer access supported
    bool available;              // Device is available for use
};

// Layer assignment for a specific GPU
struct LayerAssignment {
    uint32_t deviceId;           // Target GPU device ID
    uint32_t startLayer;         // First layer index (inclusive)
    uint32_t endLayer;           // Last layer index (inclusive)
    uint64_t vramBudgetBytes;    // VRAM budget for this assignment
    DispatchStrategy strategy;   // Strategy used for assignment
    uint32_t tensorSplitFactor;  // For tensor parallelism: split factor
};

// Topology link between two GPUs
struct TopologyLink {
    uint32_t srcDevice;          // Source device ID
    uint32_t dstDevice;          // Destination device ID
    LinkType type;               // Link type
    float bandwidthGBs;          // Bandwidth in GB/s
    float latencyUs;             // Latency in microseconds
};

// GPU load statistics
struct GPULoadStats {
    uint32_t deviceId;           // Device ID
    float utilization;           // GPU utilization (0.0 - 1.0)
    uint32_t layersAssigned;     // Number of layers assigned
    uint64_t tensorsProcessed;   // Tensors processed in current batch
    uint64_t memoryUsedBytes;    // Current memory usage
    float throughputToksPerSec;  // Measured throughput
};

// Dispatch statistics
struct DispatchStats {
    uint64_t totalDispatches;    // Total number of dispatches
    uint32_t lastBatchId;        // Last batch ID dispatched
    uint32_t lastAssignmentCount;// Number of assignments in last dispatch
    DispatchStrategy lastStrategy;// Strategy used in last dispatch
};

// Result type for MultiGPU operations
struct MultiGPUResult {
    bool success;
    int errorCode;
    const char* detail;

    static MultiGPUResult ok(const char* msg = nullptr) {
        return {true, 0, msg ? msg : "OK"};
    }
    static MultiGPUResult error(const char* msg, int code = -1) {
        return {false, code, msg ? msg : "Error"};
    }
};

// Callback types
using DispatchCompleteCallback = void (*)(uint32_t batchId, float elapsedMs);
using HealthChangeCallback = void (*)(uint32_t deviceId, bool healthy);

// Multi-GPU Manager singleton
class MultiGPUManager {
public:
    // Singleton access
    static MultiGPUManager& Instance();

    // Lifecycle
    MultiGPUResult Initialize();
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Device enumeration
    uint32_t GetDeviceCount() const;
    const GPUDeviceInfo& GetDeviceInfo(uint32_t deviceId) const;
    const std::vector<GPUDeviceInfo>& GetAllDevices() const;

    // Topology
    MultiGPUResult DetectTopology();
    const std::vector<TopologyLink>& GetTopologyLinks() const;
    bool SupportsP2P(uint32_t srcDevice, uint32_t dstDevice) const;

    // Strategy management
    MultiGPUResult SetStrategy(DispatchStrategy strategy);
    DispatchStrategy GetStrategy() const;
    const char* GetStrategyName(DispatchStrategy strategy) const;

    // Layer assignment (for layer-parallel dispatch)
    MultiGPUResult BuildLayerAssignments(uint32_t totalLayers,
                                         uint64_t modelBytes,
                                         DispatchStrategy strategy);
    const std::vector<LayerAssignment>& GetLayerAssignments() const;
    void ClearLayerAssignments();

    // Dispatch execution
    MultiGPUResult DispatchBatch(uint32_t batchId,
                                  uint32_t totalLayers,
                                  uint64_t modelBytes,
                                  DispatchStrategy strategy);
    DispatchStats GetDispatchStats() const;

    // Load monitoring
    std::vector<GPULoadStats> GetLoadStats() const;
    float GetTotalThroughput() const;
    uint64_t GetTotalVRAM() const;
    uint64_t GetFreeVRAM() const;

    // Health monitoring
    bool AllDevicesHealthy() const;
    MultiGPUResult RunHealthCheck();

    // Callbacks
    void SetDispatchCompleteCallback(DispatchCompleteCallback cb) { m_onDispatchComplete = cb; }
    void SetHealthChangeCallback(HealthChangeCallback cb) { m_onHealthChange = cb; }

    // Status reporting
    std::string GenerateStatusReport() const;
    std::string GenerateTopologyReport() const;

private:
    MultiGPUManager() = default;
    ~MultiGPUManager() = default;
    MultiGPUManager(const MultiGPUManager&) = delete;
    MultiGPUManager& operator=(const MultiGPUManager&) = delete;

    MultiGPUResult enumerateDevices();

    mutable std::mutex m_mutex;
    bool m_initialized = false;
    std::vector<GPUDeviceInfo> m_devices;
    std::vector<TopologyLink> m_topology;
    std::vector<LayerAssignment> m_assignments;
    DispatchStrategy m_strategy = DispatchStrategy::LayerParallel;
    DispatchStats m_dispatchStats{};

    DispatchCompleteCallback m_onDispatchComplete = nullptr;
    HealthChangeCallback m_onHealthChange = nullptr;
};

} // namespace RawrXD::Enterprise
