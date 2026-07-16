// ============================================================================
// Multi-GPU Scheduler for AMD AI PRO R9700 + RX 7800 XT Setup
// Capability-based device enumeration with intelligent tensor placement
// ============================================================================

#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace RawrXD {
namespace GPU {

// ============================================================================
// PCIe Link Speed Enumeration (must be defined before DeviceCapability)
// ============================================================================
enum class PCIeLinkSpeed {
    Gen3_x4 = 0,
    Gen3_x8 = 1,
    Gen3_x16 = 2,
    Gen4_x4 = 3,
    Gen4_x8 = 4,
    Gen4_x16 = 5,
    Gen5_x8 = 6,    // AMD AI PRO R9700
    Gen5_x16 = 7
};

// ============================================================================
// Device Capability Descriptor
// ============================================================================
struct DeviceCapability {
    uint32_t deviceId;              // 0, 1, 2...
    std::string deviceName;         // "AMD AI PRO R9700" or "RX 7800 XT"
    size_t totalVRAM;               // Bytes (32GB = 34359738368)
    size_t availableVRAM;           // Current free memory
    uint32_t computeUnits;          // Number of CUs
    uint32_t maxComputeWorkGroupSize;
    bool supportsHIP;               // AMD HIP support
    bool supportsVulkan;            // Vulkan compute support
    bool supportsRDNA3;             // RDNA3 architecture features
    float computeScore;             // Normalized compute capability (0.0-1.0)
    float memoryBandwidth;        // GB/s
    PCIeLinkSpeed pcieSpeed;        // Gen4 x8, Gen5 x8, etc.
    
    // Memory pool assignment
    enum class MemoryTier {
        Hot,        // Frequently accessed (largest GPU)
        Warm,       // Moderate access (secondary GPU)
        Cold        // Offload/storage
    } preferredTier;
};

// ============================================================================
// Tensor Placement Policy
// ============================================================================
enum class PlacementPolicy {
    LargestFirst,       // Put largest tensors on biggest GPU
    Striped,           // Round-robin across devices
    Pipeline,          // Layer-wise distribution
    TensorParallel,    // Split tensors across devices
    MoEExpert,         // Expert placement for MoE models
    EmbeddingOffload   // Keep embeddings on CPU/secondary
};

struct TensorPlacement {
    uint32_t deviceId;
    size_t offset;      // Offset within device memory
    size_t size;        // Size of this shard
    bool isSharded;     // True if tensor is split
    uint32_t shardIndex;// Which shard (for tensor parallelism)
    uint32_t shardCount; // Total shards
};

// ============================================================================
// Multi-GPU Scheduler
// ============================================================================
class MultiGPUScheduler {
public:
    static MultiGPUScheduler& instance();
    
    // Initialization
    bool initialize();
    bool initializeWithPolicy(PlacementPolicy policy);
    void shutdown();
    
    // Device enumeration (capability-based, not hardcoded)
    uint32_t enumerateDevices();
    const std::vector<DeviceCapability>& getDevices() const;
    const DeviceCapability* getDevice(uint32_t deviceId) const;
    const DeviceCapability* getLargestDevice() const;
    const DeviceCapability* getFastestDevice() const;
    
    // Memory management
    size_t getTotalVRAM() const;
    size_t getAvailableVRAM() const;
    bool allocateTensor(uint32_t deviceId, size_t size, void** ptr);
    void freeTensor(uint32_t deviceId, void* ptr);
    
    // Tensor placement
    TensorPlacement placeTensor(size_t size, const std::string& tensorName);
    std::vector<TensorPlacement> placeTensorSharded(size_t size, uint32_t numShards);
    bool migrateTensor(void* src, uint32_t srcDevice, void** dst, uint32_t dstDevice, size_t size);
    
    // Scheduling
    void setPolicy(PlacementPolicy policy);
    PlacementPolicy getPolicy() const;
    
    // Execution
    using ComputeTask = std::function<void(uint32_t deviceId, void* context)>;
    bool executeOnDevice(uint32_t deviceId, const ComputeTask& task, void* context);
    bool executeOnAllDevices(const ComputeTask& task);
    bool executePipeline(const std::vector<ComputeTask>& stages);
    
    // Synchronization
    void barrierAllDevices();
    void barrierDevice(uint32_t deviceId);
    
    // Telemetry
    struct DeviceStats {
        uint64_t bytesTransferredH2D;
        uint64_t bytesTransferredD2H;
        uint64_t computeCycles;
        uint64_t idleCycles;
        float temperatureCelsius;
        float powerWatts;
        float utilizationPercent;
    };
    DeviceStats getDeviceStats(uint32_t deviceId) const;
    
    // AMD AI PRO R9700 + RX 7800 XT specific
    bool isAMDSetup() const;
    uint32_t getPrimaryDevice() const;    // Returns 0 (R9700 32GB)
    uint32_t getSecondaryDevice() const;  // Returns 1 (RX 7800 XT 16GB)
    
private:
    MultiGPUScheduler() = default;
    ~MultiGPUScheduler() = default;
    MultiGPUScheduler(const MultiGPUScheduler&) = delete;
    MultiGPUScheduler& operator=(const MultiGPUScheduler&) = delete;
    
    std::vector<DeviceCapability> m_devices;
    PlacementPolicy m_policy = PlacementPolicy::LargestFirst;
    bool m_initialized = false;
    
    // Platform-specific handles
    void* m_hipContext = nullptr;
    void* m_vulkanContext = nullptr;
    
    bool probeHIPDevices();
    bool probeVulkanDevices();
    float calculateComputeScore(const DeviceCapability& device);
};

// ============================================================================
// Convenience Functions
// ============================================================================
inline MultiGPUScheduler& GetMultiGPUScheduler() {
    return MultiGPUScheduler::instance();
}

// Quick placement helpers
inline TensorPlacement PlaceOnLargestGPU(size_t size) {
    return GetMultiGPUScheduler().placeTensor(size, "auto");
}

inline TensorPlacement PlaceOnSecondaryGPU(size_t size) {
    uint32_t secondaryDeviceId = GetMultiGPUScheduler().getSecondaryDevice();
    const auto* device = GetMultiGPUScheduler().getDevice(secondaryDeviceId);
    if (device) {
        TensorPlacement placement;
        placement.deviceId = device->deviceId;
        placement.size = size;
        placement.isSharded = false;
        return placement;
    }
    return PlaceOnLargestGPU(size);
}

} // namespace GPU
} // namespace RawrXD
