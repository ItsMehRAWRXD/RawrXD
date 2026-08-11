// ============================================================================
// GPUDeviceRegistry.h - Phase 2: Multi-GPU Scheduler
// GPU topology discovery and device registry
// ============================================================================

#ifndef GPU_DEVICE_REGISTRY_H
#define GPU_DEVICE_REGISTRY_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <cstdint>
#include <functional>
#include <optional>

namespace Deep2 {
namespace MultiGPU {

// ============================================================================
// GPU Device Information
// ============================================================================
struct GPUDeviceInfo {
    int index = -1;
    std::string name;
    std::string vendor;
    std::string architecture;
    std::string backend; // "Vulkan", "ROCm", "CUDA"
    
    // Memory
    uint64_t totalVRAMBytes = 0;
    uint64_t freeVRAMBytes = 0;
    uint64_t usedVRAMBytes = 0;
    
    // Compute
    uint32_t computeUnits = 0;
    uint32_t maxWorkGroupSize = 0;
    
    // Capabilities
    bool supportsFP16 = false;
    bool supportsFP32 = true;
    bool supportsInt8 = false;
    bool supportsCooperativeGroups = false;
    bool supportsMemoryPools = false;
    
    // Status
    bool available = false;
    bool inUse = false;
    std::string role; // "primary", "secondary", "kv_cache", "speculative"
    
    // Performance metrics
    float utilizationPercent = 0.0f;
    float memoryBandwidthGBps = 0.0f;
    float computeThroughputTFlops = 0.0f;
};

// ============================================================================
// GPU Topology
// ============================================================================
struct GPUTopology {
    std::vector<GPUDeviceInfo> devices;
    uint64_t totalVRAMBytes = 0;
    uint64_t availableVRAMBytes = 0;
    int primaryDeviceIndex = -1;
    int secondaryDeviceIndex = -1;
    bool unifiedMemorySupported = false;
    bool peerAccessSupported = false;
};

// ============================================================================
// GPU Device Registry
// Singleton for managing GPU device discovery and state
// ============================================================================
class GPUDeviceRegistry {
public:
    static GPUDeviceRegistry& Instance();
    
    // Discovery
    bool DiscoverDevices();
    bool RefreshDeviceInfo();
    
    // Query
    size_t GetDeviceCount() const;
    std::vector<GPUDeviceInfo> GetAllDevices() const;
    std::vector<GPUDeviceInfo> GetAvailableDevices() const;
    std::optional<GPUDeviceInfo> GetDevice(int index) const;
    std::optional<GPUDeviceInfo> GetPrimaryDevice() const;
    std::optional<GPUDeviceInfo> GetSecondaryDevice() const;
    
    // Role management
    bool AssignRole(int deviceIndex, const std::string& role);
    bool ReleaseRole(int deviceIndex);
    std::string GetDeviceRole(int deviceIndex) const;
    
    // Memory tracking
    bool UpdateMemoryUsage(int deviceIndex, uint64_t usedBytes);
    uint64_t GetFreeVRAM(int deviceIndex) const;
    uint64_t GetTotalVRAM() const;
    uint64_t GetAvailableVRAM() const;
    
    // Topology
    GPUTopology GetTopology() const;
    
    // Validation
    bool ValidateConfiguration() const;
    std::vector<std::string> GetConfigurationErrors() const;
    
    // Events
    using DeviceChangeCallback = std::function<void(const GPUDeviceInfo&)>;
    void SetDeviceAddedCallback(DeviceChangeCallback cb);
    void SetDeviceRemovedCallback(DeviceChangeCallback cb);
    void SetDeviceChangedCallback(DeviceChangeCallback cb);

private:
    GPUDeviceRegistry() = default;
    ~GPUDeviceRegistry() = default;
    
    GPUDeviceRegistry(const GPUDeviceRegistry&) = delete;
    GPUDeviceRegistry& operator=(const GPUDeviceRegistry&) = delete;
    
    mutable std::mutex mutex_;
    std::vector<GPUDeviceInfo> devices_;
    
    DeviceChangeCallback onDeviceAdded_;
    DeviceChangeCallback onDeviceRemoved_;
    DeviceChangeCallback onDeviceChanged_;
    
    // Platform-specific discovery
    bool DiscoverVulkanDevices();
    bool DiscoverROCmDevices();
    bool DiscoverCUDADevices();
    
    void SortDevicesByCapability();
    void AssignDefaultRoles();
};

// ============================================================================
// C API
// ============================================================================
extern "C" {

__declspec(dllexport) int GPUDeviceRegistry_GetDeviceCount();
__declspec(dllexport) bool GPUDeviceRegistry_GetDeviceInfo(int index, GPUDeviceInfo* info);
__declspec(dllexport) uint64_t GPUDeviceRegistry_GetTotalVRAM();
__declspec(dllexport) uint64_t GPUDeviceRegistry_GetAvailableVRAM();

} // extern "C"

} // namespace MultiGPU
} // namespace Deep2

#endif // GPU_DEVICE_REGISTRY_H
