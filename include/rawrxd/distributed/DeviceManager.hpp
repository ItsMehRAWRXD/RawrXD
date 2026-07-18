#pragma once

#include <vector>
#include <memory>
#include <string>
#include <mutex>
#include <functional>

namespace rawrxd {
namespace distributed {

// Device types
enum class DeviceType {
    CPU,
    CUDA_GPU,
    ROCM_GPU,
    VULKAN_DEVICE,
    METAL_DEVICE
};

// Device information
struct DeviceInfo {
    int deviceId = -1;
    DeviceType type = DeviceType::CPU;
    std::string name;
    size_t totalMemoryBytes = 0;
    size_t freeMemoryBytes = 0;
    int computeCapabilityMajor = 0;
    int computeCapabilityMinor = 0;
    int numComputeUnits = 0;
    int maxWorkGroupSize = 0;
    bool isAvailable = false;
    float utilizationPercent = 0.0f;
    float temperatureCelsius = 0.0f;
};

// Memory allocation on device
struct DeviceAllocation {
    int deviceId = -1;
    void* ptr = nullptr;
    size_t sizeBytes = 0;
    bool isPinned = false;
};

// Device manager for multi-GPU systems
class DeviceManager {
public:
    static DeviceManager& GetInstance();

    // Initialize device manager
    bool Initialize();
    
    // Discover available devices
    bool DiscoverDevices();
    
    // Get device count
    int GetDeviceCount() const;
    
    // Get device info
    DeviceInfo GetDeviceInfo(int deviceId) const;
    std::vector<DeviceInfo> GetAllDevices() const;
    
    // Get devices by type
    std::vector<int> GetGPUDevices() const;
    std::vector<int> GetAvailableDevices() const;
    
    // Select device for current thread
    bool SetActiveDevice(int deviceId);
    int GetActiveDevice() const;
    
    // Memory management
    DeviceAllocation Allocate(int deviceId, size_t sizeBytes, bool pinned = false);
    void Free(DeviceAllocation& allocation);
    void* AllocateHost(size_t sizeBytes);
    void FreeHost(void* ptr);
    
    // Memory copy
    bool CopyToDevice(const void* hostPtr, DeviceAllocation& deviceAlloc, size_t sizeBytes);
    bool CopyToHost(const DeviceAllocation& deviceAlloc, void* hostPtr, size_t sizeBytes);
    bool CopyDeviceToDevice(const DeviceAllocation& src, DeviceAllocation& dst, size_t sizeBytes);
    
    // Synchronization
    void SynchronizeDevice(int deviceId);
    void SynchronizeAll();
    
    // Memory info
    size_t GetFreeMemory(int deviceId) const;
    size_t GetTotalMemory(int deviceId) const;
    
    // Load balancing
    int SelectLeastLoadedDevice(size_t requiredMemoryBytes) const;
    std::vector<int> GetDeviceLoadRanking() const;
    
    // Monitoring
    using DeviceCallback = std::function<void(int deviceId, const DeviceInfo& info)>;
    void RegisterMonitorCallback(DeviceCallback callback);
    void StartMonitoring(std::chrono::seconds interval);
    void StopMonitoring();

private:
    DeviceManager() = default;
    ~DeviceManager() = default;
    DeviceManager(const DeviceManager&) = delete;
    DeviceManager& operator=(const DeviceManager&) = delete;

    std::vector<DeviceInfo> devices_;
    mutable std::mutex mutex_;
    int activeDevice_ = 0;
    
    // Monitoring
    std::atomic<bool> monitoring_{false};
    std::thread monitorThread_;
    std::vector<DeviceCallback> monitorCallbacks_;
    
    void MonitorLoop(std::chrono::seconds interval);
    void UpdateDeviceInfo(int deviceId);
};

// RAII device guard
class DeviceGuard {
public:
    explicit DeviceGuard(int deviceId);
    ~DeviceGuard();
    
    DeviceGuard(const DeviceGuard&) = delete;
    DeviceGuard& operator=(const DeviceGuard&) = delete;
    
    DeviceGuard(DeviceGuard&& other) noexcept;
    DeviceGuard& operator=(DeviceGuard&& other) noexcept;

private:
    int previousDevice_ = -1;
    bool active_ = false;
};

} // namespace distributed
} // namespace rawrxd
