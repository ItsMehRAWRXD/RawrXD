#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace rawrxd::deep2 {

// ───────────────────────────────────────────────────────────────
// Compute device descriptor
// ───────────────────────────────────────────────────────────────
enum class DeviceType {
    CPU,
    CUDA,
    Vulkan,
    Metal,
    ROCm,
    OpenCL,
    DirectML,
    Unknown
};

struct DeviceInfo {
    uint32_t id = 0;
    DeviceType type = DeviceType::Unknown;
    std::string name;
    std::string vendor;
    uint64_t total_memory_bytes = 0;
    uint64_t free_memory_bytes = 0;
    uint32_t compute_units = 0;
    uint32_t max_compute_work_group_size = 0;
    bool supports_fp16 = false;
    bool supports_bfloat16 = false;
    bool supports_int8 = false;
    float max_clock_mhz = 0.0f;
};

// ───────────────────────────────────────────────────────────────
// Device manager — enumerates and manages compute devices
// ───────────────────────────────────────────────────────────────
class Deep2DeviceManager {
public:
    using DeviceCallback = std::function<void(const DeviceInfo&)>;

    Deep2DeviceManager();
    ~Deep2DeviceManager();

    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;

    // Enumeration
    std::vector<DeviceInfo> EnumerateDevices() const;
    std::vector<DeviceInfo> GetDevicesByType(DeviceType type) const;
    std::optional<DeviceInfo> GetDevice(uint32_t device_id) const;
    std::optional<DeviceInfo> GetDefaultDevice() const;

    // Selection
    bool SelectDevice(uint32_t device_id);
    uint32_t GetSelectedDevice() const;
    void ClearSelection();

    // Memory
    uint64_t GetAvailableMemory(uint32_t device_id) const;
    bool ReserveMemory(uint32_t device_id, uint64_t bytes);
    bool ReleaseMemory(uint32_t device_id, uint64_t bytes);

    // Properties
    bool SupportsFeature(uint32_t device_id, const std::string& feature) const;
    std::string GetDeviceName(uint32_t device_id) const;

    // Events
    void SetDeviceAddedCallback(DeviceCallback cb);
    void SetDeviceRemovedCallback(DeviceCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::deep2
