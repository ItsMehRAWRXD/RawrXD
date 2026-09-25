#include "Deep2DeviceManager.hpp"
#include <map>
#include <stdexcept>

namespace rawrxd::deep2 {

class Deep2DeviceManager::Impl {
public:
    mutable std::mutex mutex_;
    bool initialized_ = false;
    std::map<uint32_t, DeviceInfo> devices_;
    uint32_t selected_device_ = UINT32_MAX;
    DeviceCallback added_cb_;
    DeviceCallback removed_cb_;

    void PopulateDummyDevices() {
        DeviceInfo cpu;
        cpu.id = 0;
        cpu.type = DeviceType::CPU;
        cpu.name = "Host CPU";
        cpu.vendor = "Generic";
        cpu.total_memory_bytes = 16ULL * 1024 * 1024 * 1024;
        cpu.free_memory_bytes = 8ULL * 1024 * 1024 * 1024;
        cpu.compute_units = 16;
        cpu.max_compute_work_group_size = 1024;
        cpu.supports_fp16 = true;
        cpu.supports_bfloat16 = false;
        cpu.supports_int8 = true;
        cpu.max_clock_mhz = 3200.0f;
        devices_[cpu.id] = cpu;
    }
};

Deep2DeviceManager::Deep2DeviceManager() : impl_(std::make_unique<Impl>()) {}
Deep2DeviceManager::~Deep2DeviceManager() = default;

bool Deep2DeviceManager::Initialize() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialized_ = true;
    impl_->PopulateDummyDevices();
    return true;
}

void Deep2DeviceManager::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialized_ = false;
    impl_->devices_.clear();
    impl_->selected_device_ = UINT32_MAX;
}

bool Deep2DeviceManager::IsInitialized() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->initialized_;
}

std::vector<DeviceInfo> Deep2DeviceManager::EnumerateDevices() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<DeviceInfo> out;
    for (const auto& [_, dev] : impl_->devices_) out.push_back(dev);
    return out;
}

std::vector<DeviceInfo> Deep2DeviceManager::GetDevicesByType(DeviceType type) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<DeviceInfo> out;
    for (const auto& [_, dev] : impl_->devices_) {
        if (dev.type == type) out.push_back(dev);
    }
    return out;
}

std::optional<DeviceInfo> Deep2DeviceManager::GetDevice(uint32_t device_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->devices_.find(device_id);
    if (it != impl_->devices_.end()) return it->second;
    return std::nullopt;
}

std::optional<DeviceInfo> Deep2DeviceManager::GetDefaultDevice() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->devices_.empty()) return std::nullopt;
    return impl_->devices_.begin()->second;
}

bool Deep2DeviceManager::SelectDevice(uint32_t device_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->devices_.count(device_id) == 0) return false;
    impl_->selected_device_ = device_id;
    return true;
}

uint32_t Deep2DeviceManager::GetSelectedDevice() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->selected_device_;
}

void Deep2DeviceManager::ClearSelection() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->selected_device_ = UINT32_MAX;
}

uint64_t Deep2DeviceManager::GetAvailableMemory(uint32_t device_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->devices_.find(device_id);
    if (it != impl_->devices_.end()) return it->second.free_memory_bytes;
    return 0;
}

bool Deep2DeviceManager::ReserveMemory(uint32_t device_id, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->devices_.find(device_id);
    if (it == impl_->devices_.end() || it->second.free_memory_bytes < bytes) return false;
    it->second.free_memory_bytes -= bytes;
    return true;
}

bool Deep2DeviceManager::ReleaseMemory(uint32_t device_id, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->devices_.find(device_id);
    if (it == impl_->devices_.end()) return false;
    it->second.free_memory_bytes = std::min(it->second.free_memory_bytes + bytes, it->second.total_memory_bytes);
    return true;
}

bool Deep2DeviceManager::SupportsFeature(uint32_t device_id, const std::string& feature) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->devices_.find(device_id);
    if (it == impl_->devices_.end()) return false;
    if (feature == "fp16") return it->second.supports_fp16;
    if (feature == "bfloat16") return it->second.supports_bfloat16;
    if (feature == "int8") return it->second.supports_int8;
    return false;
}

std::string Deep2DeviceManager::GetDeviceName(uint32_t device_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->devices_.find(device_id);
    if (it != impl_->devices_.end()) return it->second.name;
    return "";
}

void Deep2DeviceManager::SetDeviceAddedCallback(DeviceCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->added_cb_ = std::move(cb);
}

void Deep2DeviceManager::SetDeviceRemovedCallback(DeviceCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->removed_cb_ = std::move(cb);
}

} // namespace rawrxd::deep2
