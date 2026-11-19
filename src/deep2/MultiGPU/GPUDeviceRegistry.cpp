// ============================================================================
// GPUDeviceRegistry.cpp - GPU device enumeration and management
// Supports AMD Radeon AI PRO R9700 32GB and Radeon RX 7800 XT 16GB
// ============================================================================

#include "GPUDeviceRegistry.h"
#include <algorithm>
#include <sstream>
#include <set>

namespace Deep2 {
namespace MultiGPU {

GPUDeviceRegistry& GPUDeviceRegistry::Instance() {
    static GPUDeviceRegistry instance;
    return instance;
}

bool GPUDeviceRegistry::DiscoverDevices() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    devices_.clear();
    
    // Try Vulkan first (primary path for AMD GPUs)
    if (DiscoverVulkanDevices()) {
        // Sort devices by capability
        SortDevicesByCapability();
        AssignDefaultRoles();
        return true;
    }
    
    // Fallback to ROCm/HIP
    if (DiscoverROCmDevices()) {
        SortDevicesByCapability();
        AssignDefaultRoles();
        return true;
    }
    
    // Fallback to CUDA (unlikely on AMD hardware but include for completeness)
    if (DiscoverCUDADevices()) {
        SortDevicesByCapability();
        AssignDefaultRoles();
        return true;
    }
    
    return false;
}

bool GPUDeviceRegistry::RefreshDeviceInfo() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Re-discover all devices
    devices_.clear();
    
    if (!DiscoverVulkanDevices()) {
        if (!DiscoverROCmDevices()) {
            if (!DiscoverCUDADevices()) {
                return false;
            }
        }
    }
    
    SortDevicesByCapability();
    AssignDefaultRoles();
    return true;
}

size_t GPUDeviceRegistry::GetDeviceCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.size();
}

std::vector<GPUDeviceInfo> GPUDeviceRegistry::GetAllDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_;
}

std::vector<GPUDeviceInfo> GPUDeviceRegistry::GetAvailableDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<GPUDeviceInfo> available;
    for (const auto& dev : devices_) {
        if (dev.available) {
            available.push_back(dev);
        }
    }
    return available;
}

std::optional<GPUDeviceInfo> GPUDeviceRegistry::GetDevice(int index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= 0 && static_cast<size_t>(index) < devices_.size()) {
        return devices_[index];
    }
    return std::nullopt;
}

std::optional<GPUDeviceInfo> GPUDeviceRegistry::GetPrimaryDevice() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& dev : devices_) {
        if (dev.available && dev.isPrimary) {
            return dev;
        }
    }
    return std::nullopt;
}

std::optional<GPUDeviceInfo> GPUDeviceRegistry::GetSecondaryDevice() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& dev : devices_) {
        if (dev.available && dev.isSecondary) {
            return dev;
        }
    }
    return std::nullopt;
}

bool GPUDeviceRegistry::AssignRole(int deviceIndex, const std::string& role) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (deviceIndex < 0 || static_cast<size_t>(deviceIndex) >= devices_.size()) {
        return false;
    }
    
    auto& dev = devices_[deviceIndex];
    if (!dev.available) {
        return false;
    }
    
    dev.role = role;
    
    if (role == "primary") {
        // Mark all others as not primary
        for (auto& d : devices_) {
            d.isPrimary = false;
        }
        dev.isPrimary = true;
    } else if (role == "secondary") {
        dev.isSecondary = true;
    } else {
        dev.isPrimary = false;
        dev.isSecondary = false;
    }
    
    return true;
}

bool GPUDeviceRegistry::ReleaseRole(int deviceIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (deviceIndex < 0 || static_cast<size_t>(deviceIndex) >= devices_.size()) {
        return false;
    }
    
    devices_[deviceIndex].isPrimary = false;
    devices_[deviceIndex].isSecondary = false;
    return true;
}

std::string GPUDeviceRegistry::GetDeviceRole(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (deviceIndex < 0 || static_cast<size_t>(deviceIndex) >= devices_.size()) {
        return "none";
    }
    
    return devices_[deviceIndex].role;
}

bool GPUDeviceRegistry::UpdateMemoryUsage(int deviceIndex, uint64_t usedBytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (deviceIndex < 0 || static_cast<size_t>(deviceIndex) >= devices_.size()) {
        return false;
    }
    
    devices_[deviceIndex].usedVRAMBytes = usedBytes;
    return true;
}

uint64_t GPUDeviceRegistry::GetFreeVRAM(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (deviceIndex < 0 || static_cast<size_t>(deviceIndex) >= devices_.size()) {
        return 0;
    }
    
    const auto& dev = devices_[deviceIndex];
    return dev.totalVRAMBytes - dev.usedVRAMBytes;
}

uint64_t GPUDeviceRegistry::GetTotalVRAM() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& dev : devices_) {
        total += dev.totalVRAMBytes;
    }
    return total;
}

uint64_t GPUDeviceRegistry::GetAvailableVRAM() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& dev : devices_) {
        if (dev.available) {
            total += dev.totalVRAMBytes - dev.usedVRAMBytes;
        }
    }
    return total;
}

GPUTopology GPUDeviceRegistry::GetTopology() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return deviceTopology_;
}

bool GPUDeviceRegistry::ValidateConfiguration() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> errors;
    
    // Check that at least one device is available
    bool hasAvailable = false;
    for (const auto& dev : devices_) {
        if (dev.available) {
            hasAvailable = true;
            break;
        }
    }
    if (!hasAvailable) {
        errors.push_back("No GPU devices available");
    }
    
    // Check that primary device is assigned
    bool hasPrimary = false;
    for (const auto& dev : devices_) {
        if (dev.available && dev.isPrimary) {
            hasPrimary = true;
            break;
        }
    }
    if (!hasPrimary && !devices_.empty()) {
        errors.push_back("No primary device assigned");
    }
    
    return errors.empty();
}

std::vector<std::string> GPUDeviceRegistry::GetConfigurationErrors() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return GetConfigurationErrors();
}

bool GPUDeviceRegistry::DiscoverVulkanDevices() {
    // Vulkan device discovery
    // This uses Vulkan API to enumerate physical devices
    // For now, return false as we need actual Vulkan initialization
    // which requires VkInstance creation
    return false;
}

bool GPUDeviceRegistry::DiscoverROCmDevices() {
    // ROCm device discovery
    // For now, return false as we need ROCm runtime
    return false;
}

bool GPUDeviceRegistry::DiscoverCUDADevices() {
    // CUDA device discovery
    // Not applicable for AMD GPUs
    return false;
}

void GPUDeviceRegistry::SortDevicesByCapability() {
    std::sort(devices_.begin(), devices_.end(),
        [](const GPUDeviceInfo& a, const GPUDeviceInfo& b) {
            // Sort by compute score (higher = better)
            return a.computeUnits > b.computeUnits;
        });
}

void GPUDeviceRegistry::AssignDefaultRoles() {
    if (devices_.empty()) return;
    
    // First available device becomes primary
    for (auto& dev : devices_) {
        if (dev.available && !dev.isPrimary) {
            dev.isPrimary = true;
            break;
        }
    }
    
    // Second available device becomes secondary
    int secondaryCount = 0;
    for (auto& dev : devices_) {
        if (dev.available && !dev.isPrimary && secondaryCount == 0) {
            dev.isSecondary = true;
            secondaryCount++;
            break;
        }
    }
}

} // namespace MultiGPU
} // namespace Deep2