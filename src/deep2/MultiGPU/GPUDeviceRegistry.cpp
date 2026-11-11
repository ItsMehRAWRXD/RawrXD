// ============================================================================
// GPUDeviceRegistry.cpp - Phase 2: Multi-GPU Scheduler
// GPU topology discovery and device registry implementation
// ============================================================================

#include "GPUDeviceRegistry.h"
#include "../gpu/Deep2GPUBackend.hpp"
#include <windows.h>
#include <dxgi.h>
#include <vulkan/vulkan.h>
#include <stdio>
#include <algorithm>

#pragma comment(lib, "dxgi.lib")

namespace Deep2 {
namespace MultiGPU {

// ============================================================================
// Singleton Implementation
// ============================================================================
GPUDeviceRegistry& GPUDeviceRegistry::Instance() {
    static GPUDeviceRegistry instance;
    return instance;
}

// ============================================================================
// Device Discovery
// ============================================================================
bool GPUDeviceRegistry::DiscoverDevices() {
    std::lock_guard<std::mutex> lock(mutex_);
    devices_.clear();
    
    printf("[GPUDeviceRegistry] Starting device discovery...\n");
    
    // Try Vulkan first (preferred for AMD)
    if (DiscoverVulkanDevices()) {
        printf("[GPUDeviceRegistry] Vulkan discovery successful\n");
    }
    
    // Fallback to DXGI for additional info
    // This helps identify AMD vs NVIDIA
    
    // Sort by capability (VRAM, compute units)
    SortDevicesByCapability();
    
    // Assign default roles
    AssignDefaultRoles();
    
    printf("[GPUDeviceRegistry] Discovered %zu GPU devices\n", devices_.size());
    for (const auto& dev : devices_) {
        printf("  [%d] %s - %.2f GB VRAM - Role: %s\n",
               dev.index, dev.name.c_str(),
               dev.totalVRAMBytes / (1024.0 * 1024.0 * 1024.0),
               dev.role.c_str());
    }
    
    return !devices_.empty();
}

bool GPUDeviceRegistry::DiscoverVulkanDevices() {
    VkInstance instance = VK_NULL_HANDLE;
    
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "Deep2";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "Deep2Engine";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_2;
    
    VkInstanceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;
    
    const char* extensions[] = {
        VK_KHR_EXTERNAL_MEMORY_CAPABILITIES_EXTENSION_NAME
    };
    createInfo.enabledExtensionCount = 1;
    createInfo.ppEnabledExtensionNames = extensions;
    
    if (vkCreateInstance(&createInfo, nullptr, &instance) != VK_SUCCESS) {
        printf("[GPUDeviceRegistry] Failed to create Vulkan instance\n");
        return false;
    }
    
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    
    if (deviceCount == 0) {
        printf("[GPUDeviceRegistry] No Vulkan devices found\n");
        vkDestroyInstance(instance, nullptr);
        return false;
    }
    
    std::vector<VkPhysicalDevice> vkDevices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, vkDevices.data());
    
    int index = 0;
    for (VkPhysicalDevice device : vkDevices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(device, &props);
        
        VkPhysicalDeviceMemoryProperties memProps;
        vkGetPhysicalDeviceMemoryProperties(device, &memProps);
        
        GPUDeviceInfo info;
        info.index = index++;
        info.name = props.deviceName;
        info.vendor = std::to_string(props.vendorID);
        info.backend = "Vulkan";
        info.available = true;
        
        // Calculate VRAM
        for (uint32_t i = 0; i < memProps.memoryHeapCount; i++) {
            if (memProps.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
                info.totalVRAMBytes += memProps.memoryHeaps[i].size;
            }
        }
        info.freeVRAMBytes = info.totalVRAMBytes;
        
        // Compute capabilities
        info.computeUnits = props.limits.maxComputeWorkGroupCount[0];
        info.maxWorkGroupSize = props.limits.maxComputeWorkGroupSize[0];
        
        // Check features
        VkPhysicalDeviceFeatures features;
        vkGetPhysicalDeviceFeatures(device, &features);
        info.supportsFP16 = features.shaderFloat64; // Approximation
        
        // Detect architecture
        if (info.name.find("Radeon") != std::string::npos ||
            info.name.find("AMD") != std::string::npos) {
            if (info.name.find("9700") != std::string::npos ||
                info.name.find("Radeon AI PRO") != std::string::npos) {
                info.architecture = "RDNA4";
            } else if (info.name.find("7800") != std::string::npos ||
                       info.name.find("7900") != std::string::npos) {
                info.architecture = "RDNA3";
            } else {
                info.architecture = "RDNA";
            }
        } else if (info.name.find("NVIDIA") != std::string::npos ||
                   info.name.find("GeForce") != std::string::npos) {
            info.architecture = "CUDA";
        }
        
        devices_.push_back(info);
    }
    
    vkDestroyInstance(instance, nullptr);
    return true;
}

bool GPUDeviceRegistry::DiscoverROCmDevices() {
    // TODO: Implement ROCm discovery
    // This requires ROCm SDK
    return false;
}

bool GPUDeviceRegistry::DiscoverCUDADevices() {
    // TODO: Implement CUDA discovery
    // This requires CUDA SDK
    return false;
}

// ============================================================================
// Query Methods
// ============================================================================
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
        if (dev.available && !dev.inUse) {
            available.push_back(dev);
        }
    }
    return available;
}

std::optional<GPUDeviceInfo> GPUDeviceRegistry::GetDevice(int index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= 0 && index < (int)devices_.size()) {
        return devices_[index];
    }
    return std::nullopt;
}

std::optional<GPUDeviceInfo> GPUDeviceRegistry::GetPrimaryDevice() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& dev : devices_) {
        if (dev.role == "primary" && dev.available) {
            return dev;
        }
    }
    // Fallback to first available
    for (const auto& dev : devices_) {
        if (dev.available) {
            return dev;
        }
    }
    return std::nullopt;
}

std::optional<GPUDeviceInfo> GPUDeviceRegistry::GetSecondaryDevice() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& dev : devices_) {
        if (dev.role == "secondary" && dev.available) {
            return dev;
        }
    }
    // Fallback to any non-primary device
    for (const auto& dev : devices_) {
        if (dev.available && dev.role != "primary") {
            return dev;
        }
    }
    return std::nullopt;
}

// ============================================================================
// Role Management
// ============================================================================
bool GPUDeviceRegistry::AssignRole(int deviceIndex, const std::string& role) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceIndex >= 0 && deviceIndex < (int)devices_.size()) {
        devices_[deviceIndex].role = role;
        devices_[deviceIndex].inUse = true;
        
        if (onDeviceChanged_) {
            onDeviceChanged_(devices_[deviceIndex]);
        }
        return true;
    }
    return false;
}

bool GPUDeviceRegistry::ReleaseRole(int deviceIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceIndex >= 0 && deviceIndex < (int)devices_.size()) {
        devices_[deviceIndex].role.clear();
        devices_[deviceIndex].inUse = false;
        
        if (onDeviceChanged_) {
            onDeviceChanged_(devices_[deviceIndex]);
        }
        return true;
    }
    return false;
}

std::string GPUDeviceRegistry::GetDeviceRole(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceIndex >= 0 && deviceIndex < (int)devices_.size()) {
        return devices_[deviceIndex].role;
    }
    return "";
}

// ============================================================================
// Memory Tracking
// ============================================================================
bool GPUDeviceRegistry::UpdateMemoryUsage(int deviceIndex, uint64_t usedBytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceIndex >= 0 && deviceIndex < (int)devices_.size()) {
        devices_[deviceIndex].usedVRAMBytes = usedBytes;
        devices_[deviceIndex].freeVRAMBytes = 
            devices_[deviceIndex].totalVRAMBytes - usedBytes;
        
        if (devices_[deviceIndex].totalVRAMBytes > 0) {
            devices_[deviceIndex].utilizationPercent = 
                100.0f * usedBytes / devices_[deviceIndex].totalVRAMBytes;
        }
        return true;
    }
    return false;
}

uint64_t GPUDeviceRegistry::GetFreeVRAM(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceIndex >= 0 && deviceIndex < (int)devices_.size()) {
        return devices_[deviceIndex].freeVRAMBytes;
    }
    return 0;
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
    uint64_t available = 0;
    for (const auto& dev : devices_) {
        if (dev.available) {
            available += dev.freeVRAMBytes;
        }
    }
    return available;
}

// ============================================================================
// Topology
// ============================================================================
GPUTopology GPUDeviceRegistry::GetTopology() const {
    std::lock_guard<std::mutex> lock(mutex_);
    GPUTopology topology;
    topology.devices = devices_;
    topology.totalVRAMBytes = GetTotalVRAM();
    topology.availableVRAMBytes = GetAvailableVRAM();
    
    for (size_t i = 0; i < devices_.size(); i++) {
        if (devices_[i].role == "primary") {
            topology.primaryDeviceIndex = (int)i;
        } else if (devices_[i].role == "secondary") {
            topology.secondaryDeviceIndex = (int)i;
        }
    }
    
    // Check for peer access (simplified - would need actual Vulkan check)
    topology.peerAccessSupported = (devices_.size() >= 2);
    
    return topology;
}

// ============================================================================
// Validation
// ============================================================================
bool GPUDeviceRegistry::ValidateConfiguration() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (devices_.empty()) {
        return false;
    }
    
    bool hasPrimary = false;
    for (const auto& dev : devices_) {
        if (dev.role == "primary" && dev.available) {
            hasPrimary = true;
            break;
        }
    }
    
    return hasPrimary;
}

std::vector<std::string> GPUDeviceRegistry::GetConfigurationErrors() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> errors;
    
    if (devices_.empty()) {
        errors.push_back("No GPU devices discovered");
    }
    
    bool hasPrimary = false;
    for (const auto& dev : devices_) {
        if (dev.role == "primary") {
            hasPrimary = true;
            break;
        }
    }
    
    if (!hasPrimary) {
        errors.push_back("No primary GPU assigned");
    }
    
    return errors;
}

// ============================================================================
// Event Callbacks
// ============================================================================
void GPUDeviceRegistry::SetDeviceAddedCallback(DeviceChangeCallback cb) {
    onDeviceAdded_ = cb;
}

void GPUDeviceRegistry::SetDeviceRemovedCallback(DeviceChangeCallback cb) {
    onDeviceRemoved_ = cb;
}

void GPUDeviceRegistry::SetDeviceChangedCallback(DeviceChangeCallback cb) {
    onDeviceChanged_ = cb;
}

// ============================================================================
// Private Helpers
// ============================================================================
void GPUDeviceRegistry::SortDevicesByCapability() {
    // Sort by VRAM (descending), then by compute units
    std::sort(devices_.begin(), devices_.end(),
        [](const GPUDeviceInfo& a, const GPUDeviceInfo& b) {
            if (a.totalVRAMBytes != b.totalVRAMBytes) {
                return a.totalVRAMBytes > b.totalVRAMBytes;
            }
            return a.computeUnits > b.computeUnits;
        });
    
    // Reassign indices after sort
    for (size_t i = 0; i < devices_.size(); i++) {
        devices_[i].index = (int)i;
    }
}

void GPUDeviceRegistry::AssignDefaultRoles() {
    if (devices_.empty()) return;
    
    // Largest VRAM device becomes primary
    devices_[0].role = "primary";
    devices_[0].inUse = true;
    
    // Second device becomes secondary (if exists)
    if (devices_.size() > 1) {
        devices_[1].role = "secondary";
        devices_[1].inUse = true;
    }
    
    // Additional devices are available for specialized roles
    for (size_t i = 2; i < devices_.size(); i++) {
        devices_[i].role = "available";
        devices_[i].inUse = false;
    }
}

bool GPUDeviceRegistry::RefreshDeviceInfo() {
    // Update memory usage and other dynamic properties
    // This would query actual GPU state
    return true;
}

// ============================================================================
// C API Implementation
// ============================================================================
extern "C" {

int GPUDeviceRegistry_GetDeviceCount() {
    return (int)GPUDeviceRegistry::Instance().GetDeviceCount();
}

bool GPUDeviceRegistry_GetDeviceInfo(int index, GPUDeviceInfo* info) {
    if (!info) return false;
    auto device = GPUDeviceRegistry::Instance().GetDevice(index);
    if (device) {
        *info = *device;
        return true;
    }
    return false;
}

uint64_t GPUDeviceRegistry_GetTotalVRAM() {
    return GPUDeviceRegistry::Instance().GetTotalVRAM();
}

uint64_t GPUDeviceRegistry_GetAvailableVRAM() {
    return GPUDeviceRegistry::Instance().GetAvailableVRAM();
}

} // extern "C"

} // namespace MultiGPU
} // namespace Deep2
