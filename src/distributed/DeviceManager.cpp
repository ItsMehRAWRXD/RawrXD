#include "rawrxd/distributed/DeviceManager.hpp"
#include <algorithm>
#include <string>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// CUDA detection
#ifdef RAWRXD_HAS_CUDA
#include <cuda_runtime.h>
#include <cuda.h>
#endif

namespace rawrxd {
namespace distributed {

DeviceManager& DeviceManager::GetInstance() {
    static DeviceManager instance;
    return instance;
}

bool DeviceManager::Initialize() {
    return DiscoverDevices();
}

bool DeviceManager::DiscoverDevices() {
    std::lock_guard<std::mutex> lock(mutex_);
    devices_.clear();
    
    // Always add CPU device
    DeviceInfo cpuDevice;
    cpuDevice.deviceId = 0;
    cpuDevice.type = DeviceType::CPU;
    cpuDevice.name = "CPU";
    
    // Get CPU memory info
#ifdef _WIN32
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        cpuDevice.totalMemoryBytes = memStatus.ullTotalPhys;
        cpuDevice.freeMemoryBytes = memStatus.ullAvailPhys;
    }
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long pageSize = sysconf(_SC_PAGE_SIZE);
    cpuDevice.totalMemoryBytes = pages * pageSize;
    cpuDevice.freeMemoryBytes = cpuDevice.totalMemoryBytes; // Approximate
#endif
    
    cpuDevice.isAvailable = true;
    devices_.push_back(cpuDevice);
    
    // Discover CUDA devices
#ifdef RAWRXD_HAS_CUDA
    int cudaDeviceCount = 0;
    cudaError_t err = cudaGetDeviceCount(&cudaDeviceCount);
    if (err == cudaSuccess && cudaDeviceCount > 0) {
        for (int i = 0; i < cudaDeviceCount; ++i) {
            cudaDeviceProp prop;
            if (cudaGetDeviceProperties(&prop, i) == cudaSuccess) {
                DeviceInfo gpuDevice;
                gpuDevice.deviceId = static_cast<int>(devices_.size());
                gpuDevice.type = DeviceType::CUDA_GPU;
                gpuDevice.name = prop.name;
                gpuDevice.totalMemoryBytes = prop.totalGlobalMem;
                gpuDevice.freeMemoryBytes = prop.totalGlobalMem; // Will be updated
                gpuDevice.computeCapabilityMajor = prop.major;
                gpuDevice.computeCapabilityMinor = prop.minor;
                gpuDevice.numComputeUnits = prop.multiProcessorCount;
                gpuDevice.maxWorkGroupSize = prop.maxThreadsPerBlock;
                gpuDevice.isAvailable = true;
                
                devices_.push_back(gpuDevice);
            }
        }
    }
#endif
    
    // Update memory info for all devices
    for (auto& device : devices_) {
        if (device.type == DeviceType::CUDA_GPU) {
            UpdateDeviceInfo(device.deviceId);
        }
    }
    
    return true;
}

int DeviceManager::GetDeviceCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(devices_.size());
}

DeviceInfo DeviceManager::GetDeviceInfo(int deviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceId >= 0 && deviceId < static_cast<int>(devices_.size())) {
        return devices_[deviceId];
    }
    return DeviceInfo();
}

std::vector<DeviceInfo> DeviceManager::GetAllDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_;
}

std::vector<int> DeviceManager::GetGPUDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> gpuDevices;
    for (const auto& device : devices_) {
        if (device.type == DeviceType::CUDA_GPU || 
            device.type == DeviceType::ROCM_GPU ||
            device.type == DeviceType::VULKAN_DEVICE) {
            gpuDevices.push_back(device.deviceId);
        }
    }
    return gpuDevices;
}

std::vector<int> DeviceManager::GetAvailableDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> available;
    for (const auto& device : devices_) {
        if (device.isAvailable) {
            available.push_back(device.deviceId);
        }
    }
    return available;
}

bool DeviceManager::SetActiveDevice(int deviceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceId >= 0 && deviceId < static_cast<int>(devices_.size())) {
        activeDevice_ = deviceId;
        
#ifdef RAWRXD_HAS_CUDA
        if (devices_[deviceId].type == DeviceType::CUDA_GPU) {
            // Map deviceId to CUDA device index (subtract 1 for CPU)
            int cudaDevice = deviceId - 1;
            cudaSetDevice(cudaDevice);
        }
#endif
        return true;
    }
    return false;
}

int DeviceManager::GetActiveDevice() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeDevice_;
}

DeviceAllocation DeviceManager::Allocate(int deviceId, size_t sizeBytes, bool pinned) {
    DeviceAllocation alloc;
    alloc.deviceId = deviceId;
    alloc.sizeBytes = sizeBytes;
    alloc.isPinned = pinned;
    
    if (deviceId == 0) {
        // CPU allocation
        if (pinned) {
            // Pinned memory for faster GPU transfers
#ifdef RAWRXD_HAS_CUDA
            cudaMallocHost(&alloc.ptr, sizeBytes);
#endif
        } else {
            alloc.ptr = malloc(sizeBytes);
        }
    } else {
        // GPU allocation
#ifdef RAWRXD_HAS_CUDA
        int prevDevice;
        cudaGetDevice(&prevDevice);
        cudaSetDevice(deviceId - 1);
        cudaMalloc(&alloc.ptr, sizeBytes);
        cudaSetDevice(prevDevice);
#endif
    }
    
    return alloc;
}

void DeviceManager::Free(DeviceAllocation& allocation) {
    if (!allocation.ptr) return;
    
    if (allocation.deviceId == 0) {
        if (allocation.isPinned) {
#ifdef RAWRXD_HAS_CUDA
            cudaFreeHost(allocation.ptr);
#endif
        } else {
            free(allocation.ptr);
        }
    } else {
#ifdef RAWRXD_HAS_CUDA
        cudaFree(allocation.ptr);
#endif
    }
    
    allocation.ptr = nullptr;
    allocation.sizeBytes = 0;
}

void* DeviceManager::AllocateHost(size_t sizeBytes) {
    return malloc(sizeBytes);
}

void DeviceManager::FreeHost(void* ptr) {
    free(ptr);
}

bool DeviceManager::CopyToDevice(const void* hostPtr, DeviceAllocation& deviceAlloc, size_t sizeBytes) {
    if (!hostPtr || !deviceAlloc.ptr) return false;
    
    if (deviceAlloc.deviceId == 0) {
        // CPU to CPU
        memcpy(deviceAlloc.ptr, hostPtr, sizeBytes);
        return true;
    }
    
#ifdef RAWRXD_HAS_CUDA
    int prevDevice;
    cudaGetDevice(&prevDevice);
    cudaSetDevice(deviceAlloc.deviceId - 1);
    cudaError_t err = cudaMemcpy(deviceAlloc.ptr, hostPtr, sizeBytes, cudaMemcpyHostToDevice);
    cudaSetDevice(prevDevice);
    return err == cudaSuccess;
#else
    return false;
#endif
}

bool DeviceManager::CopyToHost(const DeviceAllocation& deviceAlloc, void* hostPtr, size_t sizeBytes) {
    if (!deviceAlloc.ptr || !hostPtr) return false;
    
    if (deviceAlloc.deviceId == 0) {
        // CPU to CPU
        memcpy(hostPtr, deviceAlloc.ptr, sizeBytes);
        return true;
    }
    
#ifdef RAWRXD_HAS_CUDA
    int prevDevice;
    cudaGetDevice(&prevDevice);
    cudaSetDevice(deviceAlloc.deviceId - 1);
    cudaError_t err = cudaMemcpy(hostPtr, deviceAlloc.ptr, sizeBytes, cudaMemcpyDeviceToHost);
    cudaSetDevice(prevDevice);
    return err == cudaSuccess;
#else
    return false;
#endif
}

bool DeviceManager::CopyDeviceToDevice(const DeviceAllocation& src, DeviceAllocation& dst, size_t sizeBytes) {
    if (!src.ptr || !dst.ptr) return false;
    
    if (src.deviceId == dst.deviceId) {
        // Same device
        if (src.deviceId == 0) {
            memcpy(dst.ptr, src.ptr, sizeBytes);
            return true;
        }
#ifdef RAWRXD_HAS_CUDA
        cudaMemcpy(dst.ptr, src.ptr, sizeBytes, cudaMemcpyDeviceToDevice);
        return true;
#endif
    }
    
    // Cross-device copy - need to go through host
    std::vector<uint8_t> temp(sizeBytes);
    if (!CopyToHost(src, temp.data(), sizeBytes)) return false;
    return CopyToDevice(temp.data(), dst, sizeBytes);
}

void DeviceManager::SynchronizeDevice(int deviceId) {
    if (deviceId == 0) return; // CPU is always synchronized
    
#ifdef RAWRXD_HAS_CUDA
    int prevDevice;
    cudaGetDevice(&prevDevice);
    cudaSetDevice(deviceId - 1);
    cudaDeviceSynchronize();
    cudaSetDevice(prevDevice);
#endif
}

void DeviceManager::SynchronizeAll() {
    for (const auto& device : devices_) {
        if (device.type == DeviceType::CUDA_GPU) {
            SynchronizeDevice(device.deviceId);
        }
    }
}

size_t DeviceManager::GetFreeMemory(int deviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceId >= 0 && deviceId < static_cast<int>(devices_.size())) {
        return devices_[deviceId].freeMemoryBytes;
    }
    return 0;
}

size_t DeviceManager::GetTotalMemory(int deviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceId >= 0 && deviceId < static_cast<int>(devices_.size())) {
        return devices_[deviceId].totalMemoryBytes;
    }
    return 0;
}

int DeviceManager::SelectLeastLoadedDevice(size_t requiredMemoryBytes) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    int bestDevice = -1;
    size_t maxFreeMemory = 0;
    
    for (const auto& device : devices_) {
        if (device.isAvailable && device.freeMemoryBytes >= requiredMemoryBytes) {
            if (device.freeMemoryBytes > maxFreeMemory) {
                maxFreeMemory = device.freeMemoryBytes;
                bestDevice = device.deviceId;
            }
        }
    }
    
    return bestDevice;
}

std::vector<int> DeviceManager::GetDeviceLoadRanking() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::pair<int, size_t>> deviceLoads;
    for (const auto& device : devices_) {
        if (device.isAvailable) {
            deviceLoads.emplace_back(device.deviceId, device.freeMemoryBytes);
        }
    }
    
    // Sort by free memory (descending)
    std::sort(deviceLoads.begin(), deviceLoads.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::vector<int> result;
    for (const auto& pair : deviceLoads) {
        result.push_back(pair.first);
    }
    return result;
}

void DeviceManager::RegisterMonitorCallback(DeviceCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    monitorCallbacks_.push_back(callback);
}

void DeviceManager::StartMonitoring(std::chrono::seconds interval) {
    if (monitoring_.exchange(true)) return; // Already monitoring
    
    monitorThread_ = std::thread(&DeviceManager::MonitorLoop, this, interval);
}

void DeviceManager::StopMonitoring() {
    monitoring_ = false;
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

void DeviceManager::MonitorLoop(std::chrono::seconds interval) {
    while (monitoring_) {
        for (auto& device : devices_) {
            if (device.isAvailable) {
                UpdateDeviceInfo(device.deviceId);
                
                // Notify callbacks
                for (auto& callback : monitorCallbacks_) {
                    callback(device.deviceId, device);
                }
            }
        }
        
        std::this_thread::sleep_for(interval);
    }
}

void DeviceManager::UpdateDeviceInfo(int deviceId) {
    if (deviceId <= 0 || deviceId >= static_cast<int>(devices_.size())) return;
    
    auto& device = devices_[deviceId];
    
#ifdef RAWRXD_HAS_CUDA
    if (device.type == DeviceType::CUDA_GPU) {
        int prevDevice;
        cudaGetDevice(&prevDevice);
        cudaSetDevice(deviceId - 1);
        
        size_t freeMem, totalMem;
        cudaMemGetInfo(&freeMem, &totalMem);
        device.freeMemoryBytes = freeMem;
        device.totalMemoryBytes = totalMem;
        
        cudaSetDevice(prevDevice);
    }
#endif
}

// DeviceGuard implementation
DeviceGuard::DeviceGuard(int deviceId) {
    DeviceManager& manager = DeviceManager::GetInstance();
    previousDevice_ = manager.GetActiveDevice();
    if (manager.SetActiveDevice(deviceId)) {
        active_ = true;
    }
}

DeviceGuard::~DeviceGuard() {
    if (active_) {
        DeviceManager::GetInstance().SetActiveDevice(previousDevice_);
    }
}

DeviceGuard::DeviceGuard(DeviceGuard&& other) noexcept
    : previousDevice_(other.previousDevice_), active_(other.active_) {
    other.active_ = false;
}

DeviceGuard& DeviceGuard::operator=(DeviceGuard&& other) noexcept {
    if (this != &other) {
        if (active_) {
            DeviceManager::GetInstance().SetActiveDevice(previousDevice_);
        }
        previousDevice_ = other.previousDevice_;
        active_ = other.active_;
        other.active_ = false;
    }
    return *this;
}

} // namespace distributed
} // namespace rawrxd
