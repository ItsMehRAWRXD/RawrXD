// ============================================================================
// Multi-GPU Scheduler Implementation
// AMD AI PRO R9700 (32GB) + RX 7800 XT (16GB) Capability-Based Scheduling
// ============================================================================

#include "multi_gpu_scheduler.hpp"
#include <algorithm>
#include <cstring>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

// HIP headers (if available)
#if defined(__HIPCC__) || defined(__HIP__)
#include <hip/hip_runtime.h>
#define HAS_HIP 1
#else
#define HAS_HIP 0
#endif

// Vulkan headers
#ifdef RAWRXD_HAS_VULKAN
#include <vulkan/vulkan.h>
#define HAS_VULKAN 1
#else
#define HAS_VULKAN 0
#endif

namespace RawrXD {
namespace GPU {

// ============================================================================
// Singleton
// ============================================================================
MultiGPUScheduler& MultiGPUScheduler::instance() {
    static MultiGPUScheduler scheduler;
    return scheduler;
}

// ============================================================================
// Initialization
// ============================================================================
bool MultiGPUScheduler::initialize() {
    if (m_initialized) {
        return true;
    }

    uint32_t deviceCount = enumerateDevices();
    if (deviceCount == 0) {
        // No GPU devices found, but that's okay - we'll use CPU fallback
        return true;
    }

    m_initialized = true;
    return true;
}

bool MultiGPUScheduler::initializeWithPolicy(PlacementPolicy policy) {
    m_policy = policy;
    return initialize();
}

void MultiGPUScheduler::shutdown() {
    m_devices.clear();
    m_initialized = false;
}

// ============================================================================
// Device Enumeration (Capability-Based)
// ============================================================================
uint32_t MultiGPUScheduler::enumerateDevices() {
    m_devices.clear();

    // Try HIP first (AMD GPUs)
    probeHIPDevices();

    // Fall back to Vulkan compute
    if (m_devices.empty()) {
        probeVulkanDevices();
    }

    // Sort by VRAM size (largest first)
    std::sort(m_devices.begin(), m_devices.end(),
        [](const DeviceCapability& a, const DeviceCapability& b) {
            return a.totalVRAM > b.totalVRAM;
        });

    // Reassign device IDs after sorting
    for (size_t i = 0; i < m_devices.size(); ++i) {
        m_devices[i].deviceId = static_cast<uint32_t>(i);
    }

    return static_cast<uint32_t>(m_devices.size());
}

bool MultiGPUScheduler::probeHIPDevices() {
#if HAS_HIP
    int deviceCount = 0;
    hipError_t err = hipGetDeviceCount(&deviceCount);
    if (err != hipSuccess || deviceCount == 0) {
        return false;
    }

    for (int i = 0; i < deviceCount; ++i) {
        hipDeviceProp_t props;
        err = hipGetDeviceProperties(&props, i);
        if (err != hipSuccess) {
            continue;
        }

        DeviceCapability device;
        device.deviceId = static_cast<uint32_t>(i);
        device.deviceName = props.name;
        device.totalVRAM = props.totalGlobalMem;
        device.availableVRAM = props.totalGlobalMem; // Will be updated dynamically
        device.computeUnits = props.multiProcessorCount;
        device.maxComputeWorkGroupSize = props.maxThreadsPerBlock;
        device.supportsHIP = true;
        device.supportsVulkan = false;
        device.supportsRDNA3 = (props.major == 11); // RDNA3 is gfx11
        device.memoryBandwidth = props.memoryClockRate * props.memoryBusWidth / 8.0f / 1e6f;

        // Detect PCIe speed from device name or properties
        if (strstr(props.name, "Radeon") || strstr(props.name, "RX")) {
            // AMD AI PRO R9700 has PCIe 5.0 x8
            if (strstr(props.name, "R9700") || strstr(props.name, "AI PRO")) {
                device.pcieSpeed = PCIeLinkSpeed::Gen5_x8;
            } else {
                device.pcieSpeed = PCIeLinkSpeed::Gen4_x8;
            }
        }

        device.computeScore = calculateComputeScore(device);

        // Assign memory tier based on size
        if (device.totalVRAM >= 32ULL * 1024 * 1024 * 1024) { // 32GB+
            device.preferredTier = DeviceCapability::MemoryTier::Hot;
        } else if (device.totalVRAM >= 16ULL * 1024 * 1024 * 1024) { // 16GB+
            device.preferredTier = DeviceCapability::MemoryTier::Warm;
        } else {
            device.preferredTier = DeviceCapability::MemoryTier::Cold;
        }

        m_devices.push_back(device);
    }

    return !m_devices.empty();
#else
    return false;
#endif
}

bool MultiGPUScheduler::probeVulkanDevices() {
#if HAS_VULKAN
    // Simplified Vulkan device enumeration
    // In production, this would use proper Vulkan instance creation
    return false;
#else
    return false;
#endif
}

float MultiGPUScheduler::calculateComputeScore(const DeviceCapability& device) {
    // Calculate normalized compute score (0.0 - 1.0)
    // Based on compute units, memory bandwidth, and architecture

    float cuScore = std::min(device.computeUnits / 128.0f, 1.0f); // 128 CUs max
    float bwScore = std::min(device.memoryBandwidth / 1000.0f, 1.0f); // 1 TB/s max
    float archBonus = device.supportsRDNA3 ? 0.2f : 0.0f;

    return std::min((cuScore * 0.5f + bwScore * 0.5f) + archBonus, 1.0f);
}

// ============================================================================
// Device Queries
// ============================================================================
const std::vector<DeviceCapability>& MultiGPUScheduler::getDevices() const {
    return m_devices;
}

const DeviceCapability* MultiGPUScheduler::getDevice(uint32_t deviceId) const {
    if (deviceId >= m_devices.size()) {
        return nullptr;
    }
    return &m_devices[deviceId];
}

const DeviceCapability* MultiGPUScheduler::getLargestDevice() const {
    if (m_devices.empty()) {
        return nullptr;
    }
    // Devices are sorted by VRAM, so first is largest
    return &m_devices[0];
}

const DeviceCapability* MultiGPUScheduler::getFastestDevice() const {
    if (m_devices.empty()) {
        return nullptr;
    }

    auto it = std::max_element(m_devices.begin(), m_devices.end(),
        [](const DeviceCapability& a, const DeviceCapability& b) {
            return a.computeScore < b.computeScore;
        });

    return &(*it);
}

// ============================================================================
// Memory Management
// ============================================================================
size_t MultiGPUScheduler::getTotalVRAM() const {
    size_t total = 0;
    for (const auto& device : m_devices) {
        total += device.totalVRAM;
    }
    return total;
}

size_t MultiGPUScheduler::getAvailableVRAM() const {
    size_t available = 0;
    for (const auto& device : m_devices) {
        available += device.availableVRAM;
    }
    return available;
}

bool MultiGPUScheduler::allocateTensor(uint32_t deviceId, size_t size, void** ptr) {
    if (!ptr || deviceId >= m_devices.size()) {
        return false;
    }

#if HAS_HIP
    hipError_t err = hipSetDevice(deviceId);
    if (err != hipSuccess) {
        return false;
    }

    err = hipMalloc(ptr, size);
    if (err != hipSuccess) {
        *ptr = nullptr;
        return false;
    }

    // Update available VRAM tracking
    m_devices[deviceId].availableVRAM -= size;
    return true;
#else
    (void)size;
    *ptr = nullptr;
    return false;
#endif
}

void MultiGPUScheduler::freeTensor(uint32_t deviceId, void* ptr) {
    if (!ptr || deviceId >= m_devices.size()) {
        return;
    }

#if HAS_HIP
    hipSetDevice(deviceId);
    hipFree(ptr);
    // Note: availableVRAM tracking would need size info for accurate accounting
#endif
}

// ============================================================================
// Tensor Placement
// ============================================================================
TensorPlacement MultiGPUScheduler::placeTensor(size_t size, const std::string& tensorName) {
    (void)tensorName;

    TensorPlacement placement;
    placement.size = size;
    placement.isSharded = false;
    placement.shardIndex = 0;
    placement.shardCount = 1;

    if (m_devices.empty()) {
        placement.deviceId = 0;
        placement.offset = 0;
        return placement;
    }

    switch (m_policy) {
    case PlacementPolicy::LargestFirst:
        // Place on device with most VRAM
        placement.deviceId = getLargestDevice()->deviceId;
        break;

    case PlacementPolicy::Striped:
        // Round-robin (simplified - would need state tracking)
        placement.deviceId = 0;
        break;

    case PlacementPolicy::Pipeline:
        // Layer-wise (requires layer info)
        placement.deviceId = 0;
        break;

    case PlacementPolicy::TensorParallel:
        // Will be handled by placeTensorSharded
        placement.deviceId = 0;
        break;

    case PlacementPolicy::MoEExpert:
        // Expert placement (requires expert routing info)
        placement.deviceId = 0;
        break;

    case PlacementPolicy::EmbeddingOffload:
        // Embeddings on secondary GPU
        if (m_devices.size() > 1 && tensorName.find("embed") != std::string::npos) {
            placement.deviceId = getSecondaryDevice();
        } else {
            const auto* largest = getLargestDevice();
            placement.deviceId = largest ? largest->deviceId : 0;
        }
        break;
    }

    placement.offset = 0; // Would be calculated from allocator
    return placement;
}

std::vector<TensorPlacement> MultiGPUScheduler::placeTensorSharded(size_t size, uint32_t numShards) {
    std::vector<TensorPlacement> placements;

    if (numShards == 0 || m_devices.empty()) {
        return placements;
    }

    size_t shardSize = size / numShards;
    size_t remainder = size % numShards;

    for (uint32_t i = 0; i < numShards; ++i) {
        TensorPlacement placement;
        placement.deviceId = i % static_cast<uint32_t>(m_devices.size());
        placement.size = shardSize + (i == numShards - 1 ? remainder : 0);
        placement.isSharded = true;
        placement.shardIndex = i;
        placement.shardCount = numShards;
        placement.offset = 0;
        placements.push_back(placement);
    }

    return placements;
}

bool MultiGPUScheduler::migrateTensor(void* src, uint32_t srcDevice, void** dst, uint32_t dstDevice, size_t size) {
    if (!src || !dst || srcDevice >= m_devices.size() || dstDevice >= m_devices.size()) {
        return false;
    }

    if (srcDevice == dstDevice) {
        *dst = src;
        return true;
    }

#if HAS_HIP
    // Allocate on destination
    hipError_t err = hipSetDevice(dstDevice);
    if (err != hipSuccess) {
        return false;
    }

    err = hipMalloc(dst, size);
    if (err != hipSuccess) {
        *dst = nullptr;
        return false;
    }

    // Perform device-to-device copy (may go through host for now)
    void* hostBuffer = malloc(size);
    if (!hostBuffer) {
        hipFree(*dst);
        *dst = nullptr;
        return false;
    }

    // Src -> Host
    hipSetDevice(srcDevice);
    hipMemcpy(hostBuffer, src, size, hipMemcpyDeviceToHost);

    // Host -> Dst
    hipSetDevice(dstDevice);
    hipMemcpy(*dst, hostBuffer, size, hipMemcpyHostToDevice);

    free(hostBuffer);
    return true;
#else
    (void)size;
    *dst = nullptr;
    return false;
#endif
}

// ============================================================================
// Policy Management
// ============================================================================
void MultiGPUScheduler::setPolicy(PlacementPolicy policy) {
    m_policy = policy;
}

PlacementPolicy MultiGPUScheduler::getPolicy() const {
    return m_policy;
}

// ============================================================================
// Execution
// ============================================================================
bool MultiGPUScheduler::executeOnDevice(uint32_t deviceId, const ComputeTask& task, void* context) {
    if (deviceId >= m_devices.size()) {
        return false;
    }

#if HAS_HIP
    hipError_t err = hipSetDevice(deviceId);
    if (err != hipSuccess) {
        return false;
    }
#endif

    task(deviceId, context);
    return true;
}

bool MultiGPUScheduler::executeOnAllDevices(const ComputeTask& task) {
    bool success = true;

    for (const auto& device : m_devices) {
        if (!executeOnDevice(device.deviceId, task, nullptr)) {
            success = false;
        }
    }

    return success;
}

bool MultiGPUScheduler::executePipeline(const std::vector<ComputeTask>& stages) {
    // Execute stages sequentially on appropriate devices
    for (size_t i = 0; i < stages.size(); ++i) {
        uint32_t deviceId = static_cast<uint32_t>(i % m_devices.size());
        if (!executeOnDevice(deviceId, stages[i], nullptr)) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Synchronization
// ============================================================================
void MultiGPUScheduler::barrierAllDevices() {
#if HAS_HIP
    for (const auto& device : m_devices) {
        hipSetDevice(device.deviceId);
        hipDeviceSynchronize();
    }
#endif
}

void MultiGPUScheduler::barrierDevice(uint32_t deviceId) {
#if HAS_HIP
    if (deviceId < m_devices.size()) {
        hipSetDevice(deviceId);
        hipDeviceSynchronize();
    }
#endif
}

// ============================================================================
// Telemetry
// ============================================================================
MultiGPUScheduler::DeviceStats MultiGPUScheduler::getDeviceStats(uint32_t deviceId) const {
    DeviceStats stats{};

    if (deviceId >= m_devices.size()) {
        return stats;
    }

#if HAS_HIP
    // Get memory info
    size_t free = 0, total = 0;
    hipSetDevice(deviceId);
    hipMemGetInfo(&free, &total);

    // Calculate utilization (simplified)
    stats.utilizationPercent = 100.0f * (1.0f - static_cast<float>(free) / static_cast<float>(total));
#endif

    return stats;
}

// ============================================================================
// AMD AI PRO R9700 + RX 7800 XT Specific
// ============================================================================
bool MultiGPUScheduler::isAMDSetup() const {
    if (m_devices.size() != 2) {
        return false;
    }

    // Check for AMD device names
    bool hasR9700 = false;
    bool has7800XT = false;

    for (const auto& device : m_devices) {
        if (device.deviceName.find("R9700") != std::string::npos ||
            device.deviceName.find("AI PRO") != std::string::npos) {
            hasR9700 = true;
        }
        if (device.deviceName.find("7800") != std::string::npos) {
            has7800XT = true;
        }
    }

    return hasR9700 && has7800XT;
}

uint32_t MultiGPUScheduler::getPrimaryDevice() const {
    // Primary device is the one with most VRAM (R9700 32GB)
    const auto* device = getLargestDevice();
    return device ? device->deviceId : 0;
}

uint32_t MultiGPUScheduler::getSecondaryDevice() const {
    // Secondary device is the other one (RX 7800 XT 16GB)
    if (m_devices.size() >= 2) {
        // Devices sorted by VRAM, so index 1 is secondary
        return m_devices[1].deviceId;
    }
    return 0;
}

} // namespace GPU
} // namespace RawrXD
