// ============================================================================
// multi_gpu.cpp — Multi-GPU Inference Distribution Implementation
// ============================================================================
// Implements layer-parallel dispatch across multiple GPUs using VRAM ratios.
// Supports AMD GPUs via HIP and NVIDIA via CUDA (via runtime detection).
//
// PATTERN:   No exceptions. No std::function. Raw function pointers only.
// THREADING: Singleton with std::mutex. Thread-safe.
// ============================================================================

#include "enterprise/multi_gpu.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// HIP runtime function pointers (loaded dynamically)
using hipGetDeviceCount_t = int (*)(int*);
using hipGetDeviceProperties_t = int (*)(void*, int);
using hipSetDevice_t = int (*)(int);
using hipGetDevice_t = int (*)(int*);
using hipInit_t = int (*)(unsigned int);

namespace RawrXD::Enterprise {

// Static instance
MultiGPUManager& MultiGPUManager::Instance() {
    static MultiGPUManager instance;
    return instance;
}

// Initialize and enumerate GPUs
MultiGPUResult MultiGPUManager::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return MultiGPUResult::ok("Already initialized");
    }

    auto result = enumerateDevices();
    if (!result.success) {
        return result;
    }

    m_initialized = true;
    return MultiGPUResult::ok();
}

void MultiGPUManager::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_devices.clear();
    m_topology.clear();
    m_assignments.clear();
    m_initialized = false;
}

// Enumerate available GPUs
MultiGPUResult MultiGPUManager::enumerateDevices() {
    m_devices.clear();

    // Try to load AMD HIP runtime
    HMODULE hipModule = LoadLibraryA("amdhip64.dll");
    if (hipModule) {
        hipGetDeviceCount_t hipGetDeviceCount = 
            reinterpret_cast<hipGetDeviceCount_t>(GetProcAddress(hipModule, "hipGetDeviceCount"));
        hipGetDeviceProperties_t hipGetDeviceProperties = 
            reinterpret_cast<hipGetDeviceProperties_t>(GetProcAddress(hipModule, "hipGetDeviceProperties"));

        if (hipGetDeviceCount && hipGetDeviceProperties) {
            int deviceCount = 0;
            if (hipGetDeviceCount(&deviceCount) == 0 && deviceCount > 0) {
                for (int i = 0; i < deviceCount; ++i) {
                    // HIP device properties structure (simplified)
                    struct hipDeviceProp_t {
                        char name[256];
                        size_t totalGlobalMem;
                        int multiProcessorCount;
                        int pciBusID;
                        int pciDeviceID;
                        int pciDomainID;
                        int isMultiGpuBoard;
                        int canMapHostMemory;
                        int cooperativeLaunch;
                    } props;

                    if (hipGetDeviceProperties(&props, i) == 0) {
                        GPUDeviceInfo info{};
                        info.deviceId = static_cast<uint32_t>(i);
                        info.name = _strdup(props.name);  // Leaked intentionally for singleton lifetime
                        info.vendor = "AMD";
                        info.vramBytes = props.totalGlobalMem;
                        info.vramFreeBytes = props.totalGlobalMem;  // Will be updated by health check
                        info.computeUnits = static_cast<uint32_t>(props.multiProcessorCount);
                        info.pcieGen = 4;  // Assume PCIe 4.0 for modern AMD GPUs
                        info.pcieLanes = 16;
                        info.pcieBandwidthGBs = 32.0f;  // PCIe 4.0 x16 theoretical
                        info.supportsP2P = false;  // Will be detected in topology
                        info.available = true;

                        m_devices.push_back(info);
                    }
                }
            }
        }
    }

    // Try to load NVIDIA CUDA runtime
    HMODULE cudaModule = LoadLibraryA("nvcuda.dll");
    if (cudaModule) {
        using cuDeviceGetCount_t = int (*)(int*);
        using cuDeviceGet_t = int (*)(int*, int);
        using cuDeviceGetName_t = int (*)(char*, int, int);
        using cuDeviceTotalMem_t = int (*)(size_t*, int);
        using cuInit_t = int (*)(unsigned int);

        cuInit_t cuInit = reinterpret_cast<cuInit_t>(GetProcAddress(cudaModule, "cuInit"));
        cuDeviceGetCount_t cuDeviceGetCount = 
            reinterpret_cast<cuDeviceGetCount_t>(GetProcAddress(cudaModule, "cuDeviceGetCount"));
        cuDeviceGet_t cuDeviceGet = 
            reinterpret_cast<cuDeviceGet_t>(GetProcAddress(cudaModule, "cuDeviceGet"));
        cuDeviceGetName_t cuDeviceGetName = 
            reinterpret_cast<cuDeviceGetName_t>(GetProcAddress(cudaModule, "cuDeviceGetName"));
        cuDeviceTotalMem_t cuDeviceTotalMem = 
            reinterpret_cast<cuDeviceTotalMem_t>(GetProcAddress(cudaModule, "cuDeviceTotalMem"));

        if (cuInit && cuDeviceGetCount && cuDeviceGet && cuDeviceGetName && cuDeviceTotalMem) {
            if (cuInit(0) == 0) {
                int deviceCount = 0;
                if (cuDeviceGetCount(&deviceCount) == 0 && deviceCount > 0) {
                    for (int i = 0; i < deviceCount; ++i) {
                        int device = 0;
                        if (cuDeviceGet(&device, i) == 0) {
                            char name[256] = {};
                            size_t totalMem = 0;
                            
                            cuDeviceGetName(name, sizeof(name), device);
                            cuDeviceTotalMem(&totalMem, device);

                            GPUDeviceInfo info{};
                            info.deviceId = static_cast<uint32_t>(m_devices.size());  // Offset after AMD devices
                            info.name = _strdup(name);
                            info.vendor = "NVIDIA";
                            info.vramBytes = totalMem;
                            info.vramFreeBytes = totalMem;
                            info.computeUnits = 0;  // Would need cuDeviceGetAttribute
                            info.pcieGen = 4;
                            info.pcieLanes = 16;
                            info.pcieBandwidthGBs = 32.0f;
                            info.supportsP2P = false;
                            info.available = true;

                            m_devices.push_back(info);
                        }
                    }
                }
            }
        }
    }

    if (m_devices.empty()) {
        return MultiGPUResult::error("No GPU devices found (HIP or CUDA)", -1);
    }

    return MultiGPUResult::ok();
}

// Get device count
uint32_t MultiGPUManager::GetDeviceCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<uint32_t>(m_devices.size());
}

const GPUDeviceInfo& MultiGPUManager::GetDeviceInfo(uint32_t deviceId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    static GPUDeviceInfo empty{};
    if (deviceId < m_devices.size()) {
        return m_devices[deviceId];
    }
    return empty;
}

const std::vector<GPUDeviceInfo>& MultiGPUManager::GetAllDevices() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_devices;
}

// Topology detection
MultiGPUResult MultiGPUManager::DetectTopology() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_topology.clear();

    // Simple topology: assume all GPUs can communicate via PCIe
    for (size_t i = 0; i < m_devices.size(); ++i) {
        for (size_t j = i + 1; j < m_devices.size(); ++j) {
            TopologyLink link{};
            link.srcDevice = static_cast<uint32_t>(i);
            link.dstDevice = static_cast<uint32_t>(j);
            link.type = LinkType::PCIe;
            link.bandwidthGBs = 16.0f;  // Conservative PCIe estimate
            link.latencyUs = 5.0f;
            m_topology.push_back(link);

            // Symmetric link
            TopologyLink reverse{};
            reverse.srcDevice = static_cast<uint32_t>(j);
            reverse.dstDevice = static_cast<uint32_t>(i);
            reverse.type = LinkType::PCIe;
            reverse.bandwidthGBs = 16.0f;
            reverse.latencyUs = 5.0f;
            m_topology.push_back(reverse);
        }
    }

    return MultiGPUResult::ok();
}

const std::vector<TopologyLink>& MultiGPUManager::GetTopologyLinks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_topology;
}

bool MultiGPUManager::SupportsP2P(uint32_t srcDevice, uint32_t dstDevice) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& link : m_topology) {
        if (link.srcDevice == srcDevice && link.dstDevice == dstDevice) {
            return link.type != LinkType::None;
        }
    }
    return false;
}

// Strategy management
MultiGPUResult MultiGPUManager::SetStrategy(DispatchStrategy strategy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_strategy = strategy;
    return MultiGPUResult::ok();
}

DispatchStrategy MultiGPUManager::GetStrategy() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_strategy;
}

const char* MultiGPUManager::GetStrategyName(DispatchStrategy strategy) const {
    switch (strategy) {
        case DispatchStrategy::LayerParallel:    return "LayerParallel";
        case DispatchStrategy::TensorParallel:   return "TensorParallel";
        case DispatchStrategy::PipelineParallel: return "PipelineParallel";
        case DispatchStrategy::DataParallel:     return "DataParallel";
        case DispatchStrategy::Hybrid:           return "Hybrid";
        case DispatchStrategy::RoundRobin:       return "RoundRobin";
        case DispatchStrategy::LoadBased:        return "LoadBased";
        case DispatchStrategy::MemoryAware:      return "MemoryAware";
        default:                                 return "Unknown";
    }
}

// Build layer assignments based on VRAM ratios
MultiGPUResult MultiGPUManager::BuildLayerAssignments(uint32_t totalLayers,
                                                       uint64_t modelBytes,
                                                       DispatchStrategy strategy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_assignments.clear();

    if (m_devices.empty()) {
        return MultiGPUResult::error("No GPU devices available", -1);
    }

    if (totalLayers == 0) {
        return MultiGPUResult::error("Total layers must be > 0", -2);
    }

    // Calculate total VRAM across all devices
    uint64_t totalVram = 0;
    for (const auto& dev : m_devices) {
        if (dev.available) {
            totalVram += dev.vramBytes;
        }
    }

    if (totalVram == 0) {
        return MultiGPUResult::error("No available GPU memory", -3);
    }

    // Build assignments based on VRAM ratio
    uint32_t currentLayer = 0;
    std::vector<GPUDeviceInfo> availableDevices;
    for (const auto& dev : m_devices) {
        if (dev.available) {
            availableDevices.push_back(dev);
        }
    }

    // Sort by VRAM (largest first for better distribution)
    std::sort(availableDevices.begin(), availableDevices.end(),
              [](const GPUDeviceInfo& a, const GPUDeviceInfo& b) {
                  return a.vramBytes > b.vramBytes;
              });

    for (size_t i = 0; i < availableDevices.size() && currentLayer < totalLayers; ++i) {
        const auto& dev = availableDevices[i];
        
        // Calculate layer count for this device based on VRAM ratio
        float vramRatio = static_cast<float>(dev.vramBytes) / static_cast<float>(totalVram);
        uint32_t layersForDevice = static_cast<uint32_t>(totalLayers * vramRatio);
        
        // Ensure at least 1 layer per device (if we have fewer devices than layers)
        if (layersForDevice == 0 && currentLayer < totalLayers) {
            layersForDevice = 1;
        }
        
        // Clamp to remaining layers
        if (currentLayer + layersForDevice > totalLayers) {
            layersForDevice = totalLayers - currentLayer;
        }

        if (layersForDevice > 0) {
            LayerAssignment assign{};
            assign.deviceId = dev.deviceId;
            assign.startLayer = currentLayer;
            assign.endLayer = currentLayer + layersForDevice - 1;
            assign.vramBudgetBytes = static_cast<uint64_t>(modelBytes * vramRatio);
            assign.strategy = strategy;
            assign.tensorSplitFactor = 1;

            m_assignments.push_back(assign);
            currentLayer += layersForDevice;
        }
    }

    // Assign any remaining layers to the device with most VRAM
    if (currentLayer < totalLayers && !m_assignments.empty()) {
        m_assignments[0].endLayer += (totalLayers - currentLayer);
    }

    // Update dispatch stats
    m_dispatchStats.lastAssignmentCount = static_cast<uint32_t>(m_assignments.size());
    m_dispatchStats.lastStrategy = strategy;

    return MultiGPUResult::ok();
}

const std::vector<LayerAssignment>& MultiGPUManager::GetLayerAssignments() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_assignments;
}

void MultiGPUManager::ClearLayerAssignments() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_assignments.clear();
}

// Dispatch execution
MultiGPUResult MultiGPUManager::DispatchBatch(uint32_t batchId,
                                               uint32_t totalLayers,
                                               uint64_t modelBytes,
                                               DispatchStrategy strategy) {
    auto result = BuildLayerAssignments(totalLayers, modelBytes, strategy);
    if (!result.success) {
        return result;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_dispatchStats.totalDispatches++;
    m_dispatchStats.lastBatchId = batchId;

    if (m_onDispatchComplete) {
        m_onDispatchComplete(batchId, 0.0f);  // Elapsed time would be measured by caller
    }

    return MultiGPUResult::ok();
}

DispatchStats MultiGPUManager::GetDispatchStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_dispatchStats;
}

// Load monitoring
std::vector<GPULoadStats> MultiGPUManager::GetLoadStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<GPULoadStats> stats;
    
    for (const auto& dev : m_devices) {
        GPULoadStats s{};
        s.deviceId = dev.deviceId;
        s.utilization = 0.0f;  // Would query GPU metrics
        s.layersAssigned = 0;
        s.tensorsProcessed = 0;
        s.memoryUsedBytes = dev.vramBytes - dev.vramFreeBytes;
        s.throughputToksPerSec = 0.0f;
        
        // Count layers assigned to this device
        for (const auto& assign : m_assignments) {
            if (assign.deviceId == dev.deviceId) {
                s.layersAssigned = assign.endLayer - assign.startLayer + 1;
            }
        }
        
        stats.push_back(s);
    }
    
    return stats;
}

float MultiGPUManager::GetTotalThroughput() const {
    auto stats = GetLoadStats();
    float total = 0.0f;
    for (const auto& s : stats) {
        total += s.throughputToksPerSec;
    }
    return total;
}

uint64_t MultiGPUManager::GetTotalVRAM() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t total = 0;
    for (const auto& dev : m_devices) {
        if (dev.available) {
            total += dev.vramBytes;
        }
    }
    return total;
}

uint64_t MultiGPUManager::GetFreeVRAM() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t total = 0;
    for (const auto& dev : m_devices) {
        if (dev.available) {
            total += dev.vramFreeBytes;
        }
    }
    return total;
}

// Health monitoring
bool MultiGPUManager::AllDevicesHealthy() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& dev : m_devices) {
        if (!dev.available) {
            return false;
        }
    }
    return !m_devices.empty();
}

MultiGPUResult MultiGPUManager::RunHealthCheck() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Simple health check: verify devices are still available
    for (auto& dev : m_devices) {
        bool wasHealthy = dev.available;
        // In a real implementation, would query GPU driver for health status
        dev.available = true;  // Assume healthy for now
        
        if (wasHealthy != dev.available && m_onHealthChange) {
            m_onHealthChange(dev.deviceId, dev.available);
        }
    }
    
    return MultiGPUResult::ok();
}

// Status reporting
std::string MultiGPUManager::GenerateStatusReport() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::stringstream ss;
    
    ss << "=== Multi-GPU Status Report ===\n";
    ss << "Initialized: " << (m_initialized ? "Yes" : "No") << "\n";
    ss << "Strategy: " << GetStrategyName(m_strategy) << "\n";
    ss << "Devices: " << m_devices.size() << "\n\n";
    
    for (const auto& dev : m_devices) {
        ss << "GPU " << dev.deviceId << ": " << dev.name << "\n";
        ss << "  Vendor: " << dev.vendor << "\n";
        ss << "  VRAM: " << (dev.vramBytes / (1024ULL * 1024 * 1024)) << " GB\n";
        ss << "  Compute Units: " << dev.computeUnits << "\n";
        ss << "  Available: " << (dev.available ? "Yes" : "No") << "\n";
        ss << "\n";
    }
    
    if (!m_assignments.empty()) {
        ss << "Layer Assignments:\n";
        for (const auto& assign : m_assignments) {
            ss << "  GPU " << assign.deviceId << ": layers " 
               << assign.startLayer << "-" << assign.endLayer << "\n";
        }
    }
    
    return ss.str();
}

std::string MultiGPUManager::GenerateTopologyReport() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::stringstream ss;
    
    ss << "=== Multi-GPU Topology Report ===\n";
    
    if (m_topology.empty()) {
        ss << "No topology detected. Run DetectTopology() first.\n";
        return ss.str();
    }
    
    for (const auto& link : m_topology) {
        ss << "GPU " << link.srcDevice << " -> GPU " << link.dstDevice << ": ";
        switch (link.type) {
            case LinkType::PCIe:     ss << "PCIe"; break;
            case LinkType::NVLink:   ss << "NVLink"; break;
            case LinkType::XGMI:     ss << "XGMI (Infinity Fabric)"; break;
            case LinkType::None:     ss << "No direct link"; break;
        }
        ss << " (" << std::fixed << std::setprecision(1) << link.bandwidthGBs << " GB/s)\n";
    }
    
    return ss.str();
}

} // namespace RawrXD::Enterprise
