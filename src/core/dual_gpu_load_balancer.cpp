// dual_gpu_load_balancer.cpp
// RawrXD Dual GPU Load Balancer
// Distributes inference workload across R9700 AI Pro and RX 7800 XT

#include <windows.h>
#include <atomic>
#include <vector>
#include <mutex>
#include <algorithm>

// GPU Configuration
struct GpuInfo {
    uint32_t index;
    wchar_t name[128];
    size_t vramTotal;
    size_t vramUsed;
    float computeScore;      // Relative compute capability (0.0 - 1.0)
    float temperature;
    bool isAvailable;
    std::atomic<uint32_t> activeLayers{0};
};

// Load Balancer State
static struct {
    std::vector<GpuInfo> gpus;
    std::mutex mutex;
    std::atomic<bool> initialized{false};
    
    // Configuration
    float primaryGpuWeight = 0.7f;      // R9700 gets 70% of layers by default
    float thermalThreshold = 85.0f;    // Throttle above 85°C
    size_t vramReserve = 2ULL * 1024 * 1024 * 1024;  // Reserve 2GB per GPU
} g_balancer;

// External function declarations (would link to actual GPU detection)
extern "C" {
    int GetGpuCount();
    int GetGpuInfo(int index, GpuInfo* info);
}

// =============================================================================
// Initialization
// =============================================================================

extern "C" __declspec(dllexport) bool DualGpuBalancer_Init()
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    
    if (g_balancer.initialized)
        return true;
    
    // Detect GPUs
    int gpuCount = GetGpuCount();
    if (gpuCount < 1)
        return false;
    
    g_balancer.gpus.clear();
    
    for (int i = 0; i < gpuCount; i++) {
        GpuInfo info = {};
        info.index = i;
        if (GetGpuInfo(i, &info) == 0) {
            // Set compute scores based on GPU type
            if (wcsstr(info.name, L"R9700") || wcsstr(info.name, L"AI PRO")) {
                info.computeScore = 1.0f;  // Primary GPU
            } else if (wcsstr(info.name, L"7800")) {
                info.computeScore = 0.6f;    // Secondary GPU (60% of primary)
            } else {
                info.computeScore = 0.3f;    // Integrated/other
            }
            
            info.isAvailable = true;
            g_balancer.gpus.push_back(info);
        }
    }
    
    if (g_balancer.gpus.size() >= 2) {
        g_balancer.initialized = true;
        OutputDebugStringA("[DualGpuBalancer] Initialized with ");
        char buf[32];
        snprintf(buf, sizeof(buf), "%zu GPUs\n", g_balancer.gpus.size());
        OutputDebugStringA(buf);
        return true;
    }
    
    return false;
}

extern "C" __declspec(dllexport) void DualGpuBalancer_Shutdown()
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    g_balancer.gpus.clear();
    g_balancer.initialized = false;
}

// =============================================================================
// Layer Distribution Algorithm
// =============================================================================

extern "C" __declspec(dllexport) int DualGpuBalancer_GetGpuForLayer(
    uint32_t layerIndex, 
    uint32_t totalLayers,
    size_t layerMemoryEstimate)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    
    if (!g_balancer.initialized || g_balancer.gpus.empty())
        return 0;  // Default to GPU 0
    
    if (g_balancer.gpus.size() == 1)
        return g_balancer.gpus[0].index;
    
    // Primary GPU (R9700) - assign first 70% of layers
    uint32_t primaryLayers = (uint32_t)(totalLayers * g_balancer.primaryGpuWeight);
    
    // Check thermal throttling
    for (auto& gpu : g_balancer.gpus) {
        if (gpu.temperature > g_balancer.thermalThreshold) {
            // Move load to cooler GPU
            if (gpu.index == g_balancer.gpus[0].index && layerIndex < primaryLayers) {
                // Primary is hot, move to secondary
                return g_balancer.gpus[1].index;
            } else if (gpu.index == g_balancer.gpus[1].index && layerIndex >= primaryLayers) {
                // Secondary is hot, move to primary
                return g_balancer.gpus[0].index;
            }
        }
    }
    
    // Check VRAM availability
    for (auto& gpu : g_balancer.gpus) {
        size_t availableVram = gpu.vramTotal - gpu.vramUsed - g_balancer.vramReserve;
        if (availableVram < layerMemoryEstimate) {
            // GPU is low on memory, try to use other GPU
            for (auto& otherGpu : g_balancer.gpus) {
                if (otherGpu.index != gpu.index) {
                    size_t otherAvailable = otherGpu.vramTotal - otherGpu.vramUsed - g_balancer.vramReserve;
                    if (otherAvailable >= layerMemoryEstimate) {
                        return otherGpu.index;
                    }
                }
            }
        }
    }
    
    // Standard distribution
    if (layerIndex < primaryLayers) {
        return g_balancer.gpus[0].index;  // Primary GPU
    } else {
        return g_balancer.gpus[1].index;  // Secondary GPU
    }
}

// =============================================================================
// Dynamic Load Adjustment
// =============================================================================

extern "C" __declspec(dllexport) void DualGpuBalancer_UpdateGpuMetrics(
    uint32_t gpuIndex,
    float temperature,
    size_t vramUsed)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    
    for (auto& gpu : g_balancer.gpus) {
        if (gpu.index == gpuIndex) {
            gpu.temperature = temperature;
            gpu.vramUsed = vramUsed;
            
            // Mark as unavailable if overheating
            if (temperature > 95.0f) {
                gpu.isAvailable = false;
                char buf[128];
                snprintf(buf, sizeof(buf), 
                    "[DualGpuBalancer] GPU %d overheated (%.1f°C), marking unavailable\n",
                    gpuIndex, temperature);
                OutputDebugStringA(buf);
            } else if (temperature < 85.0f && !gpu.isAvailable) {
                // Recovery - GPU cooled down
                gpu.isAvailable = true;
                char buf[128];
                snprintf(buf, sizeof(buf), 
                    "[DualGpuBalancer] GPU %d recovered (%.1f°C), marking available\n",
                    gpuIndex, temperature);
                OutputDebugStringA(buf);
            }
            break;
        }
    }
}

extern "C" __declspec(dllexport) void DualGpuBalancer_SetPrimaryWeight(float weight)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    g_balancer.primaryGpuWeight = std::max(0.1f, std::min(0.9f, weight));
}

// =============================================================================
// Failover Support
// =============================================================================

extern "C" __declspec(dllexport) int DualGpuBalancer_GetFailoverGpu(uint32_t failedGpuIndex)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    
    // Find first available GPU that isn't the failed one
    for (auto& gpu : g_balancer.gpus) {
        if (gpu.index != failedGpuIndex && gpu.isAvailable) {
            return gpu.index;
        }
    }
    
    // No available GPU found
    return -1;
}

extern "C" __declspec(dllexport) bool DualGpuBalancer_IsGpuAvailable(uint32_t gpuIndex)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    
    for (auto& gpu : g_balancer.gpus) {
        if (gpu.index == gpuIndex) {
            return gpu.isAvailable;
        }
    }
    
    return false;
}

// =============================================================================
// Status Query
// =============================================================================

extern "C" __declspec(dllexport) uint32_t DualGpuBalancer_GetGpuCount()
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    return (uint32_t)g_balancer.gpus.size();
}

extern "C" __declspec(dllexport) bool DualGpuBalancer_GetGpuStatus(
    uint32_t gpuIndex,
    float* outTemperature,
    size_t* outVramUsed,
    size_t* outVramTotal,
    bool* outIsAvailable)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    
    for (auto& gpu : g_balancer.gpus) {
        if (gpu.index == gpuIndex) {
            if (outTemperature) *outTemperature = gpu.temperature;
            if (outVramUsed) *outVramUsed = gpu.vramUsed;
            if (outVramTotal) *outVramTotal = gpu.vramTotal;
            if (outIsAvailable) *outIsAvailable = gpu.isAvailable;
            return true;
        }
    }
    
    return false;
}
