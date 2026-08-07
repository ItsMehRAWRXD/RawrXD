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

// Nanolayer configuration — sub-layer granularity for fine-grained GPU distribution
struct NanoLayerConfig {
    bool enabled = false;              // Enable nanolayer splitting
    uint32_t subLayersPerLayer = 4;    // How many sub-units per transformer layer
    float minChunkSize = 0.1f;         // Minimum chunk as fraction of a layer (10%)
    bool dynamicAdjust = true;         // Allow runtime rebalancing
    uint32_t gpuStripeWidth = 1;       // GPU assignment stripe width (1 = round-robin)
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
    NanoLayerConfig nanoConfig;         // Nanolayer split configuration
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
    
    // NANOLAYER MODE: Sub-layer granularity distribution
    if (g_balancer.nanoConfig.enabled) {
        uint32_t subLayers = g_balancer.nanoConfig.subLayersPerLayer;
        uint32_t totalSubLayers = totalLayers * subLayers;
        uint32_t primarySubLayers = (uint32_t)(totalSubLayers * g_balancer.primaryGpuWeight);
        
        // Each layer is split into subLayers chunks
        // The subLayerIndex within this layer determines GPU assignment
        // This allows fine-grained 70/30 split at sub-layer level
        uint32_t subLayerBase = layerIndex * subLayers;
        
        // Check thermal throttling at sub-layer granularity
        for (auto& gpu : g_balancer.gpus) {
            if (gpu.temperature > g_balancer.thermalThreshold) {
                // Hot GPU — shift its sub-layers to cooler GPU
                for (uint32_t s = 0; s < subLayers; s++) {
                    uint32_t globalSubIdx = subLayerBase + s;
                    if (gpu.index == g_balancer.gpus[0].index && globalSubIdx < primarySubLayers) {
                        // Primary hot, shift this sub-layer to secondary
                        return g_balancer.gpus[1].index;
                    } else if (gpu.index == g_balancer.gpus[1].index && globalSubIdx >= primarySubLayers) {
                        // Secondary hot, shift this sub-layer to primary
                        return g_balancer.gpus[0].index;
                    }
                }
            }
        }
        
        // Stripe distribution: interleave sub-layers across GPUs
        if (g_balancer.nanoConfig.gpuStripeWidth > 1) {
            uint32_t stripeIdx = (layerIndex * subLayers) / g_balancer.nanoConfig.gpuStripeWidth;
            return g_balancer.gpus[stripeIdx % g_balancer.gpus.size()].index;
        }
        
        // Standard nanolayer distribution: assign sub-layer chunks by weight
        uint32_t subLayerStart = layerIndex * subLayers;
        uint32_t subLayerEnd = subLayerStart + subLayers;
        
        // Count how many sub-layers go to each GPU
        uint32_t primarySubCount = 0;
        for (uint32_t s = subLayerStart; s < subLayerEnd; s++) {
            if (s < primarySubLayers) primarySubCount++;
        }
        
        // If majority of this layer's sub-layers go to primary, assign whole layer to primary
        // Otherwise assign to secondary — this prevents thrashing
        if (primarySubCount >= (subLayers / 2)) {
            return g_balancer.gpus[0].index;
        } else {
            return g_balancer.gpus[1].index;
        }
    }
    
    // LEGACY MODE: Whole-layer distribution (original 70/30 split)
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
// Nanolayer Configuration
// =============================================================================

extern "C" __declspec(dllexport) void DualGpuBalancer_SetNanoLayerConfig(
    bool enabled,
    uint32_t subLayersPerLayer,
    float minChunkSize,
    bool dynamicAdjust,
    uint32_t gpuStripeWidth)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    g_balancer.nanoConfig.enabled = enabled;
    g_balancer.nanoConfig.subLayersPerLayer = std::max(1u, std::min(64u, subLayersPerLayer));
    g_balancer.nanoConfig.minChunkSize = std::max(0.01f, std::min(0.5f, minChunkSize));
    g_balancer.nanoConfig.dynamicAdjust = dynamicAdjust;
    g_balancer.nanoConfig.gpuStripeWidth = std::max(1u, gpuStripeWidth);
    
    char buf[256];
    snprintf(buf, sizeof(buf),
        "[DualGpuBalancer] NanoLayer: enabled=%d subLayers=%u stripe=%u minChunk=%.2f\n",
        enabled, subLayersPerLayer, gpuStripeWidth, minChunkSize);
    OutputDebugStringA(buf);
}

extern "C" __declspec(dllexport) bool DualGpuBalancer_GetNanoLayerConfig(
    bool* outEnabled,
    uint32_t* outSubLayersPerLayer,
    float* outMinChunkSize,
    bool* outDynamicAdjust,
    uint32_t* outGpuStripeWidth)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    if (outEnabled) *outEnabled = g_balancer.nanoConfig.enabled;
    if (outSubLayersPerLayer) *outSubLayersPerLayer = g_balancer.nanoConfig.subLayersPerLayer;
    if (outMinChunkSize) *outMinChunkSize = g_balancer.nanoConfig.minChunkSize;
    if (outDynamicAdjust) *outDynamicAdjust = g_balancer.nanoConfig.dynamicAdjust;
    if (outGpuStripeWidth) *outGpuStripeWidth = g_balancer.nanoConfig.gpuStripeWidth;
    return true;
}

extern "C" __declspec(dllexport) uint32_t DualGpuBalancer_GetNanoLayerCount(uint32_t totalLayers)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    if (!g_balancer.nanoConfig.enabled)
        return totalLayers;
    return totalLayers * g_balancer.nanoConfig.subLayersPerLayer;
}

extern "C" __declspec(dllexport) int DualGpuBalancer_GetGpuForNanoLayer(
    uint32_t layerIndex,
    uint32_t subLayerIndex,
    uint32_t totalLayers,
    size_t subLayerMemoryEstimate)
{
    std::lock_guard<std::mutex> lock(g_balancer.mutex);
    
    if (!g_balancer.initialized || g_balancer.gpus.empty())
        return 0;
    
    if (g_balancer.gpus.size() == 1)
        return g_balancer.gpus[0].index;
    
    if (!g_balancer.nanoConfig.enabled) {
        // Fall back to whole-layer assignment
        return DualGpuBalancer_GetGpuForLayer(layerIndex, totalLayers, subLayerMemoryEstimate * g_balancer.nanoConfig.subLayersPerLayer);
    }
    
    uint32_t subLayers = g_balancer.nanoConfig.subLayersPerLayer;
    uint32_t totalSubLayers = totalLayers * subLayers;
    uint32_t primarySubLayers = (uint32_t)(totalSubLayers * g_balancer.primaryGpuWeight);
    uint32_t globalSubIdx = layerIndex * subLayers + subLayerIndex;
    
    // Check thermal throttling at nanolayer level
    for (auto& gpu : g_balancer.gpus) {
        if (gpu.temperature > g_balancer.thermalThreshold) {
            if (gpu.index == g_balancer.gpus[0].index && globalSubIdx < primarySubLayers) {
                return g_balancer.gpus[1].index;  // Shift to secondary
            } else if (gpu.index == g_balancer.gpus[1].index && globalSubIdx >= primarySubLayers) {
                return g_balancer.gpus[0].index;  // Shift to primary
            }
        }
    }
    
    // Stripe distribution
    if (g_balancer.nanoConfig.gpuStripeWidth > 1) {
        uint32_t stripeIdx = globalSubIdx / g_balancer.nanoConfig.gpuStripeWidth;
        return g_balancer.gpus[stripeIdx % g_balancer.gpus.size()].index;
    }
    
    // Standard nanolayer distribution
    if (globalSubIdx < primarySubLayers) {
        return g_balancer.gpus[0].index;
    } else {
        return g_balancer.gpus[1].index;
    }
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
