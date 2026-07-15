// ============================================================================
// GPU Weight Cache - Persistent Model Weights in VRAM
// ============================================================================
// Eliminates CPU→GPU memory transfers for model weights
// Target: 7x speedup by keeping weights resident in GPU memory
// ============================================================================

#pragma once

#include "vulkan_executor.hpp"
#include <unordered_map>
#include <string>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Inference {

// ============================================================================
// Cached Weight Buffer
// ============================================================================
struct CachedWeight {
    VulkanBuffer buffer;
    uint32_t rows = 0;
    uint32_t cols = 0;
    bool is_fp16 = true;
    std::string name;
};

// ============================================================================
// GPU Weight Cache
// ============================================================================
class GPUWeightCache {
public:
    GPUWeightCache();
    ~GPUWeightCache();

    // Initialize with Vulkan device
    bool Initialize(VkDevice device, VkPhysicalDevice physical_device);
    void Shutdown();

    // Upload weight matrix to GPU (one-time)
    bool UploadWeight(const std::string& name, 
                      const std::vector<float>& data,
                      uint32_t rows, uint32_t cols);

    // Upload FP16 weight matrix (already quantized)
    bool UploadWeightFP16(const std::string& name,
                          const std::vector<uint16_t>& data,
                          uint32_t rows, uint32_t cols);

    // Get cached weight by name
    CachedWeight* GetWeight(const std::string& name);

    // Check if weight exists in cache
    bool HasWeight(const std::string& name) const;

    // Remove weight from cache
    void RemoveWeight(const std::string& name);

    // Clear all cached weights
    void Clear();

    // Get cache statistics
    size_t GetCacheSize() const { return weights_.size(); }
    size_t GetTotalVRAMUsage() const { return total_vram_usage_; }

    // Pre-upload common transformer weights
    bool UploadTransformerWeights(uint32_t hidden_size, 
                                   uint32_t intermediate_size,
                                   uint32_t num_layers);

private:
    VkDevice device_ = VK_NULL_HANDLE;
    VkPhysicalDevice physical_device_ = VK_NULL_HANDLE;
    std::unordered_map<std::string, std::unique_ptr<CachedWeight>> weights_;
    size_t total_vram_usage_ = 0;
    bool initialized_ = false;
};

// ============================================================================
// Global Weight Cache Instance
// ============================================================================
GPUWeightCache* GetGlobalWeightCache();
void InitializeGlobalWeightCache(VkDevice device, VkPhysicalDevice physical_device);
void ShutdownGlobalWeightCache();

} // namespace Inference
} // namespace RawrXD
