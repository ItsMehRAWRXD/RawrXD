// ============================================================================
// Vulkan Executor Header
// ============================================================================
// Declares the VulkanExecutor class for GPU kernel execution
// ============================================================================

#pragma once

#include <iostream>
#include <vector>
#include <cstring>
#include <cmath>
#include <unordered_map>
#include <string>

// Windows-specific Vulkan loading
#ifdef _WIN32
    #include <windows.h>
    #define VK_USE_PLATFORM_WIN32_KHR
#endif

#include <vulkan/vulkan.h>

namespace RawrXD {
namespace Inference {

// FP16 conversion helpers - defined inline in header for multi-TU compatibility
inline uint16_t FloatToFP16(float value) {
    if (value == 0.0f) return 0;
    if (value > 65504.0f) return 0x7C00;
    if (value < -65504.0f) return 0xFC00;
    
    uint32_t f_bits;
    std::memcpy(&f_bits, &value, sizeof(f_bits));
    
    uint32_t sign = (f_bits >> 31) & 0x1;
    uint32_t exponent = (f_bits >> 23) & 0xFF;
    uint32_t mantissa = f_bits & 0x7FFFFF;
    
    int16_t new_exp = (int16_t)(exponent - 127 + 15);
    if (new_exp >= 31) {
        return (sign << 15) | 0x7C00;
    } else if (new_exp <= 0) {
        if (new_exp < -10) return sign << 15;
        mantissa = (mantissa | 0x800000) >> (1 - new_exp);
        return (sign << 15) | (mantissa >> 13);
    }
    
    return (sign << 15) | (new_exp << 10) | (mantissa >> 13);
}

inline float FP16ToFloat(uint16_t value) {
    uint32_t sign = (value >> 15) & 0x1;
    uint32_t exponent = (value >> 10) & 0x1F;
    uint32_t mantissa = value & 0x3FF;
    
    if (exponent == 0) {
        if (mantissa == 0) return sign ? -0.0f : 0.0f;
        float result = mantissa / 1024.0f;
        return sign ? -result * 0.00006103515625f : result * 0.00006103515625f;
    } else if (exponent == 31) {
        return mantissa ? NAN : (sign ? -INFINITY : INFINITY);
    }
    
    float result = (1.0f + mantissa / 1024.0f) * std::pow(2.0f, (int)exponent - 15);
    return sign ? -result : result;
}

// VulkanBuffer structure for GPU memory management
struct VulkanBuffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkDeviceSize size = 0;
    void* mapped = nullptr;
};

// Pipeline information
struct PipelineInfo {
    VkPipeline pipeline = VK_NULL_HANDLE;
    VkPipelineLayout layout = VK_NULL_HANDLE;
    VkDescriptorSetLayout descriptorSetLayout = VK_NULL_HANDLE;
};

// Main Vulkan Executor class
class VulkanExecutor {
public:
    VulkanExecutor() = default;
    ~VulkanExecutor() { Cleanup(); }

    bool Initialize();
    void Cleanup();
    
    // Execute FP16 matrix multiplication: C = A * B
    bool ExecuteMatMulFP16(const std::vector<float>& A, const std::vector<float>& B, 
                           std::vector<float>& C, uint32_t M, uint32_t N, uint32_t K);
    
    bool IsInitialized() const { return initialized_; }
    std::string GetDeviceName() const { return deviceName_; }
    
    // Buffer management (protected for derived classes)
    bool CreateBuffer(VkDeviceSize size, VkBufferUsageFlags usage, VulkanBuffer& buffer);
    void DestroyBuffer(VulkanBuffer& buffer);
    void UploadBuffer(VulkanBuffer& buffer, const void* data, VkDeviceSize size);
    void DownloadBuffer(VulkanBuffer& buffer, void* data, VkDeviceSize size);
    
    // Pipeline creation (protected for derived classes)
    bool CreateComputePipeline(const std::string& name, const uint32_t* code, size_t codeSize);
    
    // Command buffer management (protected for derived classes)
    VkCommandBuffer BeginCommandBuffer();
    void EndCommandBuffer(VkCommandBuffer commandBuffer);

protected:
    VkInstance instance_ = VK_NULL_HANDLE;
    VkPhysicalDevice physicalDevice_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue queue_ = VK_NULL_HANDLE;
    VkCommandPool commandPool_ = VK_NULL_HANDLE;
    VkDescriptorPool descriptorPool_ = VK_NULL_HANDLE;
    uint32_t computeQueueFamily_ = 0;

    std::unordered_map<std::string, PipelineInfo> pipelines_;
    std::string deviceName_;
    bool initialized_ = false;

private:
    bool LoadShaders();
    uint32_t FindMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties);
};

} // namespace Inference
} // namespace RawrXD
