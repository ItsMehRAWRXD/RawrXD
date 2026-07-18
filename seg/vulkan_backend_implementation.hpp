// ============================================================================
// Vulkan Backend - Full Implementation
// ============================================================================
// Wires SPIR-V shaders to actual GPU execution on RX 7800 XT
// Target: 500 tok/s
// ============================================================================

#pragma once

#include "transformer_layer_runtime.hpp"
#include "vulkan_shader_integration.hpp"
#include <vulkan/vulkan.h>
#include <vector>
#include <memory>

namespace transformer {

// ============================================================================
// Vulkan Buffer Wrapper
// ============================================================================
struct VulkanBuffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    size_t size = 0;
    void* mapped_ptr = nullptr;
    
    bool Allocate(VkDevice device, VkPhysicalDevice physical_device, size_t size);
    void Free(VkDevice device);
    bool Upload(VkDevice device, const void* data, size_t size);
    bool Download(VkDevice device, void* data, size_t size);
};

// ============================================================================
// Descriptor Set Manager
// ============================================================================
class DescriptorSetManager {
public:
    bool Initialize(VkDevice device, uint32_t max_sets = 100);
    void Cleanup();
    
    // Allocate descriptor set for specific operation
    VkDescriptorSet AllocateSet(VkDescriptorSetLayout layout);
    
    // Update descriptor set with buffers
    void UpdateBufferBinding(VkDescriptorSet set, uint32_t binding,
                             VkBuffer buffer, size_t size);
    
private:
    VkDevice device_ = VK_NULL_HANDLE;
    VkDescriptorPool pool_ = VK_NULL_HANDLE;
};

// ============================================================================
// Command Buffer Manager
// ============================================================================
class CommandBufferManager {
public:
    bool Initialize(VkDevice device, VkCommandPool pool, uint32_t queue_family);
    void Cleanup();
    
    // Begin recording
    VkCommandBuffer BeginRecording();
    
    // End and submit
    void EndAndSubmit(VkQueue queue, VkFence fence);
    
    // Wait for completion
    void Wait(VkDevice device, VkFence fence, uint64_t timeout_ns = 10000000000);
    
private:
    VkDevice device_ = VK_NULL_HANDLE;
    VkCommandPool pool_ = VK_NULL_HANDLE;
    VkCommandBuffer cmd_buffer_ = VK_NULL_HANDLE;
    VkFence fence_ = VK_NULL_HANDLE;
    bool recording_ = false;
};

// ============================================================================
// Complete Vulkan Backend
// ============================================================================
class VulkanBackendComplete : public GPUBackend {
public:
    VulkanBackendComplete();
    ~VulkanBackendComplete() override;
    
    // GPUBackend interface
    bool Initialize() override;
    void Cleanup() override;
    
    bool AllocateBuffer(size_t size, void** device_ptr) override;
    void FreeBuffer(void* device_ptr) override;
    bool CopyHostToDevice(const void* host_ptr, void* device_ptr, size_t size) override;
    bool CopyDeviceToHost(const void* device_ptr, void* host_ptr, size_t size) override;
    
    void RMSNorm(const void* input, void* output, const void* weights,
                 uint32_t size, float epsilon) override;
    void MatMul(const void* a, const void* b, void* c,
                uint32_t m, uint32_t k, uint32_t n) override;
    void Softmax(const void* input, void* output, uint32_t size) override;
    void FlashAttention(const void* q, const void* k, const void* v,
                        void* output, uint32_t seq_len, uint32_t head_dim) override;
    
    void Synchronize() override;
    
    // Performance metrics
    double GetLastKernelTimeMs() const { return last_kernel_time_ms_; }
    
private:
    // Vulkan handles
    VkInstance instance_ = VK_NULL_HANDLE;
    VkPhysicalDevice physical_device_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue compute_queue_ = VK_NULL_HANDLE;
    uint32_t compute_queue_family_ = 0;
    VkCommandPool command_pool_ = VK_NULL_HANDLE;
    VkFence fence_ = VK_NULL_HANDLE;
    
    // Shader manager
    std::unique_ptr<RDNA3ShaderManager> shader_manager_;
    std::unique_ptr<DescriptorSetManager> descriptor_manager_;
    std::unique_ptr<CommandBufferManager> command_manager_;
    
    // Pipeline layouts
    VkPipelineLayout rmsnorm_layout_ = VK_NULL_HANDLE;
    VkPipelineLayout matmul_layout_ = VK_NULL_HANDLE;
    VkPipelineLayout softmax_layout_ = VK_NULL_HANDLE;
    VkPipelineLayout flash_attn_layout_ = VK_NULL_HANDLE;
    
    // Descriptor set layouts
    VkDescriptorSetLayout rmsnorm_desc_layout_ = VK_NULL_HANDLE;
    VkDescriptorSetLayout matmul_desc_layout_ = VK_NULL_HANDLE;
    VkDescriptorSetLayout softmax_desc_layout_ = VK_NULL_HANDLE;
    VkDescriptorSetLayout flash_attn_desc_layout_ = VK_NULL_HANDLE;
    
    // Performance tracking
    double last_kernel_time_ms_ = 0.0;
    
    // Initialization helpers
    bool CreateInstance();
    bool SelectPhysicalDevice();
    bool CreateDevice();
    bool CreateCommandPool();
    bool CreatePipelineLayouts();
    bool CreateDescriptorSetLayouts();
    bool LoadShaders();
    
    // Buffer management
    std::vector<std::unique_ptr<VulkanBuffer>> buffers_;
    VulkanBuffer* GetBuffer(void* device_ptr);
};

// Factory function
std::unique_ptr<GPUBackend> CreateVulkanBackendComplete();

} // namespace transformer
