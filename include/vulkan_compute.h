#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <queue>

// Phase 46: Vulkan support with graceful fallback for dual GPU testing
#if defined(RAWR_ENABLE_VULKAN) || defined(RAWR_HAS_VULKAN)
    #if __has_include(<vulkan/vulkan.h>)
        #include <vulkan/vulkan.h>
        #define RAWR_VULKAN_AVAILABLE 1
    #else
        #pragma message("Vulkan SDK headers not found — using CPU fallback for dual GPU testing")
        #define RAWR_VULKAN_AVAILABLE 0
    #endif
#else
    #define RAWR_VULKAN_AVAILABLE 0
#endif

#if !RAWR_VULKAN_AVAILABLE
// Dummy types to allow compilation without Vulkan SDK
// Only define if not already defined by real Vulkan headers
#ifndef VK_VERSION_1_0
typedef void* VkDevice;
typedef void* VkInstance;
typedef void* VkPhysicalDevice;
typedef void* VkQueue;
typedef void* VkCommandPool;
typedef void* VkDescriptorPool;
typedef void* VkDescriptorSet;
typedef void* VkDescriptorSetLayout;
typedef void* VkShaderModule;
typedef void* VkPipelineLayout;
typedef void* VkPipeline;
typedef void* VkPipelineCache;
typedef void* VkBuffer;
typedef void* VkDeviceMemory;
typedef void* VkCommandBuffer;
typedef void* VkFence;
typedef void* VkDescriptorSetLayoutBinding;
typedef uint32_t VkMemoryPropertyFlags;
typedef int VkResult;
typedef uint64_t VkDeviceSize;

// VkBufferCopy for buffer-to-buffer copy regions
typedef struct VkBufferCopy {
    VkDeviceSize srcOffset;
    VkDeviceSize dstOffset;
    VkDeviceSize size;
} VkBufferCopy;

typedef struct { 
    uint32_t vendorID; 
    uint32_t deviceID; 
    char deviceName[256];
} VkPhysicalDeviceProperties;

// Define VkMemoryType and VkMemoryHeap first (needed for VkPhysicalDeviceMemoryProperties)
typedef struct VkMemoryType {
    uint32_t propertyFlags;
    uint32_t heapIndex;
} VkMemoryType;

typedef struct VkMemoryHeap {
    uint64_t size;
    uint64_t flags;
} VkMemoryHeap;

// Now define VkPhysicalDeviceMemoryProperties using the proper types
typedef struct VkPhysicalDeviceMemoryProperties {
    uint32_t memoryTypeCount;
    VkMemoryType memoryTypes[32];
    uint32_t memoryHeapCount;
    VkMemoryHeap memoryHeaps[16];
} VkPhysicalDeviceMemoryProperties;

// VkQueueFamilyProperties for queue family queries
typedef struct VkQueueFamilyProperties {
    uint32_t queueFlags;
    uint32_t queueCount;
    uint32_t timestampValidBits;
    uint32_t minImageTransferGranularity[3];
} VkQueueFamilyProperties;

// Stub function declarations for CPU fallback
inline void vkGetPhysicalDeviceQueueFamilyProperties(VkPhysicalDevice, uint32_t* count, VkQueueFamilyProperties*) {
    if (count) *count = 0;
}
inline void vkGetPhysicalDeviceMemoryProperties(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties*) {}

// Additional Vulkan function stubs for CPU fallback compilation
inline VkResult vkCreateInstance(const void*, const void*, VkInstance*) { return 0; }
inline void vkDestroyInstance(VkInstance, const void*) {}
inline VkResult vkEnumeratePhysicalDevices(VkInstance, uint32_t* count, VkPhysicalDevice*) { if (count) *count = 0; return 0; }
inline void vkGetPhysicalDeviceProperties(VkPhysicalDevice, VkPhysicalDeviceProperties*) {}
inline VkResult vkCreateDevice(VkPhysicalDevice, const void*, const void*, VkDevice*) { return 0; }
inline void vkDestroyDevice(VkDevice, const void*) {}
inline void vkGetDeviceQueue(VkDevice, uint32_t, uint32_t, VkQueue*) {}
inline VkResult vkCreateCommandPool(VkDevice, const void*, const void*, VkCommandPool*) { return 0; }
inline void vkDestroyCommandPool(VkDevice, VkCommandPool, const void*) {}
inline VkResult vkCreateDescriptorSetLayout(VkDevice, const void*, const void*, VkDescriptorSetLayout*) { return 0; }
inline void vkDestroyDescriptorSetLayout(VkDevice, VkDescriptorSetLayout, const void*) {}
inline VkResult vkCreateDescriptorPool(VkDevice, const void*, const void*, VkDescriptorPool*) { return 0; }
inline void vkDestroyDescriptorPool(VkDevice, VkDescriptorPool, const void*) {}
inline VkResult vkCreatePipelineLayout(VkDevice, const void*, const void*, VkPipelineLayout*) { return 0; }
inline void vkDestroyPipelineLayout(VkDevice, VkPipelineLayout, const void*) {}
inline VkResult vkCreateShaderModule(VkDevice, const void*, const void*, VkShaderModule*) { return 0; }
inline void vkDestroyShaderModule(VkDevice, VkShaderModule, const void*) {}
inline VkResult vkCreateComputePipelines(VkDevice, VkPipelineCache, uint32_t, const void*, const void*, VkPipeline*) { return 0; }
inline void vkDestroyPipeline(VkDevice, VkPipeline, const void*) {}
inline VkResult vkCreateBuffer(VkDevice, const void*, const void*, VkBuffer*) { return 0; }
inline void vkDestroyBuffer(VkDevice, VkBuffer, const void*) {}
inline VkResult vkAllocateMemory(VkDevice, const void*, const void*, VkDeviceMemory*) { return 0; }
inline void vkFreeMemory(VkDevice, VkDeviceMemory, const void*) {}
inline void vkGetBufferMemoryRequirements(VkDevice, VkBuffer, void*) {}
inline VkResult vkBindBufferMemory(VkDevice, VkBuffer, VkDeviceMemory, uint64_t) { return 0; }
inline VkResult vkMapMemory(VkDevice, VkDeviceMemory, uint64_t, uint64_t, uint32_t, void**) { return 0; }
inline void vkUnmapMemory(VkDevice, VkDeviceMemory) {}
inline VkResult vkAllocateDescriptorSets(VkDevice, const void*, VkDescriptorSet*) { return 0; }
inline void vkUpdateDescriptorSets(VkDevice, uint32_t, const void*, uint32_t, const void*) {}
inline VkResult vkAllocateCommandBuffers(VkDevice, const void*, VkCommandBuffer*) { return 0; }
inline void vkFreeCommandBuffers(VkDevice, VkCommandPool, uint32_t, const VkCommandBuffer*) {}
inline VkResult vkBeginCommandBuffer(VkCommandBuffer, const void*) { return 0; }
inline VkResult vkEndCommandBuffer(VkCommandBuffer) { return 0; }
inline void vkCmdBindPipeline(VkCommandBuffer, uint32_t, VkPipeline) {}
inline void vkCmdBindDescriptorSets(VkCommandBuffer, uint32_t, VkPipelineLayout, uint32_t, uint32_t, const VkDescriptorSet*, uint32_t, const uint32_t*) {}
inline void vkCmdDispatch(VkCommandBuffer, uint32_t, uint32_t, uint32_t) {}
inline void vkCmdPushConstants(VkCommandBuffer, VkPipelineLayout, uint32_t, uint32_t, uint32_t, const void*) {}
inline void vkCmdCopyBuffer(VkCommandBuffer, VkBuffer, VkBuffer, uint32_t, const void*) {}
inline VkResult vkCreateFence(VkDevice, const void*, const void*, VkFence*) { return 0; }
inline void vkDestroyFence(VkDevice, VkFence, const void*) {}
inline VkResult vkQueueSubmit(VkQueue, uint32_t, const void*, VkFence) { return 0; }
inline VkResult vkQueueWaitIdle(VkQueue) { return 0; }
inline VkResult vkDeviceWaitIdle(VkDevice) { return 0; }
inline VkResult vkWaitForFences(VkDevice, uint32_t, const VkFence*, uint32_t, uint64_t) { return 0; }

#endif // VK_VERSION_1_0
#endif // !RAWR_VULKAN_AVAILABLE

// Forward declaration for gguf_loader.h which uses VulkanTensor at global scope
struct VulkanTensor;

namespace CPUInference {

// GPU compute optional - CPU inference always works
// Vulkan is enabled if system supports it, otherwise CPU fallback

struct VulkanDeviceInfo {
    std::string device_name;
    VkPhysicalDeviceProperties properties{};
    VkPhysicalDeviceMemoryProperties memory_props{};
    uint32_t vendor_id;
    uint32_t device_id;
    bool supports_compute;
    uint32_t compute_queue_family;
};

struct ComputeShader {
    std::string name;
    std::vector<uint32_t> spirv_code;
    VkShaderModule module = nullptr;
    VkPipelineLayout layout = nullptr;
    VkPipeline pipeline = nullptr;
};

struct VulkanTensor {
    std::string name;
    size_t size_bytes{0};
    std::vector<float> host_data;  // Scalar data stored in CPU memory
    VkBuffer device_buffer = nullptr;
    VkDeviceMemory device_memory = nullptr;
};

// Async command buffer pool for high-performance batching
struct CommandBufferPool {
    VkCommandBuffer buffer = nullptr;
    VkFence fence = nullptr;
    bool is_available = true;
};

class VulkanCompute {
public:
    VulkanCompute();
    ~VulkanCompute();

    bool Initialize();
    bool LoadShader(const std::string& name, const std::string& spirv_path);
    bool CreateComputePipeline(const std::string& shader_name);
    VulkanTensor TransferGGUFTensor(const std::string& tensor_name,
                                    const void* data_ptr,
                                    size_t size_bytes,
                                    uint32_t usage = 0);
    void ReleaseTensors();
    bool EnsureMatMulPipeline(const std::string& spirv_path);
    bool DispatchMatMul(uint32_t input_a_idx,
                        uint32_t input_b_idx,
                        uint32_t output_idx,
                        uint32_t M,
                        uint32_t K,
                        uint32_t N);
    
    // High-performance async variant using command buffer pooling
    bool DispatchMatMulAsync(uint32_t input_a_idx,
                             uint32_t input_b_idx,
                             uint32_t output_idx,
                             uint32_t M,
                             uint32_t K,
                             uint32_t N);
    
    // GEMV dispatch for transformer inference (FP32 weights, uploads data, dispatches, downloads result)
    bool DispatchGEMV(const float* weights, const float* input, float* output,
                      uint32_t rows, uint32_t cols);
    
    VulkanDeviceInfo GetDeviceInfo() const { return device_info_; }
    bool IsAMDDevice() const { return device_info_.vendor_id == 0x1002; }
    bool IsNvidiaDevice() const { return device_info_.vendor_id == 0x10DE; }
    
    bool AllocateBuffer(size_t size, uint32_t& buffer_idx, size_t& memory_size);
    bool AllocateBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory);
    bool CopyBufferToHost(uint32_t buffer_idx, void* host_data, size_t size);
    bool CopyBufferToHost(VkBuffer device_buffer, void* host_data, size_t size);
    bool CopyHostToBuffer(void* host_data, uint32_t buffer_idx, size_t size);
    bool CopyHostToBuffer(void* host_data, VkBuffer device_buffer, size_t size);
    
    // Staging buffer creation for async upload (CPU pointer -> VkBuffer)
    VkBuffer CreateStagingBuffer(const void* host_data, size_t size);
    
    // KV Cache management for autoregressive inference
    bool AllocateKVCache(uint32_t num_layers, uint32_t max_seq_len, uint32_t head_dim);
    bool AppendToKVCache(uint32_t layer_idx, const float* k_new, const float* v_new, uint32_t token_pos);
    bool GetKVCacheSlice(uint32_t layer_idx, uint32_t start_pos, uint32_t end_pos, float* k_out, float* v_out);
    void ClearKVCache();
    bool IsKVCacheAllocated() const { return kv_cache_allocated_; }
    
    // Command buffer & synchronization utilities
    bool ExecuteSingleTimeCommands(std::function<void(VkCommandBuffer)> record_func);
    bool ExecuteCommandBuffer(VkCommandBuffer cmd_buffer);
    
    // High-performance async execution
    VkCommandBuffer AcquireAsyncCommandBuffer();
    bool SubmitAsyncCommandBuffer(VkCommandBuffer cmd_buffer);
    bool FlushAsyncCommands();  // Wait for all pending async operations
    bool CheckAsyncCompletion(VkCommandBuffer cmd_buffer);  // Non-blocking check
    
    // Descriptor set management
    bool CreateDescriptorSetLayout(uint32_t binding_count, VkDescriptorSetLayout& layout);
    bool AllocateDescriptorSet(VkDescriptorSetLayout layout, VkDescriptorSet& descriptor_set);
    bool UpdateDescriptorSet(VkDescriptorSet descriptor_set, uint32_t binding, VkBuffer buffer, size_t buffer_size);
    
    // Scalar CPU implementations (no GPU)
    bool ExecuteMatMul(const float* input_a, const float* input_b, 
                       float* output, uint32_t m, uint32_t k, uint32_t n);
    bool ExecuteAttention(const float* queries, const float* keys, const float* values,
                         float* output, uint32_t seq_len, uint32_t head_dim);
    bool ExecuteRoPE(float* embeddings, uint32_t dim, uint32_t seq_pos, uint32_t rotation_dim);
    bool ExecuteRMSNorm(float* data, uint32_t size, float epsilon = 1e-5f);
    bool ExecuteSiLU(float* data, uint32_t size);
    bool ExecuteSoftmax(float* data, uint32_t size);
    bool ExecuteDequantize(const uint8_t* quantized, float* output,
                           uint32_t elements, const std::string& quant_type);
    
    void Cleanup();

private:
    bool CreateInstance();
    bool SelectPhysicalDevice();
    bool CreateLogicalDevice();
    bool CreateCommandPool();
    bool LoadSPIRVCode(const std::string& path, std::vector<uint32_t>& code);
    uint32_t FindMemoryType(uint32_t type_filter, VkMemoryPropertyFlags properties);

    VkInstance instance_ = nullptr;
    VkPhysicalDevice physical_device_ = nullptr;
    VkDevice device_ = nullptr;
    VkQueue compute_queue_ = nullptr;
    VkCommandPool command_pool_ = nullptr;
    VkDescriptorPool descriptor_pool_ = nullptr;

    // Async command buffer pooling for high-performance batching
    std::vector<CommandBufferPool> command_buffer_pool_;
    std::queue<size_t> available_buffer_indices_;

    // Permanent descriptor system for MatMul (avoid per-dispatch allocation overhead)
    VkDescriptorSetLayout matmul_descriptor_set_layout_ = nullptr;
    VkDescriptorPool matmul_descriptor_pool_ = nullptr;

    // KV Cache for autoregressive inference
    std::vector<std::pair<VkBuffer, VkDeviceMemory>> kv_cache_buffers_; // 2 per layer (K, V)
    uint32_t kv_cache_num_layers_ = 0;
    uint32_t kv_cache_max_seq_len_ = 0;
    uint32_t kv_cache_head_dim_ = 0;
    bool kv_cache_allocated_ = false;
    
    // Persistent staging buffer for optimized host-to-device transfers
    VkBuffer staging_buffer_ = nullptr;
    VkDeviceMemory staging_memory_ = nullptr;
    size_t staging_buffer_size_ = 0;

    // GEMV pipeline cache
    VkPipeline gemv_pipeline_ = nullptr;
    VkPipelineLayout gemv_pipeline_layout_ = nullptr;
    VkDescriptorSetLayout gemv_ds_layout_ = nullptr;
    VkDescriptorPool gemv_desc_pool_ = nullptr;
    bool gemv_pipeline_created_ = false;

    VulkanDeviceInfo device_info_;
    std::unordered_map<std::string, ComputeShader> shaders_;
    std::vector<VulkanTensor> uploaded_tensors_;
    std::vector<std::pair<VkBuffer, VkDeviceMemory>> allocated_buffers_;
    std::unordered_map<std::string, VkDescriptorSetLayout> descriptor_layouts_;
    
    // Helper methods for command buffer pool management
    void InitializeCommandBufferPool(uint32_t pool_size = 4);
    void CleanupCommandBufferPool();
    
    // Helper for offset-based buffer copies (KV cache updates)
    bool CopyHostToBufferOffset(const void* host_data, VkBuffer device_buffer, size_t offset, size_t size);
    bool CopyBufferToHostOffset(VkBuffer device_buffer, size_t offset, void* host_data, size_t size);
    
    // Helper for creating staging buffers (reduces code duplication)
    bool CreateStagingBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory);
};

} // namespace CPUInference
