#pragma once
#include <vulkan/vulkan.h>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>

namespace Deep2Rom::Compute {

    // A single Vulkan compute pipeline with its layout and descriptor set
    struct ComputePipeline {
        VkPipeline        pipeline{ VK_NULL_HANDLE };
        VkPipelineLayout  layout{ VK_NULL_HANDLE };
        VkDescriptorSetLayout dslayout{ VK_NULL_HANDLE };
        VkShaderModule    shaderModule{ VK_NULL_HANDLE };
        std::string       name;
        uint32_t          localSizeX{ 1 };
        uint32_t          localSizeY{ 1 };
        uint32_t          localSizeZ{ 1 };
    };

    // A Vulkan buffer with device memory allocation
    struct VulkanBuffer {
        VkBuffer        buffer{ VK_NULL_HANDLE };
        VkDeviceMemory  memory{ VK_NULL_HANDLE };
        VkDeviceSize    size{ 0 };
        bool            hostVisible{ false };
        void*           mapped{ nullptr };
    };

    class VulkanComputeEngine {
    public:
        VulkanComputeEngine();
        ~VulkanComputeEngine();

        // Initialize with an existing Vulkan device (created by caller)
        bool init(VkDevice device, VkPhysicalDevice physicalDevice,
                  uint32_t graphicsQueueFamilyIndex, uint32_t computeQueueFamilyIndex);

        // Create a compute pipeline from a SPIR-V file
        bool createComputePipeline(const std::string& name, const std::string& spirvPath,
                                   uint32_t pushConstantBytes,
                                   uint32_t descriptorSetCount);

        // Get a pipeline by name
        ComputePipeline* getPipeline(const std::string& name);

        // Allocate a device buffer
        bool createBuffer(VulkanBuffer& buf, VkDeviceSize size, VkBufferUsageFlags usage,
                          bool hostVisible = false);

        // Upload data to a host-visible buffer
        bool uploadBuffer(VulkanBuffer& buf, const void* data, VkDeviceSize size);

        // Begin a one-time command buffer
        bool beginCommandBuffer(VkCommandBuffer& cmd);

        // Submit and wait for completion
        bool submitAndWait(VkCommandBuffer cmd);

    // Allocate and bind a descriptor set for a pipeline with 3 storage buffers (weight, input, output)
    bool createDescriptorSet(ComputePipeline* pipeline, VkDescriptorSet& descSet,
                             VkBuffer weightBuf, VkBuffer inputBuf, VkBuffer outputBuf);

    // Update an existing descriptor set with new buffer bindings
    bool updateDescriptorSet(VkDescriptorSet descSet,
                             VkBuffer weightBuf, VkBuffer inputBuf, VkBuffer outputBuf);

    // Accessors
    VkDevice device() const { return m_device; }
    VkPhysicalDevice physicalDevice() const { return m_physicalDevice; }
    VkQueue computeQueue() const { return m_computeQueue; }
    VkCommandPool commandPool() const { return m_commandPool; }
    // The descriptor pool that owns every set this engine allocates. Callers
    // that free a set themselves need it: vkFreeDescriptorSets takes a pool,
    // not a device.
    VkDescriptorPool descriptorPool() const { return m_descriptorPool; }

        // Multi-GPU support
        void setPrimaryDevice(VkDevice device, VkPhysicalDevice physicalDevice);
        bool hasSecondaryDevice() const { return m_secondaryDevice != VK_NULL_HANDLE; }
        VkDevice secondaryDevice() const { return m_secondaryDevice; }

    private:
        VkDevice m_device{ VK_NULL_HANDLE };
        VkPhysicalDevice m_physicalDevice{ VK_NULL_HANDLE };
        VkQueue m_computeQueue{ VK_NULL_HANDLE };
        VkCommandPool m_commandPool{ VK_NULL_HANDLE };
        VkDescriptorPool m_descriptorPool{ VK_NULL_HANDLE };
        VkPipelineCache m_pipelineCache{ VK_NULL_HANDLE };

        // Secondary (asymmetric) GPU
        VkDevice m_secondaryDevice{ VK_NULL_HANDLE };
        VkPhysicalDevice m_secondaryPhysicalDevice{ VK_NULL_HANDLE };
        VkQueue m_secondaryComputeQueue{ VK_NULL_HANDLE };
        VkCommandPool m_secondaryCommandPool{ VK_NULL_HANDLE };

        std::mutex m_mutex;
        std::unordered_map<std::string, ComputePipeline> m_pipelines;

        bool createShaderModule(const std::vector<uint32_t>& code, VkShaderModule& outModule);
        bool createDescriptorPool();
    };

} // namespace Deep2Rom::Compute
