#pragma once
#include "Deep2Types.hpp"
#include <vulkan/vulkan.h>

namespace Deep2Rom::Compute {

    struct StagingSlot {
        VkBuffer       buffer{ VK_NULL_HANDLE };
        VkDeviceMemory memory{ VK_NULL_HANDLE };
        void*          mapped_ptr{ nullptr };
        size_t         size{ 0 };
    };

    class VulkanStagingPipeline {
    public:
        VulkanStagingPipeline(VkDevice device, VkPhysicalDevice gpu);
        ~VulkanStagingPipeline();

        bool acquire_staging_buffer(size_t size, StagingSlot& out_slot);
        void release_staging_buffer(StagingSlot& slot);
        bool enqueue_asynchronous_dma(VkQueue queue, VkCommandBuffer cmd, const StagingSlot& src, VkBuffer dst, size_t size);
        
    private:
        VkDevice m_device;
        VkPhysicalDevice m_gpu;
    };
}