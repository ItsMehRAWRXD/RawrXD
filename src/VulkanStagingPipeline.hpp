#pragma once
#include <vulkan/vulkan.h>
#include <windows.h>
#include <vector>
#include <mutex>

namespace Deep2Rom::Compute {

    struct StagingSlot {
        VkBuffer       buffer{ VK_NULL_HANDLE };
        VkDeviceMemory memory{ VK_NULL_HANDLE };
        void*          mapped_ptr{ nullptr };
        size_t         capacity{ 0 };
        bool           in_use{ false };
    };

    class VulkanStagingPipeline {
    public:
        VulkanStagingPipeline(VkDevice logical_device, VkPhysicalDevice physical_device)
            : m_device(logical_device), m_gpu(physical_device) {}

        ~VulkanStagingPipeline();

        VulkanStagingPipeline(const VulkanStagingPipeline&) = delete;
        VulkanStagingPipeline& operator=(const VulkanStagingPipeline&) = delete;

        bool acquire_staging_buffer(size_t size, StagingSlot& out_slot);
        void release_staging_buffer(StagingSlot& slot);

        bool enqueue_asynchronous_dma(
            VkQueue transfer_queue,
            VkCommandBuffer cmd_buffer,
            const StagingSlot& src_slot,
            VkBuffer dst_vram_buffer,
            size_t bytes_count
        );

    private:
        uint32_t resolve_memory_type_index(uint32_t type_filter, VkMemoryPropertyFlags properties);

        VkDevice         m_device;
        VkPhysicalDevice m_gpu;
        std::vector<StagingSlot> m_pool;
        std::mutex       m_pool_mutex;
    };
}
