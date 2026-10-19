#include "VulkanStagingPipeline.hpp"
#include <iostream>

namespace Deep2Rom::Compute {

    VulkanStagingPipeline::VulkanStagingPipeline(VkDevice device, VkPhysicalDevice gpu)
        : m_device(device), m_gpu(gpu) {}

    VulkanStagingPipeline::~VulkanStagingPipeline() {}

    bool VulkanStagingPipeline::acquire_staging_buffer(size_t size, StagingSlot& out_slot) {
        VkBufferCreateInfo buffer_info{ VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
        buffer_info.size = size;
        buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        if (::vkCreateBuffer(m_device, &buffer_info, nullptr, &out_slot.buffer) != VK_SUCCESS) return false;

        VkMemoryRequirements mem_reqs;
        ::vkGetBufferMemoryRequirements(m_device, out_slot.buffer, &mem_reqs);
        VkPhysicalDeviceMemoryProperties mem_props;
        ::vkGetPhysicalDeviceMemoryProperties(m_gpu, &mem_props);
        
        uint32_t type_index = 0xFFFFFFFF;
        for (uint32_t i = 0; i < mem_props.memoryTypeCount; i++) {
            if ((mem_reqs.memoryTypeBits & (1 << i)) && (mem_props.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) == (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
                type_index = i; break;
            }
        }
        if (type_index == 0xFFFFFFFF) return false;

        VkMemoryAllocateInfo alloc_info{ VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
        alloc_info.allocationSize = mem_reqs.size;
        alloc_info.memoryTypeIndex = type_index;
        if (::vkAllocateMemory(m_device, &alloc_info, nullptr, &out_slot.memory) != VK_SUCCESS) return false;

        ::vkBindBufferMemory(m_device, out_slot.buffer, out_slot.memory, 0);
        ::vkMapMemory(m_device, out_slot.memory, 0, size, 0, &out_slot.mapped_ptr);
        out_slot.size = size;
        return true;
    }

    void VulkanStagingPipeline::release_staging_buffer(StagingSlot& slot) {
        if (slot.buffer) {
            if (slot.mapped_ptr) {
                ::vkUnmapMemory(m_device, slot.memory);
            }
            ::vkDestroyBuffer(m_device, slot.buffer, nullptr);
            ::vkFreeMemory(m_device, slot.memory, nullptr);
            slot.buffer = VK_NULL_HANDLE;
            slot.memory = VK_NULL_HANDLE;
            slot.mapped_ptr = nullptr;
            slot.size = 0;
        }
    }

    bool VulkanStagingPipeline::enqueue_asynchronous_dma(VkQueue queue, VkCommandBuffer cmd, const StagingSlot& src, VkBuffer dst, size_t size) {
        VkCommandBufferBeginInfo begin{ VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
        begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        if (::vkBeginCommandBuffer(cmd, &begin) != VK_SUCCESS) return false;

        VkBufferCopy region{ 0, 0, size };
        ::vkCmdCopyBuffer(cmd, src.buffer, dst, 1, &region);

        VkBufferMemoryBarrier barrier{ VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER };
        barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        barrier.buffer = dst;
        barrier.offset = 0;
        barrier.size = size;
        ::vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 0, nullptr, 1, &barrier, 0, nullptr);

        if (::vkEndCommandBuffer(cmd) != VK_SUCCESS) return false;

        VkSubmitInfo submit{ VK_STRUCTURE_TYPE_SUBMIT_INFO };
        submit.commandBufferCount = 1;
        submit.pCommandBuffers = &cmd;
        if (::vkQueueSubmit(queue, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS) return false;

        ::vkQueueWaitIdle(queue);
        return true;
    }
}