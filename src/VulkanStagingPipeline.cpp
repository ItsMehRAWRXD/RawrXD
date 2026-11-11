#include "VulkanStagingPipeline.hpp"
#include <iostream>

namespace Deep2Rom::Compute {

    VulkanStagingPipeline::~VulkanStagingPipeline() {
        std::lock_guard<std::mutex> lock(m_pool_mutex);
        for (auto& slot : m_pool) {
            if (slot.buffer != VK_NULL_HANDLE) {
                if (slot.memory != VK_NULL_HANDLE && slot.mapped_ptr != nullptr) {
                    ::vkUnmapMemory(m_device, slot.memory);
                }
                if (slot.buffer != VK_NULL_HANDLE) {
                    ::vkDestroyBuffer(m_device, slot.buffer, nullptr);
                }
                if (slot.memory != VK_NULL_HANDLE) {
                    ::vkFreeMemory(m_device, slot.memory, nullptr);
                }
            }
        }
        m_pool.clear();
    }

    uint32_t VulkanStagingPipeline::resolve_memory_type_index(uint32_t type_filter, VkMemoryPropertyFlags properties) {
        VkPhysicalDeviceMemoryProperties mem_props;
        ::vkGetPhysicalDeviceMemoryProperties(m_gpu, &mem_props);
        for (uint32_t i = 0; i < mem_props.memoryTypeCount; i++) {
            if ((type_filter & (1u << i)) &&
                (mem_props.memoryTypes[i].propertyFlags & properties) == properties) {
                return i;
            }
        }
        return 0xFFFFFFFFu;
    }

    bool VulkanStagingPipeline::acquire_staging_buffer(size_t size, StagingSlot& out_slot) {
        std::lock_guard<std::mutex> lock(m_pool_mutex);

        // Reuse an existing free slot with sufficient capacity
        for (auto& slot : m_pool) {
            if (!slot.in_use && slot.capacity >= size) {
                slot.in_use = true;
                out_slot = slot;
                return true;
            }
        }

        // Allocate a new host-visible, host-coherent staging buffer
        VkBufferCreateInfo buffer_info{ VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
        buffer_info.size = size;
        buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

        if (::vkCreateBuffer(m_device, &buffer_info, nullptr, &out_slot.buffer) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkCreateBuffer failed\n";
            return false;
        }

        VkMemoryRequirements mem_reqs;
        ::vkGetBufferMemoryRequirements(m_device, out_slot.buffer, &mem_reqs);

        VkMemoryAllocateInfo alloc_info{ VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
        alloc_info.allocationSize = mem_reqs.size;
        alloc_info.memoryTypeIndex = resolve_memory_type_index(
            mem_reqs.memoryTypeBits,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);

        if (alloc_info.memoryTypeIndex == 0xFFFFFFFFu ||
            ::vkAllocateMemory(m_device, &alloc_info, nullptr, &out_slot.memory) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkAllocateMemory failed\n";
            ::vkDestroyBuffer(m_device, out_slot.buffer, nullptr);
            out_slot.buffer = VK_NULL_HANDLE;
            return false;
        }

        if (::vkBindBufferMemory(m_device, out_slot.buffer, out_slot.memory, 0) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkBindBufferMemory failed\n";
            ::vkDestroyBuffer(m_device, out_slot.buffer, nullptr);
            ::vkFreeMemory(m_device, out_slot.memory, nullptr);
            out_slot.buffer = VK_NULL_HANDLE;
            out_slot.memory = VK_NULL_HANDLE;
            return false;
        }

        if (::vkMapMemory(m_device, out_slot.memory, 0, size, 0, &out_slot.mapped_ptr) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkMapMemory failed\n";
            ::vkDestroyBuffer(m_device, out_slot.buffer, nullptr);
            ::vkFreeMemory(m_device, out_slot.memory, nullptr);
            out_slot.buffer = VK_NULL_HANDLE;
            out_slot.memory = VK_NULL_HANDLE;
            return false;
        }

        out_slot.capacity = size;
        out_slot.in_use = true;
        m_pool.push_back(out_slot);
        return true;
    }

    void VulkanStagingPipeline::release_staging_buffer(StagingSlot& slot) {
        std::lock_guard<std::mutex> lock(m_pool_mutex);
        for (auto& pooled_slot : m_pool) {
            if (pooled_slot.buffer == slot.buffer) {
                pooled_slot.in_use = false;
                break;
            }
        }
    }

    bool VulkanStagingPipeline::enqueue_asynchronous_dma(
        VkQueue transfer_queue,
        VkCommandBuffer cmd_buffer,
        const StagingSlot& src_slot,
        VkBuffer dst_vram_buffer,
        size_t bytes_count)
    {
        VkCommandBufferBeginInfo begin_info{ VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
        begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

        if (::vkBeginCommandBuffer(cmd_buffer, &begin_info) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkBeginCommandBuffer failed\n";
            return false;
        }

        VkBufferCopy region{};
        region.srcOffset = 0;
        region.dstOffset = 0;
        region.size = bytes_count;

        ::vkCmdCopyBuffer(cmd_buffer, src_slot.buffer, dst_vram_buffer, 1, &region);

        VkBufferMemoryBarrier barrier{ VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER };
        barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barrier.buffer = dst_vram_buffer;
        barrier.size = bytes_count;

        ::vkCmdPipelineBarrier(cmd_buffer,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
            0, 0, nullptr, 1, &barrier, 0, nullptr);

        if (::vkEndCommandBuffer(cmd_buffer) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkEndCommandBuffer failed\n";
            return false;
        }

        VkSubmitInfo submit_info{ VK_STRUCTURE_TYPE_SUBMIT_INFO };
        submit_info.commandBufferCount = 1;
        submit_info.pCommandBuffers = &cmd_buffer;

        return ::vkQueueSubmit(transfer_queue, 1, &submit_info, VK_NULL_HANDLE) == VK_SUCCESS;
    }
}
