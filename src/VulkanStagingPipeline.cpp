#include "VulkanStagingPipeline.hpp"
#include <iostream>
#include <algorithm>
#include <cstdint>

namespace Deep2Rom::Compute {

    VulkanStagingPipeline::~VulkanStagingPipeline() {
        std::lock_guard<std::mutex> lock(m_pool_mutex);
        if (m_device != VK_NULL_HANDLE) {
            // Submitted copies still read from their source staging buffers.
            // Drain those transfers before unmapping or freeing any slot.
            for (auto& slot : m_pool) {
                if (slot.pending_fence != VK_NULL_HANDLE) {
                    const VkResult waited = ::vkWaitForFences(
                        m_device, 1, &slot.pending_fence, VK_TRUE, UINT64_MAX);
                    if (waited != VK_SUCCESS)
                        std::cerr << "[VulkanStaging] fence wait during teardown failed: "
                                  << waited << "\\n";
                    ::vkDestroyFence(m_device, slot.pending_fence, nullptr);
                    slot.pending_fence = VK_NULL_HANDLE;
                }
            }
            for (auto& slot : m_pool) {
                if (slot.mapped_ptr && slot.memory != VK_NULL_HANDLE)
                    ::vkUnmapMemory(m_device, slot.memory);
                if (slot.buffer != VK_NULL_HANDLE)
                    ::vkDestroyBuffer(m_device, slot.buffer, nullptr);
                if (slot.memory != VK_NULL_HANDLE)
                    ::vkFreeMemory(m_device, slot.memory, nullptr);
                slot = {};
            }
        }
        m_pool.clear();
    }

    uint32_t VulkanStagingPipeline::resolve_memory_type_index(
        uint32_t type_filter, VkMemoryPropertyFlags properties) {
        VkPhysicalDeviceMemoryProperties mem_props{};
        ::vkGetPhysicalDeviceMemoryProperties(m_gpu, &mem_props);
        for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
            if ((type_filter & (1u << i)) &&
                (mem_props.memoryTypes[i].propertyFlags & properties) == properties)
                return i;
        }
        return 0xFFFFFFFFu;
    }

    bool VulkanStagingPipeline::acquire_staging_buffer(size_t size, StagingSlot& out_slot) {
        if (!size || m_device == VK_NULL_HANDLE || m_gpu == VK_NULL_HANDLE)
            return false;
        std::lock_guard<std::mutex> lock(m_pool_mutex);

        // Reclaim completed fences before considering a slot reusable. A
        // released slot with an in-flight transfer must never be overwritten.
        for (auto& slot : m_pool) {
            if (slot.in_use || slot.capacity < size) continue;
            if (slot.pending_fence != VK_NULL_HANDLE) {
                const VkResult status = ::vkGetFenceStatus(m_device, slot.pending_fence);
                if (status != VK_SUCCESS) continue; // NOT_READY and device errors both fail closed.
                ::vkDestroyFence(m_device, slot.pending_fence, nullptr);
                slot.pending_fence = VK_NULL_HANDLE;
            }
            slot.in_use = true;
            out_slot = slot;
            return true;
        }

        StagingSlot candidate{};
        VkBufferCreateInfo buffer_info{ VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
        buffer_info.size = size;
        buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        if (::vkCreateBuffer(m_device, &buffer_info, nullptr, &candidate.buffer) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkCreateBuffer failed\\n";
            return false;
        }

        VkMemoryRequirements mem_reqs{};
        ::vkGetBufferMemoryRequirements(m_device, candidate.buffer, &mem_reqs);
        VkMemoryAllocateInfo alloc_info{ VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
        alloc_info.allocationSize = mem_reqs.size;
        alloc_info.memoryTypeIndex = resolve_memory_type_index(
            mem_reqs.memoryTypeBits,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        if (alloc_info.memoryTypeIndex == 0xFFFFFFFFu ||
            ::vkAllocateMemory(m_device, &alloc_info, nullptr, &candidate.memory) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] host-visible coherent memory allocation failed\\n";
            ::vkDestroyBuffer(m_device, candidate.buffer, nullptr);
            return false;
        }
        if (::vkBindBufferMemory(m_device, candidate.buffer, candidate.memory, 0) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkBindBufferMemory failed\\n";
            ::vkDestroyBuffer(m_device, candidate.buffer, nullptr);
            ::vkFreeMemory(m_device, candidate.memory, nullptr);
            return false;
        }
        if (::vkMapMemory(m_device, candidate.memory, 0, mem_reqs.size, 0,
                          &candidate.mapped_ptr) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkMapMemory failed\\n";
            ::vkDestroyBuffer(m_device, candidate.buffer, nullptr);
            ::vkFreeMemory(m_device, candidate.memory, nullptr);
            return false;
        }

        candidate.capacity = static_cast<size_t>(std::min<VkDeviceSize>(
            mem_reqs.size, static_cast<VkDeviceSize>(SIZE_MAX)));
        candidate.in_use = true;
        m_pool.push_back(candidate);
        out_slot = candidate;
        return true;
    }

    void VulkanStagingPipeline::release_staging_buffer(StagingSlot& slot) {
        std::lock_guard<std::mutex> lock(m_pool_mutex);
        for (auto& pooled_slot : m_pool) {
            if (pooled_slot.buffer == slot.buffer && slot.buffer != VK_NULL_HANDLE) {
                pooled_slot.in_use = false;
                slot.in_use = false;
                return;
            }
        }
        // Unknown/stale handles are not allowed to affect another pool entry.
        slot.in_use = false;
    }

    bool VulkanStagingPipeline::enqueue_asynchronous_dma(
        VkQueue transfer_queue,
        VkCommandBuffer cmd_buffer,
        const StagingSlot& src_slot,
        VkBuffer dst_vram_buffer,
        size_t bytes_count) {
        if (transfer_queue == VK_NULL_HANDLE || cmd_buffer == VK_NULL_HANDLE ||
            dst_vram_buffer == VK_NULL_HANDLE || !bytes_count ||
            bytes_count > src_slot.capacity || src_slot.buffer == VK_NULL_HANDLE)
            return false;

        std::lock_guard<std::mutex> lock(m_pool_mutex);
        auto pooled = std::find_if(m_pool.begin(), m_pool.end(),
            [&src_slot](const StagingSlot& item) {
                return item.buffer == src_slot.buffer && item.in_use &&
                       item.pending_fence == VK_NULL_HANDLE;
            });
        if (pooled == m_pool.end()) return false;

        VkCommandBufferBeginInfo begin_info{ VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
        begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        if (::vkBeginCommandBuffer(cmd_buffer, &begin_info) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkBeginCommandBuffer failed\\n";
            return false;
        }

        VkBufferCopy region{};
        region.srcOffset = 0;
        region.dstOffset = 0;
        region.size = static_cast<VkDeviceSize>(bytes_count);
        ::vkCmdCopyBuffer(cmd_buffer, src_slot.buffer, dst_vram_buffer, 1, &region);

        VkBufferMemoryBarrier barrier{ VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER };
        barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        barrier.buffer = dst_vram_buffer;
        barrier.offset = 0;
        barrier.size = static_cast<VkDeviceSize>(bytes_count);
        ::vkCmdPipelineBarrier(cmd_buffer,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
            0, 0, nullptr, 1, &barrier, 0, nullptr);

        if (::vkEndCommandBuffer(cmd_buffer) != VK_SUCCESS) {
            std::cerr << "[VulkanStaging] vkEndCommandBuffer failed\\n";
            return false;
        }

        VkFenceCreateInfo fence_info{ VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
        VkFence fence = VK_NULL_HANDLE;
        if (::vkCreateFence(m_device, &fence_info, nullptr, &fence) != VK_SUCCESS)
            return false;

        VkSubmitInfo submit_info{ VK_STRUCTURE_TYPE_SUBMIT_INFO };
        submit_info.commandBufferCount = 1;
        submit_info.pCommandBuffers = &cmd_buffer;
        const VkResult submitted = ::vkQueueSubmit(transfer_queue, 1, &submit_info, fence);
        if (submitted != VK_SUCCESS) {
            ::vkDestroyFence(m_device, fence, nullptr);
            std::cerr << "[VulkanStaging] vkQueueSubmit failed: " << submitted << "\\n";
            return false;
        }

        // Keep the fence attached to the pool-owned slot. The CPU may release
        // its lease now, but acquire_staging_buffer will not recycle the bytes
        // until this exact submission has completed.
        pooled->pending_fence = fence;
        return true;
    }
}
