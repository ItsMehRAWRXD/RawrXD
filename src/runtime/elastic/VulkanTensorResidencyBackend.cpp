// ============================================================================
// VulkanTensorResidencyBackend.cpp
// Real Vulkan buffer allocation for ElasticResidencyManager.
// ============================================================================
#include "VulkanTensorResidencyBackend.hpp"
#include <cstdio>
#include <string>

namespace RawrXD::Elastic {

VulkanTensorResidencyBackend::VulkanTensorResidencyBackend(VkDevice device, VkPhysicalDevice physDevice,
                                                                          VkQueue queue, VkCommandPool cmdPool)
    : m_device(device), m_physDevice(physDevice), m_queue(queue), m_cmdPool(cmdPool) {}

VulkanTensorResidencyBackend::~VulkanTensorResidencyBackend() {
    // NOTE: caller must ensure all tensors are freed before destruction
}

uint32_t VulkanTensorResidencyBackend::FindMemoryType(uint32_t typeBits, VkMemoryPropertyFlags props) {
    VkPhysicalDeviceMemoryProperties memProps;
    vkGetPhysicalDeviceMemoryProperties(m_physDevice, &memProps);
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        if ((typeBits & (1u << i)) &&
            (memProps.memoryTypes[i].propertyFlags & props) == props) {
            return i;
        }
    }
    return UINT32_MAX;
}

void* VulkanTensorResidencyBackend::AllocateTensor(uint64_t requested_bytes, uint64_t& out_allocated_bytes) {
    if (!m_device || requested_bytes == 0) {
        out_allocated_bytes = 0;
        return nullptr;
    }

    // Create buffer
    VkBufferCreateInfo bufferInfo{};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufferInfo.size = requested_bytes;
    bufferInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bufferInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer buffer = VK_NULL_HANDLE;
    VkResult result = vkCreateBuffer(m_device, &bufferInfo, nullptr, &buffer);
    if (result != VK_SUCCESS || buffer == VK_NULL_HANDLE) {
        printf("[VulkanTensorResidencyBackend] vkCreateBuffer failed (VkResult=%d, size=%llu)\n",
               static_cast<int>(result), static_cast<unsigned long long>(requested_bytes));
        out_allocated_bytes = 0;
        return nullptr;
    }

    // Get memory requirements
    VkMemoryRequirements memReqs{};
    vkGetBufferMemoryRequirements(m_device, buffer, &memReqs);

    // Prefer device-local; fall back to host-visible
    VkMemoryPropertyFlags props = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    uint32_t memType = FindMemoryType(memReqs.memoryTypeBits, props);
    if (memType == UINT32_MAX) {
        props = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
        memType = FindMemoryType(memReqs.memoryTypeBits, props);
    }
    if (memType == UINT32_MAX) {
        printf("[VulkanTensorResidencyBackend] No suitable memory type found\n");
        vkDestroyBuffer(m_device, buffer, nullptr);
        out_allocated_bytes = 0;
        return nullptr;
    }

    // Allocate memory
    VkMemoryAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memReqs.size;
    allocInfo.memoryTypeIndex = memType;

    VkDeviceMemory memory = VK_NULL_HANDLE;
    result = vkAllocateMemory(m_device, &allocInfo, nullptr, &memory);
    if (result != VK_SUCCESS || memory == VK_NULL_HANDLE) {
        printf("[VulkanTensorResidencyBackend] vkAllocateMemory failed (VkResult=%d, size=%llu)\n",
               static_cast<int>(result), static_cast<unsigned long long>(memReqs.size));
        vkDestroyBuffer(m_device, buffer, nullptr);
        out_allocated_bytes = 0;
        return nullptr;
    }

    // Bind
    result = vkBindBufferMemory(m_device, buffer, memory, 0);
    if (result != VK_SUCCESS) {
        printf("[VulkanTensorResidencyBackend] vkBindBufferMemory failed (VkResult=%d)\n",
               static_cast<int>(result));
        vkFreeMemory(m_device, memory, nullptr);
        vkDestroyBuffer(m_device, buffer, nullptr);
        out_allocated_bytes = 0;
        return nullptr;
    }

    auto* handle = new VulkanTensorHandle{};
    handle->buffer = buffer;
    handle->memory = memory;
    handle->allocated_bytes = memReqs.size;
    handle->requested_bytes = requested_bytes;

    out_allocated_bytes = memReqs.size;
    total_allocated_.fetch_add(memReqs.size);
    tensor_count_.fetch_add(1);

    printf("[VulkanTensorResidencyBackend] Allocated tensor: %llu bytes (aligned %llu)\n",
           static_cast<unsigned long long>(requested_bytes),
           static_cast<unsigned long long>(memReqs.size));
    return static_cast<void*>(handle);
}

void VulkanTensorResidencyBackend::FreeTensor(void* opaque_handle) {
    if (!opaque_handle || !m_device) return;

    auto* handle = static_cast<VulkanTensorHandle*>(opaque_handle);
    if (handle->buffer != VK_NULL_HANDLE) {
        vkDestroyBuffer(m_device, handle->buffer, nullptr);
    }
    if (handle->memory != VK_NULL_HANDLE) {
        vkFreeMemory(m_device, handle->memory, nullptr);
    }

    total_allocated_.fetch_sub(handle->allocated_bytes);
    tensor_count_.fetch_sub(1);

    printf("[VulkanTensorResidencyBackend] Freed tensor: %llu bytes\n",
           static_cast<unsigned long long>(handle->allocated_bytes));
    delete handle;
}

bool VulkanTensorResidencyBackend::UploadData(void* opaque_handle, const void* src_data, uint64_t bytes) {
    if (!opaque_handle || !src_data || bytes == 0) return false;

    auto* handle = static_cast<VulkanTensorHandle*>(opaque_handle);

    // For device-local memory, we need a staging buffer
    VkMemoryRequirements memReqs{};
    vkGetBufferMemoryRequirements(m_device, handle->buffer, &memReqs);

    // Check if memory is host-visible
    VkPhysicalDeviceMemoryProperties memProps{};
    vkGetPhysicalDeviceMemoryProperties(m_physDevice, &memProps);

    uint32_t memTypeIdx = UINT32_MAX;
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        if ((memReqs.memoryTypeBits & (1u << i)) &&
            (memProps.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
            memTypeIdx = i;
            break;
        }
    }

    bool isDeviceLocal = (memTypeIdx != UINT32_MAX) &&
                         (memProps.memoryTypes[memTypeIdx].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) != 0;

    if (!isDeviceLocal) {
        // Host-visible: map and memcpy
        void* mapped = nullptr;
        VkResult result = vkMapMemory(m_device, handle->memory, 0, bytes, 0, &mapped);
        if (result != VK_SUCCESS) return false;
        std::memcpy(mapped, src_data, static_cast<size_t>(bytes));
        vkUnmapMemory(m_device, handle->memory);
        return true;
    }

    // Device-local: create staging buffer
    VkBufferCreateInfo stagingInfo{};
    stagingInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    stagingInfo.size = bytes;
    stagingInfo.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    stagingInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer stagingBuffer = VK_NULL_HANDLE;
    VkResult result = vkCreateBuffer(m_device, &stagingInfo, nullptr, &stagingBuffer);
    if (result != VK_SUCCESS) return false;

    VkMemoryRequirements stagingReqs{};
    vkGetBufferMemoryRequirements(m_device, stagingBuffer, &stagingReqs);

    uint32_t stagingMemType = FindMemoryType(stagingReqs.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (stagingMemType == UINT32_MAX) {
        vkDestroyBuffer(m_device, stagingBuffer, nullptr);
        return false;
    }

    VkMemoryAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = stagingReqs.size;
    allocInfo.memoryTypeIndex = stagingMemType;

    VkDeviceMemory stagingMemory = VK_NULL_HANDLE;
    result = vkAllocateMemory(m_device, &allocInfo, nullptr, &stagingMemory);
    if (result != VK_SUCCESS) {
        vkDestroyBuffer(m_device, stagingBuffer, nullptr);
        return false;
    }

    result = vkBindBufferMemory(m_device, stagingBuffer, stagingMemory, 0);
    if (result != VK_SUCCESS) {
        vkFreeMemory(m_device, stagingMemory, nullptr);
        vkDestroyBuffer(m_device, stagingBuffer, nullptr);
        return false;
    }

    // Map staging, copy data
    void* mapped = nullptr;
    result = vkMapMemory(m_device, stagingMemory, 0, bytes, 0, &mapped);
    if (result != VK_SUCCESS) {
        vkFreeMemory(m_device, stagingMemory, nullptr);
        vkDestroyBuffer(m_device, stagingBuffer, nullptr);
        return false;
    }
    std::memcpy(mapped, src_data, static_cast<size_t>(bytes));

    // Flush if memory is not coherent
    if (!(memProps.memoryTypes[stagingMemType].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
        VkMappedMemoryRange flushRange{};
        flushRange.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
        flushRange.memory = stagingMemory;
        flushRange.offset = 0;
        flushRange.size = VK_WHOLE_SIZE;
        vkFlushMappedMemoryRanges(m_device, 1, &flushRange);
    }

    vkUnmapMemory(m_device, stagingMemory);

    // Submit actual GPU transfer
    bool transferOk = SubmitCopyBuffer(stagingBuffer, handle->buffer, bytes);

    // Clean up staging resources
    vkFreeMemory(m_device, stagingMemory, nullptr);
    vkDestroyBuffer(m_device, stagingBuffer, nullptr);

    if (transferOk) {
        printf("[VulkanTensorResidencyBackend] UploadData: %llu bytes transferred to GPU\n",
               static_cast<unsigned long long>(bytes));
    } else {
        printf("[VulkanTensorResidencyBackend] UploadData: transfer submission FAILED\n");
    }
    return transferOk;
}

VkBuffer VulkanTensorResidencyBackend::GetVkBuffer(void* opaque_handle) {
    if (!opaque_handle) return VK_NULL_HANDLE;
    auto* handle = static_cast<VulkanTensorHandle*>(opaque_handle);
    return handle->buffer;
}

ElasticResidencyManager::GpuAllocator VulkanTensorResidencyBackend::GetAllocator() {
    return [this](uint64_t req, uint64_t& out) -> void* {
        return this->AllocateTensor(req, out);
    };
}

ElasticResidencyManager::GpuDeallocator VulkanTensorResidencyBackend::GetDeallocator() {
    return [this](void* h) {
        this->FreeTensor(h);
    };
}

// ============================================================================
// SubmitCopyBuffer
// Records vkCmdCopyBuffer, submits to queue, waits on fence.
// ============================================================================
bool VulkanTensorResidencyBackend::SubmitCopyBuffer(VkBuffer src, VkBuffer dst, uint64_t bytes) {
    if (!m_device || !m_queue || !m_cmdPool) {
        printf("[VulkanTensorResidencyBackend] SubmitCopyBuffer: missing device/queue/pool\n");
        return false;
    }

    // Allocate command buffer
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = m_cmdPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer cmdBuf = VK_NULL_HANDLE;
    VkResult result = vkAllocateCommandBuffers(m_device, &allocInfo, &cmdBuf);
    if (result != VK_SUCCESS || cmdBuf == VK_NULL_HANDLE) {
        printf("[VulkanTensorResidencyBackend] vkAllocateCommandBuffers failed (VkResult=%d)\n", static_cast<int>(result));
        return false;
    }

    // Begin recording
    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    result = vkBeginCommandBuffer(cmdBuf, &beginInfo);
    if (result != VK_SUCCESS) {
        printf("[VulkanTensorResidencyBackend] vkBeginCommandBuffer failed (VkResult=%d)\n", static_cast<int>(result));
        vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);
        return false;
    }

    // Record copy
    VkBufferCopy copyRegion{};
    copyRegion.srcOffset = 0;
    copyRegion.dstOffset = 0;
    copyRegion.size = bytes;
    vkCmdCopyBuffer(cmdBuf, src, dst, 1, &copyRegion);

    // End recording
    result = vkEndCommandBuffer(cmdBuf);
    if (result != VK_SUCCESS) {
        printf("[VulkanTensorResidencyBackend] vkEndCommandBuffer failed (VkResult=%d)\n", static_cast<int>(result));
        vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);
        return false;
    }

    // Create fence for synchronization
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence fence = VK_NULL_HANDLE;
    result = vkCreateFence(m_device, &fenceInfo, nullptr, &fence);
    if (result != VK_SUCCESS || fence == VK_NULL_HANDLE) {
        printf("[VulkanTensorResidencyBackend] vkCreateFence failed (VkResult=%d)\n", static_cast<int>(result));
        vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);
        return false;
    }

    // Submit
    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmdBuf;

    result = vkQueueSubmit(m_queue, 1, &submitInfo, fence);
    if (result != VK_SUCCESS) {
        printf("[VulkanTensorResidencyBackend] vkQueueSubmit failed (VkResult=%d)\n", static_cast<int>(result));
        vkDestroyFence(m_device, fence, nullptr);
        vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);
        return false;
    }

    // Wait for completion (blocking — acceptable for residency uploads)
    constexpr uint64_t kFenceTimeoutNs = 10ULL * 1000 * 1000 * 1000; // 10 seconds
    result = vkWaitForFences(m_device, 1, &fence, VK_TRUE, kFenceTimeoutNs);
    if (result != VK_SUCCESS) {
        printf("[VulkanTensorResidencyBackend] vkWaitForFences failed (VkResult=%d)\n", static_cast<int>(result));
        vkDestroyFence(m_device, fence, nullptr);
        vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);
        return false;
    }

    // Cleanup
    vkDestroyFence(m_device, fence, nullptr);
    vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);

    return true;
}

} // namespace RawrXD::Elastic
