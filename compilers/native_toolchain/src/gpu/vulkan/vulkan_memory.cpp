// vulkan_memory.cpp - Vulkan Memory Management
// Phase 8.3 G12: Vulkan Compute Implementation

#define VK_USE_PLATFORM_WIN32_KHR
#define NOMINMAX

#include "vulkan_backend.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// MEMORY ALLOCATION
// ============================================================================

void* Vulkan_Allocate(GPUBackend* backend, size_t size) {
    if (!backend || !backend->device) return NULL;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    // Find memory type
    uint32_t memory_type_index = UINT32_MAX;
    for (uint32_t i = 0; i < ctx->memory_props.memoryTypeCount; i++) {
        VkMemoryPropertyFlags flags = ctx->memory_props.memoryTypes[i].propertyFlags;
        // Prefer device local + host visible for easy upload
        if ((flags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) &&
            (flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
            memory_type_index = i;
            break;
        }
    }
    
    // Fall back to any device local
    if (memory_type_index == UINT32_MAX) {
        for (uint32_t i = 0; i < ctx->memory_props.memoryTypeCount; i++) {
            if (ctx->memory_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                memory_type_index = i;
                break;
            }
        }
    }
    
    if (memory_type_index == UINT32_MAX) {
        printf("[Vulkan] No suitable memory type found\n");
        return NULL;
    }
    
    VkMemoryAllocateInfo alloc_info = {0};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = size;
    alloc_info.memoryTypeIndex = memory_type_index;
    
    VkDeviceMemory memory;
    VkResult result = vkAllocateMemory(ctx->device, &alloc_info, NULL, &memory);
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to allocate memory: %d\n", result);
        return NULL;
    }
    
    return (void*)memory;
}

void Vulkan_Free(GPUBackend* backend, void* ptr) {
    if (!backend || !backend->device || !ptr) return;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    vkFreeMemory(ctx->device, (VkDeviceMemory)ptr, NULL);
}

// ============================================================================
// TENSOR UPLOAD/DOWNLOAD
// ============================================================================

GPUStatus Vulkan_Upload(GPUBackend* backend, GPUTensor* tensor, const void* data) {
    if (!backend || !tensor || !data) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    // For simplicity, create a staging buffer and copy
    // In production, would use dedicated staging memory
    
    VkBufferCreateInfo buffer_info = {0};
    buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buffer_info.size = tensor->size;
    buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    
    VkBuffer buffer;
    VkResult result = vkCreateBuffer(ctx->device, &buffer_info, NULL, &buffer);
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to create buffer: %d\n", result);
        return GPU_ERROR;
    }
    
    // Get memory requirements
    VkMemoryRequirements mem_reqs;
    vkGetBufferMemoryRequirements(ctx->device, buffer, &mem_reqs);
    
    // Find memory type
    uint32_t memory_type_index = UINT32_MAX;
    for (uint32_t i = 0; i < ctx->memory_props.memoryTypeCount; i++) {
        if (mem_reqs.memoryTypeBits & (1 << i)) {
            VkMemoryPropertyFlags flags = ctx->memory_props.memoryTypes[i].propertyFlags;
            if (flags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                memory_type_index = i;
                break;
            }
        }
    }
    
    if (memory_type_index == UINT32_MAX) {
        vkDestroyBuffer(ctx->device, buffer, NULL);
        return GPU_ERROR_OUT_OF_MEMORY;
    }
    
    // Allocate memory
    VkMemoryAllocateInfo alloc_info = {0};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_reqs.size;
    alloc_info.memoryTypeIndex = memory_type_index;
    
    VkDeviceMemory memory;
    result = vkAllocateMemory(ctx->device, &alloc_info, NULL, &memory);
    if (result != VK_SUCCESS) {
        vkDestroyBuffer(ctx->device, buffer, NULL);
        return GPU_ERROR_OUT_OF_MEMORY;
    }
    
    // Bind memory
    result = vkBindBufferMemory(ctx->device, buffer, memory, 0);
    if (result != VK_SUCCESS) {
        vkFreeMemory(ctx->device, memory, NULL);
        vkDestroyBuffer(ctx->device, buffer, NULL);
        return GPU_ERROR;
    }
    
    // Create staging buffer for upload
    VkBufferCreateInfo staging_info = {0};
    staging_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    staging_info.size = tensor->size;
    staging_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    staging_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    
    VkBuffer staging_buffer;
    result = vkCreateBuffer(ctx->device, &staging_info, NULL, &staging_buffer);
    if (result != VK_SUCCESS) {
        vkFreeMemory(ctx->device, memory, NULL);
        vkDestroyBuffer(ctx->device, buffer, NULL);
        return GPU_ERROR;
    }
    
    VkMemoryRequirements staging_reqs;
    vkGetBufferMemoryRequirements(ctx->device, staging_buffer, &staging_reqs);
    
    // Find host-visible memory
    uint32_t staging_type = UINT32_MAX;
    for (uint32_t i = 0; i < ctx->memory_props.memoryTypeCount; i++) {
        if (staging_reqs.memoryTypeBits & (1 << i)) {
            VkMemoryPropertyFlags flags = ctx->memory_props.memoryTypes[i].propertyFlags;
            if ((flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
                (flags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
                staging_type = i;
                break;
            }
        }
    }
    
    if (staging_type == UINT32_MAX) {
        vkDestroyBuffer(ctx->device, staging_buffer, NULL);
        vkFreeMemory(ctx->device, memory, NULL);
        vkDestroyBuffer(ctx->device, buffer, NULL);
        return GPU_ERROR_OUT_OF_MEMORY;
    }
    
    VkMemoryAllocateInfo staging_alloc = {0};
    staging_alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    staging_alloc.allocationSize = staging_reqs.size;
    staging_alloc.memoryTypeIndex = staging_type;
    
    VkDeviceMemory staging_memory;
    result = vkAllocateMemory(ctx->device, &staging_alloc, NULL, &staging_memory);
    if (result != VK_SUCCESS) {
        vkDestroyBuffer(ctx->device, staging_buffer, NULL);
        vkFreeMemory(ctx->device, memory, NULL);
        vkDestroyBuffer(ctx->device, buffer, NULL);
        return GPU_ERROR_OUT_OF_MEMORY;
    }
    
    result = vkBindBufferMemory(ctx->device, staging_buffer, staging_memory, 0);
    if (result != VK_SUCCESS) {
        vkFreeMemory(ctx->device, staging_memory, NULL);
        vkDestroyBuffer(ctx->device, staging_buffer, NULL);
        vkFreeMemory(ctx->device, memory, NULL);
        vkDestroyBuffer(ctx->device, buffer, NULL);
        return GPU_ERROR;
    }
    
    // Map and copy data
    void* mapped;
    result = vkMapMemory(ctx->device, staging_memory, 0, tensor->size, 0, &mapped);
    if (result != VK_SUCCESS) {
        vkFreeMemory(ctx->device, staging_memory, NULL);
        vkDestroyBuffer(ctx->device, staging_buffer, NULL);
        vkFreeMemory(ctx->device, memory, NULL);
        vkDestroyBuffer(ctx->device, buffer, NULL);
        return GPU_ERROR;
    }
    
    memcpy(mapped, data, tensor->size);
    vkUnmapMemory(ctx->device, staging_memory);
    
    // Record copy command
    VkCommandBufferBeginInfo begin_info = {0};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    
    vkBeginCommandBuffer(ctx->command_buffer, &begin_info);
    
    VkBufferCopy copy_region = {0};
    copy_region.size = tensor->size;
    vkCmdCopyBuffer(ctx->command_buffer, staging_buffer, buffer, 1, &copy_region);
    
    vkEndCommandBuffer(ctx->command_buffer);
    
    // Submit
    VkSubmitInfo submit_info = {0};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &ctx->command_buffer;
    
    vkQueueSubmit(ctx->compute_queue, 1, &submit_info, ctx->fence);
    vkWaitForFences(ctx->device, 1, &ctx->fence, VK_TRUE, UINT64_MAX);
    vkResetFences(ctx->device, 1, &ctx->fence);
    
    // Cleanup staging
    vkFreeMemory(ctx->device, staging_memory, NULL);
    vkDestroyBuffer(ctx->device, staging_buffer, NULL);
    
    // Store in tensor
    tensor->device_data = (void*)buffer;
    tensor->staging_data = (void*)memory;
    tensor->is_on_gpu = 1;
    
    return GPU_SUCCESS;
}

GPUStatus Vulkan_Download(GPUBackend* backend, GPUTensor* tensor, void* data) {
    if (!backend || !tensor || !data) return GPU_ERROR_NULL_POINTER;
    if (!tensor->is_on_gpu) return GPU_ERROR;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    VkBuffer buffer = (VkBuffer)tensor->device_data;
    VkDeviceMemory memory = (VkDeviceMemory)tensor->staging_data;
    
    // Create staging buffer for download
    VkBufferCreateInfo staging_info = {0};
    staging_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    staging_info.size = tensor->size;
    staging_info.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    staging_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    
    VkBuffer staging_buffer;
    VkResult result = vkCreateBuffer(ctx->device, &staging_info, NULL, &staging_buffer);
    if (result != VK_SUCCESS) return GPU_ERROR;
    
    VkMemoryRequirements staging_reqs;
    vkGetBufferMemoryRequirements(ctx->device, staging_buffer, &staging_reqs);
    
    uint32_t staging_type = UINT32_MAX;
    for (uint32_t i = 0; i < ctx->memory_props.memoryTypeCount; i++) {
        if (staging_reqs.memoryTypeBits & (1 << i)) {
            VkMemoryPropertyFlags flags = ctx->memory_props.memoryTypes[i].propertyFlags;
            if ((flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
                (flags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
                staging_type = i;
                break;
            }
        }
    }
    
    if (staging_type == UINT32_MAX) {
        vkDestroyBuffer(ctx->device, staging_buffer, NULL);
        return GPU_ERROR;
    }
    
    VkMemoryAllocateInfo staging_alloc = {0};
    staging_alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    staging_alloc.allocationSize = staging_reqs.size;
    staging_alloc.memoryTypeIndex = staging_type;
    
    VkDeviceMemory staging_memory;
    result = vkAllocateMemory(ctx->device, &staging_alloc, NULL, &staging_memory);
    if (result != VK_SUCCESS) {
        vkDestroyBuffer(ctx->device, staging_buffer, NULL);
        return GPU_ERROR;
    }
    
    vkBindBufferMemory(ctx->device, staging_buffer, staging_memory, 0);
    
    // Record copy command
    VkCommandBufferBeginInfo begin_info = {0};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    
    vkBeginCommandBuffer(ctx->command_buffer, &begin_info);
    
    VkBufferCopy copy_region = {0};
    copy_region.size = tensor->size;
    vkCmdCopyBuffer(ctx->command_buffer, buffer, staging_buffer, 1, &copy_region);
    
    vkEndCommandBuffer(ctx->command_buffer);
    
    VkSubmitInfo submit_info = {0};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &ctx->command_buffer;
    
    vkQueueSubmit(ctx->compute_queue, 1, &submit_info, ctx->fence);
    vkWaitForFences(ctx->device, 1, &ctx->fence, VK_TRUE, UINT64_MAX);
    vkResetFences(ctx->device, 1, &ctx->fence);
    
    // Map and copy data
    void* mapped;
    vkMapMemory(ctx->device, staging_memory, 0, tensor->size, 0, &mapped);
    memcpy(data, mapped, tensor->size);
    vkUnmapMemory(ctx->device, staging_memory);
    
    // Cleanup
    vkFreeMemory(ctx->device, staging_memory, NULL);
    vkDestroyBuffer(ctx->device, staging_buffer, NULL);
    
    return GPU_SUCCESS;
}

// ============================================================================
// SYNCHRONIZATION
// ============================================================================

GPUStatus Vulkan_Synchronize(GPUBackend* backend) {
    if (!backend || !backend->device) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    vkDeviceWaitIdle(ctx->device);
    return GPU_SUCCESS;
}