// vulkan_kernels.cpp - Vulkan Compute Kernel Implementation
// Phase 8.3 G12: Vulkan Compute Backend - Kernel Dispatch

#define VK_USE_PLATFORM_WIN32_KHR
#define NOMINMAX

#include "vulkan_backend.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ============================================================================
// SHADER LOADING
// ============================================================================

static GPUStatus LoadSPIRV(GPUBackend* backend, const char* filename, VkShaderModule* module) {
    if (!backend || !filename || !module) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    // Open file
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("[Vulkan] Failed to open shader: %s\n", filename);
        return GPU_ERROR;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Read SPIR-V code
    uint32_t* code = (uint32_t*)malloc(size);
    if (!code) {
        fclose(file);
        return GPU_ERROR_OUT_OF_MEMORY;
    }
    
    fread(code, 1, size, file);
    fclose(file);
    
    // Create shader module
    VkShaderModuleCreateInfo create_info = {0};
    create_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    create_info.codeSize = size;
    create_info.pCode = code;
    
    VkResult result = vkCreateShaderModule(ctx->device, &create_info, NULL, module);
    free(code);
    
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to create shader module: %d\n", result);
        return GPU_ERROR_SHADER_COMPILE;
    }
    
    return GPU_SUCCESS;
}

static GPUStatus EnsureShaderLoaded(GPUBackend* backend, VkShaderModule* shader, const char* filename) {
    if (*shader) return GPU_SUCCESS;  // Already loaded
    return LoadSPIRV(backend, filename, shader);
}

// ============================================================================
// PIPELINE CREATION
// ============================================================================

typedef struct {
    VkPipeline pipeline;
    VkPipelineLayout layout;
    VkDescriptorSetLayout descriptor_layout;
    VkDescriptorSet descriptor_set;
} VulkanPipeline;

static GPUStatus CreateComputePipeline(GPUBackend* backend, VkShaderModule shader,
                                       uint32_t push_constant_size,
                                       VulkanPipeline* pipeline) {
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    // Create descriptor set layout
    VkDescriptorSetLayoutBinding bindings[4] = {0};
    for (int i = 0; i < 4; i++) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    
    VkDescriptorSetLayoutCreateInfo layout_info = {0};
    layout_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layout_info.bindingCount = 4;
    layout_info.pBindings = bindings;
    
    VkResult result = vkCreateDescriptorSetLayout(ctx->device, &layout_info, NULL,
                                                   &pipeline->descriptor_layout);
    if (result != VK_SUCCESS) return GPU_ERROR;
    
    // Create pipeline layout
    VkPushConstantRange push_constant = {0};
    push_constant.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    push_constant.offset = 0;
    push_constant.size = push_constant_size;
    
    VkPipelineLayoutCreateInfo pipeline_layout_info = {0};
    pipeline_layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipeline_layout_info.setLayoutCount = 1;
    pipeline_layout_info.pSetLayouts = &pipeline->descriptor_layout;
    pipeline_layout_info.pushConstantRangeCount = push_constant_size > 0 ? 1 : 0;
    pipeline_layout_info.pPushConstantRanges = push_constant_size > 0 ? &push_constant : NULL;
    
    result = vkCreatePipelineLayout(ctx->device, &pipeline_layout_info, NULL,
                                      &pipeline->layout);
    if (result != VK_SUCCESS) {
        vkDestroyDescriptorSetLayout(ctx->device, pipeline->descriptor_layout, NULL);
        return GPU_ERROR;
    }
    
    // Create compute pipeline
    VkPipelineShaderStageCreateInfo stage_info = {0};
    stage_info.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage_info.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage_info.module = shader;
    stage_info.pName = "main";
    
    VkComputePipelineCreateInfo pipeline_info = {0};
    pipeline_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipeline_info.stage = stage_info;
    pipeline_info.layout = pipeline->layout;
    
    result = vkCreateComputePipelines(ctx->device, ctx->pipeline_cache, 1,
                                       &pipeline_info, NULL, &pipeline->pipeline);
    if (result != VK_SUCCESS) {
        vkDestroyPipelineLayout(ctx->device, pipeline->layout, NULL);
        vkDestroyDescriptorSetLayout(ctx->device, pipeline->descriptor_layout, NULL);
        return GPU_ERROR;
    }
    
    return GPU_SUCCESS;
}

static void DestroyPipeline(GPUBackend* backend, VulkanPipeline* pipeline) {
    if (!backend || !pipeline) return;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    if (pipeline->pipeline) vkDestroyPipeline(ctx->device, pipeline->pipeline, NULL);
    if (pipeline->layout) vkDestroyPipelineLayout(ctx->device, pipeline->layout, NULL);
    if (pipeline->descriptor_layout) vkDestroyDescriptorSetLayout(ctx->device, pipeline->descriptor_layout, NULL);
}

// ============================================================================
// DESCRIPTOR SET MANAGEMENT
// ============================================================================

static GPUStatus AllocateDescriptorSet(GPUBackend* backend, VulkanPipeline* pipeline,
                                        VkBuffer* buffers, uint32_t buffer_count) {
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    // Ensure descriptor pool exists
    if (!ctx->descriptor_pool) {
        VkDescriptorPoolSize pool_size = {0};
        pool_size.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        pool_size.descriptorCount = 1024;  // Reserve space
        
        VkDescriptorPoolCreateInfo pool_info = {0};
        pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        pool_info.maxSets = 256;
        pool_info.poolSizeCount = 1;
        pool_info.pPoolSizes = &pool_size;
        
        VkResult result = vkCreateDescriptorPool(ctx->device, &pool_info, NULL,
                                                  &ctx->descriptor_pool);
        if (result != VK_SUCCESS) return GPU_ERROR;
    }
    
    // Allocate descriptor set
    VkDescriptorSetAllocateInfo alloc_info = {0};
    alloc_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    alloc_info.descriptorPool = ctx->descriptor_pool;
    alloc_info.descriptorSetCount = 1;
    alloc_info.pSetLayouts = &pipeline->descriptor_layout;
    
    VkResult result = vkAllocateDescriptorSets(ctx->device, &alloc_info,
                                                &pipeline->descriptor_set);
    if (result != VK_SUCCESS) return GPU_ERROR;
    
    // Update descriptor set with buffers
    VkWriteDescriptorSet writes[4] = {0};
    VkDescriptorBufferInfo buffer_infos[4] = {0};
    
    for (uint32_t i = 0; i < buffer_count && i < 4; i++) {
        buffer_infos[i].buffer = buffers[i];
        buffer_infos[i].offset = 0;
        buffer_infos[i].range = VK_WHOLE_SIZE;
        
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = pipeline->descriptor_set;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &buffer_infos[i];
    }
    
    vkUpdateDescriptorSets(ctx->device, buffer_count, writes, 0, NULL);
    
    return GPU_SUCCESS;
}

// ============================================================================
// KERNEL DISPATCH
// ============================================================================

static GPUStatus DispatchKernel(GPUBackend* backend, VulkanPipeline* pipeline,
                                 uint32_t group_count_x, uint32_t group_count_y,
                                 uint32_t group_count_z, void* push_constants,
                                 uint32_t push_constant_size) {
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    // Begin command buffer
    VkCommandBufferBeginInfo begin_info = {0};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    
    vkBeginCommandBuffer(ctx->command_buffer, &begin_info);
    
    // Bind pipeline
    vkCmdBindPipeline(ctx->command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline->pipeline);
    
    // Bind descriptor set
    vkCmdBindDescriptorSets(ctx->command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE,
                            pipeline->layout, 0, 1, &pipeline->descriptor_set,
                            0, NULL);
    
    // Push constants if provided
    if (push_constants && push_constant_size > 0) {
        vkCmdPushConstants(ctx->command_buffer, pipeline->layout,
                          VK_SHADER_STAGE_COMPUTE_BIT, 0, push_constant_size,
                          push_constants);
    }
    
    // Dispatch
    vkCmdDispatch(ctx->command_buffer, group_count_x, group_count_y, group_count_z);
    
    // End command buffer
    vkEndCommandBuffer(ctx->command_buffer);
    
    // Submit
    VkSubmitInfo submit_info = {0};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &ctx->command_buffer;
    
    VkResult result = vkQueueSubmit(ctx->compute_queue, 1, &submit_info, ctx->fence);
    if (result != VK_SUCCESS) return GPU_ERROR_KERNEL_LAUNCH;
    
    // Wait for completion
    vkWaitForFences(ctx->device, 1, &ctx->fence, VK_TRUE, UINT64_MAX);
    vkResetFences(ctx->device, 1, &ctx->fence);
    
    return GPU_SUCCESS;
}

// ============================================================================
// KERNEL IMPLEMENTATIONS
// ============================================================================

GPUStatus Vulkan_RMSNorm(GPUBackend* backend, GPUTensor* output, const GPUTensor* input,
                          const GPUTensor* weight, float epsilon, uint32_t n_elements) {
    if (!backend || !output || !input || !weight) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    // Ensure shader is loaded
    GPUStatus status = EnsureShaderLoaded(backend, &ctx->rmsnorm_shader,
                                           "src/gpu/vulkan/shaders/rmsnorm.spv");
    if (status != GPU_SUCCESS) return status;
    
    // Create pipeline
    VulkanPipeline pipeline = {0};
    struct {
        uint32_t n_elements;
        float epsilon;
    } push_constants;
    push_constants.n_elements = n_elements;
    push_constants.epsilon = epsilon;
    
    status = CreateComputePipeline(backend, ctx->rmsnorm_shader, sizeof(push_constants), &pipeline);
    if (status != GPU_SUCCESS) return status;
    
    // Allocate descriptor set
    VkBuffer buffers[] = {
        (VkBuffer)input->device_data,
        (VkBuffer)weight->device_data,
        (VkBuffer)output->device_data
    };
    status = AllocateDescriptorSet(backend, &pipeline, buffers, 3);
    if (status != GPU_SUCCESS) {
        DestroyPipeline(backend, &pipeline);
        return status;
    }
    
    // Dispatch
    uint32_t group_count = (n_elements + 255) / 256;
    status = DispatchKernel(backend, &pipeline, group_count, 1, 1,
                             &push_constants, sizeof(push_constants));
    
    DestroyPipeline(backend, &pipeline);
    return status;
}

GPUStatus Vulkan_RoPE(GPUBackend* backend, GPUTensor* query, GPUTensor* key,
                       uint32_t n_heads, uint32_t head_dim, uint32_t position, float freq_base) {
    if (!backend || !query || !key) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    GPUStatus status = EnsureShaderLoaded(backend, &ctx->rope_shader,
                                           "src/gpu/vulkan/shaders/rope.spv");
    if (status != GPU_SUCCESS) return status;
    
    VulkanPipeline pipeline = {0};
    struct {
        uint32_t n_heads;
        uint32_t head_dim;
        uint32_t position;
        float freq_base;
    } push_constants;
    push_constants.n_heads = n_heads;
    push_constants.head_dim = head_dim;
    push_constants.position = position;
    push_constants.freq_base = freq_base;
    
    status = CreateComputePipeline(backend, ctx->rope_shader, sizeof(push_constants), &pipeline);
    if (status != GPU_SUCCESS) return status;
    
    VkBuffer buffers[] = {
        (VkBuffer)query->device_data,
        (VkBuffer)key->device_data
    };
    status = AllocateDescriptorSet(backend, &pipeline, buffers, 2);
    if (status != GPU_SUCCESS) {
        DestroyPipeline(backend, &pipeline);
        return status;
    }
    
    uint32_t total_dims = n_heads * head_dim / 2;
    uint32_t group_count = (total_dims + 63) / 64;
    status = DispatchKernel(backend, &pipeline, group_count, 1, 1,
                             &push_constants, sizeof(push_constants));
    
    DestroyPipeline(backend, &pipeline);
    return status;
}

GPUStatus Vulkan_Attention(GPUBackend* backend, GPUTensor* output,
                            const GPUTensor* query, const GPUTensor* key, const GPUTensor* value,
                            uint32_t n_heads, uint32_t seq_len, uint32_t head_dim) {
    if (!backend || !output || !query || !key || !value) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    GPUStatus status = EnsureShaderLoaded(backend, &ctx->attention_shader,
                                           "src/gpu/vulkan/shaders/attention.spv");
    if (status != GPU_SUCCESS) return status;
    
    VulkanPipeline pipeline = {0};
    struct {
        uint32_t n_heads;
        uint32_t seq_len;
        uint32_t head_dim;
    } push_constants;
    push_constants.n_heads = n_heads;
    push_constants.seq_len = seq_len;
    push_constants.head_dim = head_dim;
    
    status = CreateComputePipeline(backend, ctx->attention_shader, sizeof(push_constants), &pipeline);
    if (status != GPU_SUCCESS) return status;
    
    VkBuffer buffers[] = {
        (VkBuffer)query->device_data,
        (VkBuffer)key->device_data,
        (VkBuffer)value->device_data,
        (VkBuffer)output->device_data
    };
    status = AllocateDescriptorSet(backend, &pipeline, buffers, 4);
    if (status != GPU_SUCCESS) {
        DestroyPipeline(backend, &pipeline);
        return status;
    }
    
    uint32_t group_count = n_heads * seq_len;
    status = DispatchKernel(backend, &pipeline, group_count, 1, 1,
                             &push_constants, sizeof(push_constants));
    
    DestroyPipeline(backend, &pipeline);
    return status;
}

GPUStatus Vulkan_MatMul(GPUBackend* backend, GPUTensor* output,
                          const GPUTensor* a, const GPUTensor* b,
                          uint32_t m, uint32_t n, uint32_t k, GPUDataType compute_type) {
    if (!backend || !output || !a || !b) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    GPUStatus status = EnsureShaderLoaded(backend, &ctx->matmul_shader,
                                           "src/gpu/vulkan/shaders/matmul.spv");
    if (status != GPU_SUCCESS) return status;
    
    VulkanPipeline pipeline = {0};
    struct {
        uint32_t m;
        uint32_t n;
        uint32_t k;
    } push_constants;
    push_constants.m = m;
    push_constants.n = n;
    push_constants.k = k;
    
    status = CreateComputePipeline(backend, ctx->matmul_shader, sizeof(push_constants), &pipeline);
    if (status != GPU_SUCCESS) return status;
    
    VkBuffer buffers[] = {
        (VkBuffer)a->device_data,
        (VkBuffer)b->device_data,
        (VkBuffer)output->device_data
    };
    status = AllocateDescriptorSet(backend, &pipeline, buffers, 3);
    if (status != GPU_SUCCESS) {
        DestroyPipeline(backend, &pipeline);
        return status;
    }
    
    uint32_t group_count_x = (n + 15) / 16;
    uint32_t group_count_y = (m + 15) / 16;
    status = DispatchKernel(backend, &pipeline, group_count_x, group_count_y, 1,
                             &push_constants, sizeof(push_constants));
    
    DestroyPipeline(backend, &pipeline);
    return status;
}

GPUStatus Vulkan_Softmax(GPUBackend* backend, GPUTensor* output, const GPUTensor* input,
                          uint32_t n_elements) {
    if (!backend || !output || !input) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    GPUStatus status = EnsureShaderLoaded(backend, &ctx->softmax_shader,
                                           "src/gpu/vulkan/shaders/softmax.spv");
    if (status != GPU_SUCCESS) return status;
    
    VulkanPipeline pipeline = {0};
    struct {
        uint32_t n_elements;
    } push_constants;
    push_constants.n_elements = n_elements;
    
    status = CreateComputePipeline(backend, ctx->softmax_shader, sizeof(push_constants), &pipeline);
    if (status != GPU_SUCCESS) return status;
    
    VkBuffer buffers[] = {
        (VkBuffer)input->device_data,
        (VkBuffer)output->device_data
    };
    status = AllocateDescriptorSet(backend, &pipeline, buffers, 2);
    if (status != GPU_SUCCESS) {
        DestroyPipeline(backend, &pipeline);
        return status;
    }
    
    uint32_t group_count = (n_elements + 255) / 256;
    status = DispatchKernel(backend, &pipeline, group_count, 1, 1,
                             &push_constants, sizeof(push_constants));
    
    DestroyPipeline(backend, &pipeline);
    return status;
}

GPUStatus Vulkan_SwiGLU(GPUBackend* backend, GPUTensor* output,
                          const GPUTensor* gate, const GPUTensor* up, uint32_t n_elements) {
    if (!backend || !output || !gate || !up) return GPU_ERROR_NULL_POINTER;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    
    GPUStatus status = EnsureShaderLoaded(backend, &ctx->swiglu_shader,
                                           "src/gpu/vulkan/shaders/swiglu.spv");
    if (status != GPU_SUCCESS) return status;
    
    VulkanPipeline pipeline = {0};
    struct {
        uint32_t n_elements;
    } push_constants;
    push_constants.n_elements = n_elements;
    
    status = CreateComputePipeline(backend, ctx->swiglu_shader, sizeof(push_constants), &pipeline);
    if (status != GPU_SUCCESS) return status;
    
    VkBuffer buffers[] = {
        (VkBuffer)gate->device_data,
        (VkBuffer)up->device_data,
        (VkBuffer)output->device_data
    };
    status = AllocateDescriptorSet(backend, &pipeline, buffers, 3);
    if (status != GPU_SUCCESS) {
        DestroyPipeline(backend, &pipeline);
        return status;
    }
    
    uint32_t group_count = (n_elements + 255) / 256;
    status = DispatchKernel(backend, &pipeline, group_count, 1, 1,
                             &push_constants, sizeof(push_constants));
    
    DestroyPipeline(backend, &pipeline);
    return status;
}

GPUStatus Vulkan_Add(GPUBackend* backend, GPUTensor* output,
                     const GPUTensor* a, const GPUTensor* b, uint32_t n_elements) {
    if (!backend || !output || !a || !b) return GPU_ERROR_NULL_POINTER;
    
    // Simple element-wise add - could use compute shader
    // For now, fallback to CPU
    return GPU_ERROR_UNSUPPORTED;
}