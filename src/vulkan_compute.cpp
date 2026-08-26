#ifdef _WIN32
#include <windows.h>
#endif

#include "vulkan_compute.h"

#if RAWR_VULKAN_AVAILABLE

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace CPUInference {

VulkanCompute::VulkanCompute()
    : instance_(nullptr)
    , physical_device_(nullptr)
    , device_(nullptr)
    , compute_queue_(nullptr)
    , command_pool_(nullptr)
    , descriptor_pool_(nullptr)
    , matmul_descriptor_set_layout_(nullptr)
    , matmul_descriptor_pool_(nullptr)
    , kv_cache_num_layers_(0)
    , kv_cache_max_seq_len_(0)
    , kv_cache_head_dim_(0)
    , kv_cache_allocated_(false)
    , staging_buffer_(nullptr)
    , staging_memory_(nullptr)
    , staging_buffer_size_(0)
{
    std::memset(&device_info_, 0, sizeof(VulkanDeviceInfo));
}

VulkanCompute::~VulkanCompute() {
    Cleanup();
}

bool VulkanCompute::Initialize() {
    // Check if Vulkan is available at runtime
    #ifdef _WIN32
    HMODULE vulkanDll = LoadLibraryA("vulkan-1.dll");
    if (!vulkanDll) {
        printf("[VulkanCompute] Vulkan runtime not available (vulkan-1.dll not found)\n");
        return false;
    }
    FreeLibrary(vulkanDll);
    #endif
    
    if (!CreateInstance()) return false;
    if (!SelectPhysicalDevice()) return false;
    if (!CreateLogicalDevice()) return false;
    if (!CreateCommandPool()) return false;
    return true;
}

void VulkanCompute::Cleanup() {
    // Proper cleanup of Vulkan resources
    if (device_) {
        vkDeviceWaitIdle(device_);
        
        // Free GEMV pipeline
        if (gemv_pipeline_) {
            vkDestroyPipeline(device_, gemv_pipeline_, nullptr);
            gemv_pipeline_ = nullptr;
        }
        if (gemv_pipeline_layout_) {
            vkDestroyPipelineLayout(device_, gemv_pipeline_layout_, nullptr);
            gemv_pipeline_layout_ = nullptr;
        }
        if (gemv_ds_layout_) {
            vkDestroyDescriptorSetLayout(device_, gemv_ds_layout_, nullptr);
            gemv_ds_layout_ = nullptr;
        }
        if (gemv_desc_pool_) {
            vkDestroyDescriptorPool(device_, gemv_desc_pool_, nullptr);
            gemv_desc_pool_ = nullptr;
        }
        gemv_pipeline_created_ = false;
        
        // Free staging buffer
        if (staging_buffer_) {
            vkDestroyBuffer(device_, staging_buffer_, nullptr);
            staging_buffer_ = nullptr;
        }
        if (staging_memory_) {
            vkFreeMemory(device_, staging_memory_, nullptr);
            staging_memory_ = nullptr;
        }
        
        // Free descriptor pools
        if (matmul_descriptor_pool_) {
            vkDestroyDescriptorPool(device_, matmul_descriptor_pool_, nullptr);
            matmul_descriptor_pool_ = nullptr;
        }
        if (descriptor_pool_) {
            vkDestroyDescriptorPool(device_, descriptor_pool_, nullptr);
            descriptor_pool_ = nullptr;
        }
        
        // Free descriptor set layouts
        if (matmul_descriptor_set_layout_) {
            vkDestroyDescriptorSetLayout(device_, matmul_descriptor_set_layout_, nullptr);
            matmul_descriptor_set_layout_ = nullptr;
        }
        
        // Free command pool
        if (command_pool_) {
            vkDestroyCommandPool(device_, command_pool_, nullptr);
            command_pool_ = nullptr;
        }
        
        // Destroy device
        vkDestroyDevice(device_, nullptr);
        device_ = nullptr;
    }
    
    // Destroy instance
    if (instance_) {
        vkDestroyInstance(instance_, nullptr);
        instance_ = nullptr;
    }
    
    physical_device_ = nullptr;
    compute_queue_ = nullptr;
    kv_cache_allocated_ = false;
}

bool VulkanCompute::LoadShader(const std::string& name, const std::string& spirv_path) {
    (void)name; (void)spirv_path;
    return false;
}

bool VulkanCompute::CreateComputePipeline(const std::string& shader_name) {
    (void)shader_name;
    return false;
}

VulkanTensor VulkanCompute::TransferGGUFTensor(const std::string& tensor_name,
                                               const void* data_ptr,
                                               size_t size_bytes,
                                               uint32_t usage) {
    (void)tensor_name; (void)data_ptr; (void)size_bytes; (void)usage;
    return VulkanTensor{};
}

void VulkanCompute::ReleaseTensors() {
}

bool VulkanCompute::EnsureMatMulPipeline(const std::string& spirv_path) {
    (void)spirv_path;
    return false;
}

bool VulkanCompute::DispatchMatMul(uint32_t input_a_idx,
                                   uint32_t input_b_idx,
                                   uint32_t output_idx,
                                   uint32_t M,
                                   uint32_t K,
                                   uint32_t N) {
    (void)input_a_idx; (void)input_b_idx; (void)output_idx;
    (void)M; (void)K; (void)N;
    return false;
}

bool VulkanCompute::DispatchMatMulAsync(uint32_t input_a_idx,
                                        uint32_t input_b_idx,
                                        uint32_t output_idx,
                                        uint32_t M,
                                        uint32_t K,
                                        uint32_t N) {
    (void)input_a_idx; (void)input_b_idx; (void)output_idx;
    (void)M; (void)K; (void)N;
    return false;
}

// ============================================================================
// DispatchGEMV: GPU-accelerated matrix-vector multiply for transformer inference
// Uploads FP32 weights + input, dispatches compute shader, downloads result.
// Returns true on success, false on any failure (caller falls back to CPU).
// ============================================================================
bool VulkanCompute::DispatchGEMV(const float* weights, const float* input, float* output,
                                 uint32_t rows, uint32_t cols) {
    if (!device_ || !compute_queue_ || !command_pool_) {
        printf("[DispatchGEMV] FAIL: device/queue/pool null\n");
        return false;
    }

    // --- 1. Create GEMV pipeline on first use ---
    if (!gemv_pipeline_created_) {
        // Load SPIR-V from disk (compiled at build time)
        std::string spirvPath = "src/backend/gemv.spv";
        std::ifstream file(spirvPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            // Try relative to working directory
            spirvPath = "gemv.spv";
            file.open(spirvPath, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                printf("[DispatchGEMV] FAIL: cannot open gemv.spv\n");
                return false;
            }
        }
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<uint32_t> spirvCode(fileSize / sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(spirvCode.data()), fileSize);
        file.close();
        printf("[DispatchGEMV] Loaded SPIR-V: %zu dwords from %s\n", spirvCode.size(), spirvPath.c_str());

        // Create shader module
        VkShaderModuleCreateInfo shaderInfo{};
        shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
        shaderInfo.codeSize = spirvCode.size() * sizeof(uint32_t);
        shaderInfo.pCode = spirvCode.data();
        VkShaderModule shaderModule = nullptr;
        if (vkCreateShaderModule(device_, &shaderInfo, nullptr, &shaderModule) != VK_SUCCESS) {
            printf("[DispatchGEMV] FAIL: vkCreateShaderModule\n");
            return false;
        }
        printf("[DispatchGEMV] Shader module created OK\n");

        // Descriptor set layout: 3 storage buffers (weight, input, output)
        VkDescriptorSetLayoutBinding bindings[3] = {};
        for (int i = 0; i < 3; ++i) {
            bindings[i].binding = i;
            bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            bindings[i].descriptorCount = 1;
            bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        }
        VkDescriptorSetLayoutCreateInfo dslInfo{};
        dslInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
        dslInfo.bindingCount = 3;
        dslInfo.pBindings = bindings;
        if (vkCreateDescriptorSetLayout(device_, &dslInfo, nullptr, &gemv_ds_layout_) != VK_SUCCESS) {
            printf("[DispatchGEMV] FAIL: vkCreateDescriptorSetLayout\n");
            vkDestroyShaderModule(device_, shaderModule, nullptr);
            return false;
        }
        printf("[DispatchGEMV] Descriptor set layout created OK\n");

        // Push constants: rows, cols
        VkPushConstantRange pcRange{};
        pcRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        pcRange.offset = 0;
        pcRange.size = sizeof(uint32_t) * 2;

        VkPipelineLayoutCreateInfo plInfo{};
        plInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
        plInfo.setLayoutCount = 1;
        plInfo.pSetLayouts = &gemv_ds_layout_;
        plInfo.pushConstantRangeCount = 1;
        plInfo.pPushConstantRanges = &pcRange;
        if (vkCreatePipelineLayout(device_, &plInfo, nullptr, &gemv_pipeline_layout_) != VK_SUCCESS) {
            printf("[DispatchGEMV] FAIL: vkCreatePipelineLayout\n");
            vkDestroyDescriptorSetLayout(device_, gemv_ds_layout_, nullptr);
            gemv_ds_layout_ = nullptr;
            vkDestroyShaderModule(device_, shaderModule, nullptr);
            return false;
        }
        printf("[DispatchGEMV] Pipeline layout created OK\n");

        VkPipelineShaderStageCreateInfo stageInfo{};
        stageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
        stageInfo.module = shaderModule;
        stageInfo.pName = "main";

        VkComputePipelineCreateInfo pipelineInfo{};
        pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
        pipelineInfo.layout = gemv_pipeline_layout_;
        pipelineInfo.stage = stageInfo;

        VkResult result = vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &gemv_pipeline_);
        vkDestroyShaderModule(device_, shaderModule, nullptr);
        if (result != VK_SUCCESS) {
            printf("[DispatchGEMV] FAIL: vkCreateComputePipelines result=%d\n", (int)result);
            vkDestroyPipelineLayout(device_, gemv_pipeline_layout_, nullptr);
            gemv_pipeline_layout_ = nullptr;
            vkDestroyDescriptorSetLayout(device_, gemv_ds_layout_, nullptr);
            gemv_ds_layout_ = nullptr;
            return false;
        }
        printf("[DispatchGEMV] Compute pipeline created OK\n");

        // Descriptor pool
        VkDescriptorPoolSize poolSize{};
        poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        poolSize.descriptorCount = 3;
        VkDescriptorPoolCreateInfo dpInfo{};
        dpInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        dpInfo.maxSets = 1;
        dpInfo.poolSizeCount = 1;
        dpInfo.pPoolSizes = &poolSize;
        if (vkCreateDescriptorPool(device_, &dpInfo, nullptr, &gemv_desc_pool_) != VK_SUCCESS) {
            printf("[DispatchGEMV] FAIL: vkCreateDescriptorPool\n");
            vkDestroyPipeline(device_, gemv_pipeline_, nullptr);
            gemv_pipeline_ = nullptr;
            vkDestroyPipelineLayout(device_, gemv_pipeline_layout_, nullptr);
            gemv_pipeline_layout_ = nullptr;
            vkDestroyDescriptorSetLayout(device_, gemv_ds_layout_, nullptr);
            gemv_ds_layout_ = nullptr;
            return false;
        }
        printf("[DispatchGEMV] Descriptor pool created OK\n");
        gemv_pipeline_created_ = true;
    }

    // --- 2. Allocate GPU buffers ---
    size_t weightBytes = (size_t)rows * cols * sizeof(float);
    size_t inputBytes  = (size_t)cols * sizeof(float);
    size_t outputBytes = (size_t)rows * sizeof(float);
    printf("[DispatchGEMV] Allocating buffers: weight=%zu input=%zu output=%zu\n", weightBytes, inputBytes, outputBytes);

    auto createDeviceBuffer = [&](size_t size, VkBufferUsageFlags usage) -> std::pair<VkBuffer, VkDeviceMemory> {
        VkBufferCreateInfo bufInfo{};
        bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bufInfo.size = size;
        bufInfo.usage = usage | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        VkBuffer buf = nullptr;
        VkResult r = vkCreateBuffer(device_, &bufInfo, nullptr, &buf);
        if (r != VK_SUCCESS) { printf("[DispatchGEMV] FAIL: vkCreateBuffer result=%d\n", (int)r); return {nullptr, nullptr}; }
        VkMemoryRequirements memReq;
        vkGetBufferMemoryRequirements(device_, buf, &memReq);
        VkMemoryAllocateInfo allocInfo{};
        allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        allocInfo.allocationSize = memReq.size;
        allocInfo.memoryTypeIndex = FindMemoryType(memReq.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
        if (allocInfo.memoryTypeIndex == UINT32_MAX) {
            printf("[DispatchGEMV] FAIL: FindMemoryType DEVICE_LOCAL returned UINT32_MAX\n");
            vkDestroyBuffer(device_, buf, nullptr);
            return {nullptr, nullptr};
        }
        VkDeviceMemory mem = nullptr;
        r = vkAllocateMemory(device_, &allocInfo, nullptr, &mem);
        if (r != VK_SUCCESS) { printf("[DispatchGEMV] FAIL: vkAllocateMemory result=%d\n", (int)r); vkDestroyBuffer(device_, buf, nullptr); return {nullptr, nullptr}; }
        vkBindBufferMemory(device_, buf, mem, 0);
        return {buf, mem};
    };

    auto [weightBuf, weightMem] = createDeviceBuffer(weightBytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
    auto [inputBuf, inputMem]   = createDeviceBuffer(inputBytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
    auto [outputBuf, outputMem]   = createDeviceBuffer(outputBytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);

    if (!weightBuf || !inputBuf || !outputBuf) {
        printf("[DispatchGEMV] FAIL: buffer allocation failed\n");
        if (weightBuf) { vkDestroyBuffer(device_, weightBuf, nullptr); vkFreeMemory(device_, weightMem, nullptr); }
        if (inputBuf)  { vkDestroyBuffer(device_, inputBuf, nullptr); vkFreeMemory(device_, inputMem, nullptr); }
        if (outputBuf) { vkDestroyBuffer(device_, outputBuf, nullptr); vkFreeMemory(device_, outputMem, nullptr); }
        return false;
    }
    printf("[DispatchGEMV] Buffers allocated OK\n");

    // --- 3. Upload data via staging buffer ---
    auto uploadViaStaging = [&](const void* data, size_t size, VkBuffer dstBuf) {
        VkBufferCreateInfo stagingInfo{};
        stagingInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        stagingInfo.size = size;
        stagingInfo.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        stagingInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        VkBuffer stagingBuf = nullptr;
        vkCreateBuffer(device_, &stagingInfo, nullptr, &stagingBuf);
        VkMemoryRequirements stagingReq;
        vkGetBufferMemoryRequirements(device_, stagingBuf, &stagingReq);
        VkMemoryAllocateInfo stagingAlloc{};
        stagingAlloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        stagingAlloc.allocationSize = stagingReq.size;
        stagingAlloc.memoryTypeIndex = FindMemoryType(stagingReq.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        if (stagingAlloc.memoryTypeIndex == UINT32_MAX) {
            printf("[DispatchGEMV] FAIL: FindMemoryType HOST_VISIBLE returned UINT32_MAX\n");
            vkDestroyBuffer(device_, stagingBuf, nullptr);
            return;
        }
        VkDeviceMemory stagingMem = nullptr;
        vkAllocateMemory(device_, &stagingAlloc, nullptr, &stagingMem);
        vkBindBufferMemory(device_, stagingBuf, stagingMem, 0);
        void* mapped = nullptr;
        vkMapMemory(device_, stagingMem, 0, size, 0, &mapped);
        memcpy(mapped, data, size);
        vkUnmapMemory(device_, stagingMem);

        VkCommandBufferAllocateInfo allocInfo{};
        allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        allocInfo.commandPool = command_pool_;
        allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        allocInfo.commandBufferCount = 1;
        VkCommandBuffer cmdBuf = nullptr;
        vkAllocateCommandBuffers(device_, &allocInfo, &cmdBuf);
        VkCommandBufferBeginInfo beginInfo{};
        beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(cmdBuf, &beginInfo);
        VkBufferCopy copyRegion{};
        copyRegion.size = size;
        vkCmdCopyBuffer(cmdBuf, stagingBuf, dstBuf, 1, &copyRegion);
        vkEndCommandBuffer(cmdBuf);
        VkSubmitInfo submitInfo{};
        submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submitInfo.commandBufferCount = 1;
        submitInfo.pCommandBuffers = &cmdBuf;
        vkQueueSubmit(compute_queue_, 1, &submitInfo, VK_NULL_HANDLE);
        vkQueueWaitIdle(compute_queue_);
        vkFreeCommandBuffers(device_, command_pool_, 1, &cmdBuf);
        vkDestroyBuffer(device_, stagingBuf, nullptr);
        vkFreeMemory(device_, stagingMem, nullptr);
    };

    uploadViaStaging(weights, weightBytes, weightBuf);
    uploadViaStaging(input, inputBytes, inputBuf);
    printf("[DispatchGEMV] Upload via staging OK\n");

    // --- 4. Dispatch compute shader ---
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = command_pool_;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    VkCommandBuffer cmdBuf = nullptr;
    vkAllocateCommandBuffers(device_, &allocInfo, &cmdBuf);

    VkDescriptorSetAllocateInfo dsAllocInfo{};
    dsAllocInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    dsAllocInfo.descriptorPool = gemv_desc_pool_;
    dsAllocInfo.descriptorSetCount = 1;
    dsAllocInfo.pSetLayouts = &gemv_ds_layout_;
    VkDescriptorSet ds = nullptr;
    VkResult dsResult = vkAllocateDescriptorSets(device_, &dsAllocInfo, &ds);
    if (dsResult != VK_SUCCESS) {
        printf("[DispatchGEMV] FAIL: vkAllocateDescriptorSets result=%d\n", (int)dsResult);
        vkFreeCommandBuffers(device_, command_pool_, 1, &cmdBuf);
        vkDestroyBuffer(device_, weightBuf, nullptr); vkFreeMemory(device_, weightMem, nullptr);
        vkDestroyBuffer(device_, inputBuf, nullptr); vkFreeMemory(device_, inputMem, nullptr);
        vkDestroyBuffer(device_, outputBuf, nullptr); vkFreeMemory(device_, outputMem, nullptr);
        return false;
    }

    VkDescriptorBufferInfo dbiWeight{weightBuf, 0, weightBytes};
    VkDescriptorBufferInfo dbiInput{inputBuf, 0, inputBytes};
    VkDescriptorBufferInfo dbiOutput{outputBuf, 0, outputBytes};

    VkWriteDescriptorSet writes[3] = {};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].dstBinding = 0; writes[0].pBufferInfo = &dbiWeight;
    writes[1].dstBinding = 1; writes[1].pBufferInfo = &dbiInput;
    writes[2].dstBinding = 2; writes[2].pBufferInfo = &dbiOutput;
    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmdBuf, &beginInfo);
    vkCmdBindPipeline(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, gemv_pipeline_);
    vkCmdBindDescriptorSets(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, gemv_pipeline_layout_, 0, 1, &ds, 0, nullptr);
    uint32_t pushConsts[2] = {rows, cols};
    vkCmdPushConstants(cmdBuf, gemv_pipeline_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pushConsts), pushConsts);
    vkCmdDispatch(cmdBuf, (rows + 255) / 256, 1, 1);
    vkEndCommandBuffer(cmdBuf);
    printf("[DispatchGEMV] Command buffer recorded OK\n");

    VkFence fence = nullptr;
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(device_, &fenceInfo, nullptr, &fence);
    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmdBuf;
    VkResult result = vkQueueSubmit(compute_queue_, 1, &submitInfo, fence);
    if (result != VK_SUCCESS) {
        printf("[DispatchGEMV] FAIL: vkQueueSubmit result=%d\n", (int)result);
        vkDestroyFence(device_, fence, nullptr);
        vkFreeCommandBuffers(device_, command_pool_, 1, &cmdBuf);
        vkDestroyBuffer(device_, weightBuf, nullptr); vkFreeMemory(device_, weightMem, nullptr);
        vkDestroyBuffer(device_, inputBuf, nullptr); vkFreeMemory(device_, inputMem, nullptr);
        vkDestroyBuffer(device_, outputBuf, nullptr); vkFreeMemory(device_, outputMem, nullptr);
        return false;
    }
    printf("[DispatchGEMV] Queue submit OK, waiting on fence...\n");
    vkWaitForFences(device_, 1, &fence, VK_TRUE, 10000000000ULL);
    printf("[DispatchGEMV] Fence signaled OK\n");

    // --- 5. Download result ---
    VkBufferCreateInfo readbackInfo{};
    readbackInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    readbackInfo.size = outputBytes;
    readbackInfo.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    readbackInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    VkBuffer readbackBuf = nullptr;
    vkCreateBuffer(device_, &readbackInfo, nullptr, &readbackBuf);
    VkMemoryRequirements readbackReq;
    vkGetBufferMemoryRequirements(device_, readbackBuf, &readbackReq);
    VkMemoryAllocateInfo readbackAlloc{};
    readbackAlloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    readbackAlloc.allocationSize = readbackReq.size;
    readbackAlloc.memoryTypeIndex = FindMemoryType(readbackReq.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (readbackAlloc.memoryTypeIndex == UINT32_MAX) {
        printf("[DispatchGEMV] FAIL: FindMemoryType HOST_VISIBLE for readback returned UINT32_MAX\n");
        vkDestroyBuffer(device_, readbackBuf, nullptr);
        vkFreeCommandBuffers(device_, command_pool_, 1, &cmdBuf);
        vkDestroyFence(device_, fence, nullptr);
        vkDestroyBuffer(device_, weightBuf, nullptr); vkFreeMemory(device_, weightMem, nullptr);
        vkDestroyBuffer(device_, inputBuf, nullptr); vkFreeMemory(device_, inputMem, nullptr);
        vkDestroyBuffer(device_, outputBuf, nullptr); vkFreeMemory(device_, outputMem, nullptr);
        return false;
    }
    VkDeviceMemory readbackMem = nullptr;
    vkAllocateMemory(device_, &readbackAlloc, nullptr, &readbackMem);
    vkBindBufferMemory(device_, readbackBuf, readbackMem, 0);

    VkCommandBuffer dlCmdBuf = nullptr;
    vkAllocateCommandBuffers(device_, &allocInfo, &dlCmdBuf);
    VkCommandBufferBeginInfo dlBeginInfo{};
    dlBeginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    dlBeginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(dlCmdBuf, &dlBeginInfo);
    VkBufferCopy dlCopy{};
    dlCopy.size = outputBytes;
    vkCmdCopyBuffer(dlCmdBuf, outputBuf, readbackBuf, 1, &dlCopy);
    vkEndCommandBuffer(dlCmdBuf);
    VkSubmitInfo dlSubmit{};
    dlSubmit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    dlSubmit.commandBufferCount = 1;
    dlSubmit.pCommandBuffers = &dlCmdBuf;
    vkQueueSubmit(compute_queue_, 1, &dlSubmit, VK_NULL_HANDLE);
    vkQueueWaitIdle(compute_queue_);
    void* mappedOut = nullptr;
    vkMapMemory(device_, readbackMem, 0, outputBytes, 0, &mappedOut);
    memcpy(output, mappedOut, outputBytes);
    vkUnmapMemory(device_, readbackMem);
    printf("[DispatchGEMV] Download result OK\n");

    // --- 6. Cleanup ---
    vkFreeCommandBuffers(device_, command_pool_, 1, &cmdBuf);
    vkFreeCommandBuffers(device_, command_pool_, 1, &dlCmdBuf);
    vkDestroyFence(device_, fence, nullptr);
    vkDestroyBuffer(device_, readbackBuf, nullptr);
    vkFreeMemory(device_, readbackMem, nullptr);
    vkDestroyBuffer(device_, weightBuf, nullptr); vkFreeMemory(device_, weightMem, nullptr);
    vkDestroyBuffer(device_, inputBuf, nullptr); vkFreeMemory(device_, inputMem, nullptr);
    vkDestroyBuffer(device_, outputBuf, nullptr); vkFreeMemory(device_, outputMem, nullptr);

    printf("[DispatchGEMV] SUCCESS\n");
    return true;
}

bool VulkanCompute::AllocateBuffer(size_t size, uint32_t& buffer_idx, size_t& memory_size) {
    (void)size; (void)buffer_idx; (void)memory_size;
    return false;
}

bool VulkanCompute::AllocateBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory) {
    (void)size; (void)buffer; (void)memory;
    return false;
}

bool VulkanCompute::CopyBufferToHost(uint32_t buffer_idx, void* host_data, size_t size) {
    (void)buffer_idx; (void)host_data; (void)size;
    return false;
}

bool VulkanCompute::CopyBufferToHost(VkBuffer device_buffer, void* host_data, size_t size) {
    (void)device_buffer; (void)host_data; (void)size;
    return false;
}

bool VulkanCompute::CopyHostToBuffer(void* host_data, uint32_t buffer_idx, size_t size) {
    (void)host_data; (void)buffer_idx; (void)size;
    return false;
}

bool VulkanCompute::CopyHostToBuffer(void* host_data, VkBuffer device_buffer, size_t size) {
    (void)host_data; (void)device_buffer; (void)size;
    return false;
}

VkBuffer VulkanCompute::CreateStagingBuffer(const void* host_data, size_t size) {
    (void)host_data; (void)size;
    return nullptr; // Stubs: real implementation allocates host-visible VkBuffer + memcpy
}

bool VulkanCompute::AllocateKVCache(uint32_t num_layers, uint32_t max_seq_len, uint32_t head_dim) {
    (void)num_layers; (void)max_seq_len; (void)head_dim;
    return false;
}

bool VulkanCompute::AppendToKVCache(uint32_t layer_idx, const float* k_new, const float* v_new, uint32_t token_pos) {
    (void)layer_idx; (void)k_new; (void)v_new; (void)token_pos;
    return false;
}

bool VulkanCompute::GetKVCacheSlice(uint32_t layer_idx, uint32_t start_pos, uint32_t end_pos, float* k_out, float* v_out) {
    (void)layer_idx; (void)start_pos; (void)end_pos; (void)k_out; (void)v_out;
    return false;
}

void VulkanCompute::ClearKVCache() {
}

bool VulkanCompute::ExecuteSingleTimeCommands(std::function<void(VkCommandBuffer)> record_func) {
    (void)record_func;
    return false;
}

bool VulkanCompute::ExecuteCommandBuffer(VkCommandBuffer cmd_buffer) {
    (void)cmd_buffer;
    return false;
}

VkCommandBuffer VulkanCompute::AcquireAsyncCommandBuffer() {
    return nullptr;
}

bool VulkanCompute::SubmitAsyncCommandBuffer(VkCommandBuffer cmd_buffer) {
    (void)cmd_buffer;
    return false;
}

bool VulkanCompute::FlushAsyncCommands() {
    return false;
}

bool VulkanCompute::CheckAsyncCompletion(VkCommandBuffer cmd_buffer) {
    (void)cmd_buffer;
    return false;
}

bool VulkanCompute::CreateDescriptorSetLayout(uint32_t binding_count, VkDescriptorSetLayout& layout) {
    (void)binding_count; (void)layout;
    return false;
}

bool VulkanCompute::AllocateDescriptorSet(VkDescriptorSetLayout layout, VkDescriptorSet& descriptor_set) {
    (void)layout; (void)descriptor_set;
    return false;
}

bool VulkanCompute::UpdateDescriptorSet(VkDescriptorSet descriptor_set, uint32_t binding, VkBuffer buffer, size_t buffer_size) {
    (void)descriptor_set; (void)binding; (void)buffer; (void)buffer_size;
    return false;
}

bool VulkanCompute::ExecuteMatMul(const float* input_a, const float* input_b,
                                    float* output, uint32_t m, uint32_t k, uint32_t n) {
    (void)input_a; (void)input_b; (void)output;
    (void)m; (void)k; (void)n;
    return false;
}

bool VulkanCompute::ExecuteAttention(const float* queries, const float* keys, const float* values,
                                     float* output, uint32_t seq_len, uint32_t head_dim) {
    (void)queries; (void)keys; (void)values; (void)output;
    (void)seq_len; (void)head_dim;
    return false;
}

bool VulkanCompute::ExecuteRoPE(float* embeddings, uint32_t dim, uint32_t seq_pos, uint32_t rotation_dim) {
    (void)embeddings; (void)dim; (void)seq_pos; (void)rotation_dim;
    return false;
}

bool VulkanCompute::ExecuteRMSNorm(float* data, uint32_t size, float epsilon) {
    (void)data; (void)size; (void)epsilon;
    return false;
}

bool VulkanCompute::ExecuteSiLU(float* data, uint32_t size) {
    (void)data; (void)size;
    return false;
}

bool VulkanCompute::ExecuteSoftmax(float* data, uint32_t size) {
    (void)data; (void)size;
    return false;
}

bool VulkanCompute::ExecuteDequantize(const uint8_t* quantized, float* output,
                                      uint32_t elements, const std::string& quant_type) {
    (void)quantized; (void)output; (void)elements; (void)quant_type;
    return false;
}

bool VulkanCompute::CreateInstance() {
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD Inference";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "RawrXD Engine";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_3;

    VkInstanceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;
    createInfo.enabledLayerCount = 0;
    createInfo.enabledExtensionCount = 0;

    if (vkCreateInstance(&createInfo, nullptr, &instance_) != VK_SUCCESS) {
        printf("[VulkanCompute] vkCreateInstance failed\n");
        return false;
    }
    return true;
}

bool VulkanCompute::SelectPhysicalDevice() {
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance_, &deviceCount, nullptr);
    if (deviceCount == 0) {
        printf("[VulkanCompute] No Vulkan-capable devices found\n");
        return false;
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance_, &deviceCount, devices.data());

    physical_device_ = VK_NULL_HANDLE;
    for (const auto& device : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(device, &props);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            physical_device_ = device;
            device_info_.device_name = props.deviceName;
            device_info_.vendor_id = props.vendorID;
            device_info_.device_id = props.deviceID;
            break;
        }
    }
    if (physical_device_ == VK_NULL_HANDLE) {
        physical_device_ = devices[0];
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(physical_device_, &props);
        device_info_.device_name = props.deviceName;
        device_info_.vendor_id = props.vendorID;
        device_info_.device_id = props.deviceID;
    }

    VkPhysicalDeviceMemoryProperties memProps;
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &memProps);
    device_info_.memory_props = memProps;

    // Find compute queue family
    uint32_t queueFamilyCount = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device_, &queueFamilyCount, nullptr);
    std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device_, &queueFamilyCount, queueFamilies.data());
    device_info_.compute_queue_family = 0;
    for (uint32_t i = 0; i < queueFamilyCount; ++i) {
        if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            device_info_.compute_queue_family = i;
            device_info_.supports_compute = true;
            break;
        }
    }
    return true;
}

bool VulkanCompute::CreateLogicalDevice() {
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueCreateInfo{};
    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCreateInfo.queueFamilyIndex = device_info_.compute_queue_family;
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;

    VkPhysicalDeviceFeatures deviceFeatures{};

    VkDeviceCreateInfo deviceCreateInfo{};
    deviceCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceCreateInfo.queueCreateInfoCount = 1;
    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;
    deviceCreateInfo.pEnabledFeatures = &deviceFeatures;
    deviceCreateInfo.enabledExtensionCount = 0;

    if (vkCreateDevice(physical_device_, &deviceCreateInfo, nullptr, &device_) != VK_SUCCESS) {
        printf("[VulkanCompute] vkCreateDevice failed\n");
        return false;
    }

    vkGetDeviceQueue(device_, device_info_.compute_queue_family, 0, &compute_queue_);
    return true;
}

bool VulkanCompute::CreateCommandPool() {
    VkCommandPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    poolInfo.queueFamilyIndex = device_info_.compute_queue_family;

    if (vkCreateCommandPool(device_, &poolInfo, nullptr, &command_pool_) != VK_SUCCESS) {
        printf("[VulkanCompute] vkCreateCommandPool failed\n");
        return false;
    }

    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 100;

    VkDescriptorPoolCreateInfo descriptorPoolInfo{};
    descriptorPoolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    descriptorPoolInfo.poolSizeCount = 1;
    descriptorPoolInfo.pPoolSizes = &poolSize;
    descriptorPoolInfo.maxSets = 100;

    if (vkCreateDescriptorPool(device_, &descriptorPoolInfo, nullptr, &descriptor_pool_) != VK_SUCCESS) {
        printf("[VulkanCompute] vkCreateDescriptorPool failed\n");
        return false;
    }
    return true;
}

bool VulkanCompute::LoadSPIRVCode(const std::string& path, std::vector<uint32_t>& code) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    code.resize(size / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(code.data()), size);
    return true;
}

uint32_t VulkanCompute::FindMemoryType(uint32_t type_filter, VkMemoryPropertyFlags properties) {
    VkPhysicalDeviceMemoryProperties memProperties;
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &memProperties);
    for (uint32_t i = 0; i < memProperties.memoryTypeCount; ++i) {
        if ((type_filter & (1u << i)) && (memProperties.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }
    return 0;
}

void VulkanCompute::InitializeCommandBufferPool(uint32_t pool_size) {
    (void)pool_size;
}

void VulkanCompute::CleanupCommandBufferPool() {
}

bool VulkanCompute::CopyHostToBufferOffset(const void* host_data, VkBuffer device_buffer, size_t offset, size_t size) {
    (void)host_data; (void)device_buffer; (void)offset; (void)size;
    return false;
}

bool VulkanCompute::CopyBufferToHostOffset(VkBuffer device_buffer, size_t offset, void* host_data, size_t size) {
    (void)device_buffer; (void)offset; (void)host_data; (void)size;
    return false;
}

bool VulkanCompute::CreateStagingBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory) {
    (void)size; (void)buffer; (void)memory;
    return false;
}

} // namespace CPUInference

#endif // RAWR_VULKAN_AVAILABLE

// ============================================================================
// Stub implementations when Vulkan SDK is not available
// These satisfy linker requirements for translation units that reference
// CPUInference::VulkanCompute when RAWR_VULKAN_AVAILABLE == 0.
// ============================================================================
#if !RAWR_VULKAN_AVAILABLE
namespace CPUInference {

VulkanCompute::VulkanCompute() {}
VulkanCompute::~VulkanCompute() {}

bool VulkanCompute::Initialize() { return false; }

bool VulkanCompute::DispatchGEMV(const float* weights, const float* input, float* output,
                                 uint32_t rows, uint32_t cols) {
    (void)weights; (void)input; (void)output; (void)rows; (void)cols;
    return false;
}

bool VulkanCompute::FlushAsyncCommands() { return false; }

} // namespace CPUInference
#endif // !RAWR_VULKAN_AVAILABLE




