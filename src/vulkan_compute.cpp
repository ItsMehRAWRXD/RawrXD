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
#include <cstdint>

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

bool VulkanCompute::InitializeSolo(const char* nameNeedle) {
    // Empty needle → best discrete by VRAM (DeviceManager supplies name when known).
    solo_needle_ = nameNeedle && nameNeedle[0] ? nameNeedle : "";
    return Initialize();
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
        gemv_ds_ = nullptr;
        gemv_pipeline_created_ = false;
        ReleaseGemvResidents();
        ReleaseForwardArena();
        // Forward-resident pipelines / arena (STREAMER_GPU_FORWARD_OPS_001)
        ReleaseForwardArena();
        auto killPipe = [&](VkPipeline& p, VkPipelineLayout& l, VkDescriptorSetLayout& d,
                            VkDescriptorPool& pool) {
            if (p) { vkDestroyPipeline(device_, p, nullptr); p = nullptr; }
            if (l) { vkDestroyPipelineLayout(device_, l, nullptr); l = nullptr; }
            if (d) { vkDestroyDescriptorSetLayout(device_, d, nullptr); d = nullptr; }
            if (pool) { vkDestroyDescriptorPool(device_, pool, nullptr); pool = nullptr; }
        };
        killPipe(rms_pipe_, rms_layout_, rms_dsl_, rms_pool_); rms_ds_ = nullptr;
        killPipe(add_pipe_, add_layout_, add_dsl_, add_pool_); add_ds_ = nullptr;
        killPipe(rope_pipe_, rope_layout_, rope_dsl_, rope_pool_); rope_ds_ = nullptr;
        killPipe(attn_pipe_, attn_layout_, attn_dsl_, attn_pool_); attn_ds_ = nullptr;
        killPipe(swiglu_pipe_, swiglu_layout_, swiglu_dsl_, swiglu_pool_); swiglu_ds_ = nullptr;
        
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
// GEMV helpers — resident DEVICE_LOCAL weights; host-visible activations
// ============================================================================
void VulkanCompute::ReleaseGemvResidents() {
    for (auto& kv : gemv_weight_cache_) {
        if (kv.second.buffer) vkDestroyBuffer(device_, kv.second.buffer, nullptr);
        if (kv.second.memory) vkFreeMemory(device_, kv.second.memory, nullptr);
    }
    gemv_weight_cache_.clear();
    gemv_resident_bytes_ = 0;
    if (gemv_in_buf_) { vkDestroyBuffer(device_, gemv_in_buf_, nullptr); gemv_in_buf_ = nullptr; }
    if (gemv_in_mem_) { vkFreeMemory(device_, gemv_in_mem_, nullptr); gemv_in_mem_ = nullptr; }
    gemv_in_cap_ = 0;
    if (gemv_out_buf_) { vkDestroyBuffer(device_, gemv_out_buf_, nullptr); gemv_out_buf_ = nullptr; }
    if (gemv_out_mem_) { vkFreeMemory(device_, gemv_out_mem_, nullptr); gemv_out_mem_ = nullptr; }
    gemv_out_cap_ = 0;
}

bool VulkanCompute::CreateDeviceLocalBuffer(size_t size, VkBuffer& buf, VkDeviceMemory& mem) {
    VkBufferCreateInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size = size;
    bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT |
               VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device_, &bi, nullptr, &buf) != VK_SUCCESS) return false;
    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(device_, buf, &mr);
    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = mr.size;
    ai.memoryTypeIndex = FindMemoryType(mr.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (ai.memoryTypeIndex == UINT32_MAX) {
        vkDestroyBuffer(device_, buf, nullptr); buf = nullptr; return false;
    }
    if (vkAllocateMemory(device_, &ai, nullptr, &mem) != VK_SUCCESS) {
        vkDestroyBuffer(device_, buf, nullptr); buf = nullptr; return false;
    }
    vkBindBufferMemory(device_, buf, mem, 0);
    return true;
}

bool VulkanCompute::CreateHostVisibleBuffer(size_t size, VkBuffer& buf, VkDeviceMemory& mem) {
    VkBufferCreateInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size = size;
    bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
               VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device_, &bi, nullptr, &buf) != VK_SUCCESS) return false;
    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(device_, buf, &mr);
    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = mr.size;
    ai.memoryTypeIndex = FindMemoryType(
        mr.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (ai.memoryTypeIndex == UINT32_MAX) {
        vkDestroyBuffer(device_, buf, nullptr); buf = nullptr; return false;
    }
    if (vkAllocateMemory(device_, &ai, nullptr, &mem) != VK_SUCCESS) {
        vkDestroyBuffer(device_, buf, nullptr); buf = nullptr; return false;
    }
    vkBindBufferMemory(device_, buf, mem, 0);
    return true;
}

bool VulkanCompute::UploadToDeviceLocal(const void* src, size_t size, VkBuffer dst) {
    VkBuffer staging = nullptr;
    VkDeviceMemory stagingMem = nullptr;
    if (!CreateHostVisibleBuffer(size, staging, stagingMem)) return false;
    // Host-visible was created with STORAGE usage; fine for staging memcpy path.
    // Re-create as TRANSFER_SRC for correctness on strict drivers:
    vkDestroyBuffer(device_, staging, nullptr);
    vkFreeMemory(device_, stagingMem, nullptr);
    VkBufferCreateInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size = size;
    bi.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device_, &bi, nullptr, &staging) != VK_SUCCESS) return false;
    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(device_, staging, &mr);
    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = mr.size;
    ai.memoryTypeIndex = FindMemoryType(
        mr.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (ai.memoryTypeIndex == UINT32_MAX ||
        vkAllocateMemory(device_, &ai, nullptr, &stagingMem) != VK_SUCCESS) {
        vkDestroyBuffer(device_, staging, nullptr);
        return false;
    }
    vkBindBufferMemory(device_, staging, stagingMem, 0);
    void* mapped = nullptr;
    vkMapMemory(device_, stagingMem, 0, size, 0, &mapped);
    std::memcpy(mapped, src, size);
    vkUnmapMemory(device_, stagingMem);

    VkCommandBufferAllocateInfo cai{};
    cai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &begin);
    VkBufferCopy copy{};
    copy.size = size;
    vkCmdCopyBuffer(cmd, staging, dst, 1, &copy);
    vkEndCommandBuffer(cmd);
    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    vkQueueSubmit(compute_queue_, 1, &si, VK_NULL_HANDLE);
    vkQueueWaitIdle(compute_queue_);
    vkFreeCommandBuffers(device_, command_pool_, 1, &cmd);
    vkDestroyBuffer(device_, staging, nullptr);
    vkFreeMemory(device_, stagingMem, nullptr);
    return true;
}

bool VulkanCompute::EnsureHostIo(size_t inBytes, size_t outBytes) {
    if (inBytes > gemv_in_cap_) {
        if (gemv_in_buf_) { vkDestroyBuffer(device_, gemv_in_buf_, nullptr); gemv_in_buf_ = nullptr; }
        if (gemv_in_mem_) { vkFreeMemory(device_, gemv_in_mem_, nullptr); gemv_in_mem_ = nullptr; }
        gemv_in_cap_ = 0;
        if (!CreateHostVisibleBuffer(inBytes, gemv_in_buf_, gemv_in_mem_)) return false;
        gemv_in_cap_ = inBytes;
    }
    if (outBytes > gemv_out_cap_) {
        if (gemv_out_buf_) { vkDestroyBuffer(device_, gemv_out_buf_, nullptr); gemv_out_buf_ = nullptr; }
        if (gemv_out_mem_) { vkFreeMemory(device_, gemv_out_mem_, nullptr); gemv_out_mem_ = nullptr; }
        gemv_out_cap_ = 0;
        if (!CreateHostVisibleBuffer(outBytes, gemv_out_buf_, gemv_out_mem_)) return false;
        gemv_out_cap_ = outBytes;
    }
    return true;
}

bool VulkanCompute::EnsureGemvPipeline() {
    if (gemv_pipeline_created_) return true;
    std::string spirvPath = "src/backend/gemv.spv";
    std::ifstream file(spirvPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        const char* candidates[] = {
            "gemv.spv", "bin/gemv.spv",
            "G:/~dev/rawrxd/src/backend/gemv.spv",
            "G:\\~dev\\rawrxd\\src\\backend\\gemv.spv",
            "G:/~dev/rawrxd/build-ninja/bin/gemv.spv",
        };
        for (const char* c : candidates) {
            file.open(c, std::ios::binary | std::ios::ate);
            if (file.is_open()) { spirvPath = c; break; }
        }
        if (!file.is_open()) return false;
    }
    size_t fileSize = (size_t)file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint32_t> spirvCode(fileSize / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(spirvCode.data()), (std::streamsize)fileSize);
    file.close();

    VkShaderModuleCreateInfo shaderInfo{};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = spirvCode.size() * sizeof(uint32_t);
    shaderInfo.pCode = spirvCode.data();
    VkShaderModule shaderModule = nullptr;
    if (vkCreateShaderModule(device_, &shaderInfo, nullptr, &shaderModule) != VK_SUCCESS)
        return false;

    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; ++i) {
        bindings[i].binding = (uint32_t)i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo dslInfo{};
    dslInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dslInfo.bindingCount = 3;
    dslInfo.pBindings = bindings;
    if (vkCreateDescriptorSetLayout(device_, &dslInfo, nullptr, &gemv_ds_layout_) != VK_SUCCESS) {
        vkDestroyShaderModule(device_, shaderModule, nullptr);
        return false;
    }

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
        vkDestroyDescriptorSetLayout(device_, gemv_ds_layout_, nullptr);
        gemv_ds_layout_ = nullptr;
        vkDestroyShaderModule(device_, shaderModule, nullptr);
        return false;
    }

    VkPipelineShaderStageCreateInfo stageInfo{};
    stageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stageInfo.module = shaderModule;
    stageInfo.pName = "main";
    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.layout = gemv_pipeline_layout_;
    pipelineInfo.stage = stageInfo;
    VkResult pr = vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &pipelineInfo,
                                           nullptr, &gemv_pipeline_);
    vkDestroyShaderModule(device_, shaderModule, nullptr);
    if (pr != VK_SUCCESS) {
        vkDestroyPipelineLayout(device_, gemv_pipeline_layout_, nullptr);
        gemv_pipeline_layout_ = nullptr;
        vkDestroyDescriptorSetLayout(device_, gemv_ds_layout_, nullptr);
        gemv_ds_layout_ = nullptr;
        return false;
    }

    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 3;
    VkDescriptorPoolCreateInfo dpInfo{};
    dpInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dpInfo.maxSets = 1;
    dpInfo.poolSizeCount = 1;
    dpInfo.pPoolSizes = &poolSize;
    if (vkCreateDescriptorPool(device_, &dpInfo, nullptr, &gemv_desc_pool_) != VK_SUCCESS)
        return false;
    VkDescriptorSetAllocateInfo onceAlloc{};
    onceAlloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    onceAlloc.descriptorPool = gemv_desc_pool_;
    onceAlloc.descriptorSetCount = 1;
    onceAlloc.pSetLayouts = &gemv_ds_layout_;
    if (vkAllocateDescriptorSets(device_, &onceAlloc, &gemv_ds_) != VK_SUCCESS || !gemv_ds_)
        return false;
    ++gemv_desc_allocs_;
    gemv_pipeline_created_ = true;
    return true;
}

// ============================================================================
// DispatchGEMV: resident weights + host-visible activations on planned primary
// ============================================================================
bool VulkanCompute::DispatchGEMV(const float* weights, const float* input, float* output,
                                 uint32_t rows, uint32_t cols, uint64_t cacheKey) {
    if (!device_ || !compute_queue_ || !command_pool_ || !weights || !input || !output)
        return false;
    if (!EnsureGemvPipeline()) return false;
    ++gemv_attempts_;
    if (gemv_ds_) ++gemv_desc_reuses_;

    const size_t weightBytes = (size_t)rows * cols * sizeof(float);
    const size_t inputBytes = (size_t)cols * sizeof(float);
    const size_t outputBytes = (size_t)rows * sizeof(float);
    if (cacheKey == 0)
        cacheKey = (uint64_t)(uintptr_t)weights ^ ((uint64_t)rows << 32) ^ (uint64_t)cols;

    GemvResidentWeight* resident = nullptr;
    auto it = gemv_weight_cache_.find(cacheKey);
    if (it != gemv_weight_cache_.end() && it->second.rows == rows && it->second.cols == cols) {
        resident = &it->second;
        ++gemv_weight_hits_;
    } else {
        GemvResidentWeight rw{};
        if (!CreateDeviceLocalBuffer(weightBytes, rw.buffer, rw.memory)) return false;
        if (!UploadToDeviceLocal(weights, weightBytes, rw.buffer)) {
            vkDestroyBuffer(device_, rw.buffer, nullptr);
            vkFreeMemory(device_, rw.memory, nullptr);
            return false;
        }
        rw.bytes = weightBytes;
        rw.rows = rows;
        rw.cols = cols;
        if (it != gemv_weight_cache_.end()) {
            if (it->second.buffer) vkDestroyBuffer(device_, it->second.buffer, nullptr);
            if (it->second.memory) vkFreeMemory(device_, it->second.memory, nullptr);
            gemv_resident_bytes_ -= it->second.bytes;
        }
        gemv_weight_cache_[cacheKey] = rw;
        gemv_resident_bytes_ += weightBytes;
        ++gemv_weight_uploads_;
        resident = &gemv_weight_cache_[cacheKey];
    }

    if (!EnsureHostIo(inputBytes, outputBytes)) return false;
    void* mappedIn = nullptr;
    vkMapMemory(device_, gemv_in_mem_, 0, inputBytes, 0, &mappedIn);
    std::memcpy(mappedIn, input, inputBytes);
    vkUnmapMemory(device_, gemv_in_mem_);

    VkDescriptorBufferInfo dbiW{resident->buffer, 0, weightBytes};
    VkDescriptorBufferInfo dbiI{gemv_in_buf_, 0, inputBytes};
    VkDescriptorBufferInfo dbiO{gemv_out_buf_, 0, outputBytes};
    VkWriteDescriptorSet writes[3] = {};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = gemv_ds_;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].dstBinding = 0; writes[0].pBufferInfo = &dbiW;
    writes[1].dstBinding = 1; writes[1].pBufferInfo = &dbiI;
    writes[2].dstBinding = 2; writes[2].pBufferInfo = &dbiO;
    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);

    VkCommandBufferAllocateInfo cai{};
    cai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &begin);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, gemv_pipeline_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, gemv_pipeline_layout_,
                            0, 1, &gemv_ds_, 0, nullptr);
    uint32_t pc[2] = {rows, cols};
    vkCmdPushConstants(cmd, gemv_pipeline_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), pc);
    vkCmdDispatch(cmd, (rows + 255u) / 256u, 1, 1);
    vkEndCommandBuffer(cmd);

    VkFence fence = nullptr;
    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(device_, &fi, nullptr, &fence);
    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    if (vkQueueSubmit(compute_queue_, 1, &si, fence) != VK_SUCCESS) {
        vkDestroyFence(device_, fence, nullptr);
        vkFreeCommandBuffers(device_, command_pool_, 1, &cmd);
        return false;
    }
    vkWaitForFences(device_, 1, &fence, VK_TRUE, 10000000000ULL);
    void* mappedOut = nullptr;
    vkMapMemory(device_, gemv_out_mem_, 0, outputBytes, 0, &mappedOut);
    std::memcpy(output, mappedOut, outputBytes);
    vkUnmapMemory(device_, gemv_out_mem_);
    vkDestroyFence(device_, fence, nullptr);
    vkFreeCommandBuffers(device_, command_pool_, 1, &cmd);
    ++gemv_success_;
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

static bool VkNameHas(const char* hay, const char* needle) {
    if (!hay || !needle || !*needle) return false;
    const size_t nlen = std::strlen(needle);
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        while (p[i] && i < nlen) {
            char a = p[i], b = needle[i];
            if (a >= 'a' && a <= 'z') a = (char)(a - 32);
            if (b >= 'a' && b <= 'z') b = (char)(b - 32);
            if (a != b) break;
            ++i;
        }
        if (i == nlen) return true;
    }
    return false;
}

static bool VkTokenGeneric(const char* tok) {
    return VkNameHas("AMD NVIDIA INTEL RADEON GEFORCE RTX GTX GRAPHICS ADAPTER SERIES", tok);
}

// Higher = better needle fidelity. Generic vendor tokens ignored.
static int VkNeedleScore(const char* deviceName, const char* needle) {
    if (!needle || !*needle) return 0;
    if (VkNameHas(deviceName, needle) || VkNameHas(needle, deviceName)) return 1000;
    int score = 0;
    int needed = 0;
    const char* t = needle;
    while (*t) {
        while (*t == ' ' || *t == '(' || *t == ')') ++t;
        char tok[32]{};
        size_t k = 0;
        while (*t && *t != ' ' && *t != '(' && *t != ')' && k + 1 < sizeof(tok))
            tok[k++] = *t++;
        if (k < 3) continue;
        if (VkTokenGeneric(tok)) continue;
        ++needed;
        if (VkNameHas(deviceName, tok)) score += (k >= 4) ? 10 : 4;
    }
    if (needed == 0) return VkNameHas(deviceName, needle) ? 1 : 0;
    return score;
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
    int bestNeedle = -1;
    int bestRank = -1;
    uint64_t bestVram = 0;
    for (uint32_t i = 0; i < deviceCount; ++i) {
        VkPhysicalDeviceProperties props{};
        vkGetPhysicalDeviceProperties(devices[i], &props);
        printf("[VulkanCompute] DETECTED phys[%u] type=%u %s\n",
               i, props.deviceType, props.deviceName);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU)
            continue;
        if (props.deviceType != VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU &&
            props.deviceType != VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU)
            continue;

        int needleScore = 0;
        if (!solo_needle_.empty()) {
            needleScore = VkNeedleScore(props.deviceName, solo_needle_.c_str());
            if (needleScore <= 0) continue;
        }
        int rank = 2;
        VkPhysicalDeviceMemoryProperties mem{};
        vkGetPhysicalDeviceMemoryProperties(devices[i], &mem);
        uint64_t vram = 0;
        for (uint32_t h = 0; h < mem.memoryHeapCount; ++h) {
            if (mem.memoryHeaps[h].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)
                vram = (std::max)(vram, (uint64_t)mem.memoryHeaps[h].size);
        }
        // Needle fidelity wins; then discrete rank; then VRAM.
        const bool better =
            needleScore > bestNeedle ||
            (needleScore == bestNeedle && rank > bestRank) ||
            (needleScore == bestNeedle && rank == bestRank && vram > bestVram);
        if (better) {
            bestNeedle = needleScore;
            bestRank = rank;
            bestVram = vram;
            physical_device_ = devices[i];
            device_info_.device_name = props.deviceName;
            device_info_.vendor_id = props.vendorID;
            device_info_.device_id = props.deviceID;
        }
    }
    if (physical_device_ == VK_NULL_HANDLE) {
        printf("[VulkanCompute] no eligible compute device (needle=%s)\n",
               solo_needle_.empty() ? "(none)" : solo_needle_.c_str());
        return false;
    }
    printf("[VulkanCompute] OPEN_ONE %s (others unused)\n",
           device_info_.device_name.c_str());

    VkPhysicalDeviceMemoryProperties memProps;
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &memProps);
    device_info_.memory_props = memProps;

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
bool VulkanCompute::InitializeSolo(const char*) { return false; }

bool VulkanCompute::DispatchGEMV(const float* weights, const float* input, float* output,
                                 uint32_t rows, uint32_t cols, uint64_t cacheKey) {
    (void)weights; (void)input; (void)output; (void)rows; (void)cols; (void)cacheKey;
    return false;
}

bool VulkanCompute::FlushAsyncCommands() { return false; }

} // namespace CPUInference
#endif // !RAWR_VULKAN_AVAILABLE




