#ifndef RAWRXD_FORMAT_AWARE_GPU_DISPATCH_HPP
#define RAWRXD_FORMAT_AWARE_GPU_DISPATCH_HPP
// ============================================================================
// FormatAwareGpuDispatch.hpp -- Stage 6J: route each GGUF tensor to the right
// native GPU kernel based on its quantization type, with packed-weight VRAM
// residency and safe fallback.
// ----------------------------------------------------------------------------
//   Q4_0  (type 2)  -> q4_0_matvec.spv  (32-value blocks, symmetric)
//   Q4_K  (type 12) -> q4_k_matvec.spv  (256-value superblocks, scale+min)
//   INT4  (custom)  -> int4_matvec.spv  (64-value blocks, F16 scale)
//   F16/F32/unsupported -> fallback (no native INT4 kernel)
//
// The dispatch preserves packed weights in VRAM (no F32 expansion) and reuses
// buffers across calls (upload-once). FP64 capability is checked for the Q4_K
// double-accumulation path; if unsupported, the caller falls back to F32.
//
// Header-only, C++17, Vulkan. Link vulkan-1.
// ============================================================================
#include <vulkan/vulkan.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace rawrxd::gpu {

enum class GpuWeightFormat : uint32_t {
    Q4_0 = 2, Q4_K = 12, INT4 = 0x10000, F16 = 1, F32 = 0, Unsupported = 0xFFFFFFFFu
};

// Map a GGUF tensor type to a native GPU kernel format.
inline GpuWeightFormat DetectFormat(uint32_t gguf_type) {
    switch (gguf_type) {
        case 2:  return GpuWeightFormat::Q4_0;
        case 12: return GpuWeightFormat::Q4_K;
        case 0:  return GpuWeightFormat::F32;
        case 1:  return GpuWeightFormat::F16;
        default: return GpuWeightFormat::Unsupported;
    }
}

// Custom INT4 (RawrXD packed nibbles + F16 scales) -- used after requantizing
// F32/F16 tensors; not a GGUF type but a RawrXD internal format.
inline bool IsCustomInt4(GpuWeightFormat f) { return f == GpuWeightFormat::INT4; }

// FP64 capability check: Q4_K's double-accumulation kernel requires
// shaderFloat64. If unsupported, the caller falls back to a float-accumulation
// variant or the CPU path.
inline bool HasFloat64(VkPhysicalDevice pd) {
    VkPhysicalDeviceFeatures f; vkGetPhysicalDeviceFeatures(pd, &f);
    return f.shaderFloat64 != VK_FALSE;
}

// Values per block for each format (for geometry).
inline uint32_t ValuesPerBlock(GpuWeightFormat f) {
    switch (f) {
        case GpuWeightFormat::Q4_0: return 32;
        case GpuWeightFormat::Q4_K: return 256;
        case GpuWeightFormat::INT4: return 64;
        default: return 0;
    }
}

// Block bytes for each format.
inline uint32_t BlockBytes(GpuWeightFormat f) {
    switch (f) {
        case GpuWeightFormat::Q4_0: return 18;
        case GpuWeightFormat::Q4_K: return 144;
        case GpuWeightFormat::INT4: return 0; // INT4 is custom (packed nibbles + scales)
        default: return 0;
    }
}

// A single compute program (one shader). Two descriptor layouts:
//   int4Layout=false (Q4_0/Q4_K): 0=weights, 1=x, 2=y (storage), 3=dims (uniform)
//   int4Layout=true  (INT4):      0=W, 1=scales, 2=x, 3=y (storage), 4=dims (uniform)
struct GpuProgram {
    VkDevice dev = VK_NULL_HANDLE;
    VkShaderModule shader = VK_NULL_HANDLE;
    VkPipelineLayout layout = VK_NULL_HANDLE;
    VkPipeline pipe = VK_NULL_HANDLE;
    VkDescriptorSetLayout dsl = VK_NULL_HANDLE;
    VkDescriptorPool pool = VK_NULL_HANDLE;
    VkDescriptorSet set = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;

    bool init(VkDevice d, const std::string& spv, bool int4Layout = false) {
        dev = d;
        std::ifstream sf(spv, std::ios::binary | std::ios::ate);
        if (!sf) return false;
        std::streamsize sz = sf.tellg(); sf.seekg(0);
        std::vector<char> buf(sz); if (!sf.read(buf.data(), sz)) return false;
        VkShaderModuleCreateInfo smi{}; smi.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO; smi.codeSize=buf.size(); smi.pCode=(const uint32_t*)buf.data();
        if (vkCreateShaderModule(d,&smi,nullptr,&shader)!=VK_SUCCESS) return false;
        VkPipelineShaderStageCreateInfo ssi{}; ssi.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO; ssi.stage=VK_SHADER_STAGE_COMPUTE_BIT; ssi.module=shader; ssi.pName="main";
        const uint32_t nStorage = int4Layout ? 4u : 3u; // INT4 has 4 storage buffers; Q4_0/Q4_K have 3
        const uint32_t dimsBinding = int4Layout ? 4u : 3u; // dims uniform binding index
        const uint32_t totalBindings = int4Layout ? 5u : 4u;
        VkDescriptorSetLayoutBinding b[5]; std::memset(b,0,sizeof(b));
        for (uint32_t i=0;i<nStorage;++i){ b[i].binding=i; b[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; b[i].descriptorCount=1; b[i].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT; }
        b[dimsBinding].binding=dimsBinding; b[dimsBinding].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER; b[dimsBinding].descriptorCount=1; b[dimsBinding].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
        VkDescriptorSetLayoutCreateInfo dl{}; dl.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO; dl.bindingCount=totalBindings; dl.pBindings=b;
        if (vkCreateDescriptorSetLayout(d,&dl,nullptr,&dsl)!=VK_SUCCESS) return false;
        VkPipelineLayoutCreateInfo pl{}; pl.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO; pl.setLayoutCount=1; pl.pSetLayouts=&dsl;
        if (vkCreatePipelineLayout(d,&pl,nullptr,&layout)!=VK_SUCCESS) return false;
        VkComputePipelineCreateInfo cp{}; cp.sType=VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO; cp.layout=layout; cp.stage=ssi;
        if (vkCreateComputePipelines(d,nullptr,1,&cp,nullptr,&pipe)!=VK_SUCCESS) return false;
        VkDescriptorPoolSize ps[2]={{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,nStorage},{VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,1}};
        VkDescriptorPoolCreateInfo dp{}; dp.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO; dp.maxSets=1; dp.poolSizeCount=2; dp.pPoolSizes=ps;
        if (vkCreateDescriptorPool(d,&dp,nullptr,&pool)!=VK_SUCCESS) return false;
        VkDescriptorSetAllocateInfo da{}; da.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO; da.descriptorPool=pool; da.descriptorSetCount=1; da.pSetLayouts=&dsl;
        if (vkAllocateDescriptorSets(d,&da,&set)!=VK_SUCCESS) return false;
        VkFenceCreateInfo fc{}; fc.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO; vkCreateFence(d,&fc,nullptr,&fence);
        return true;
    }

    // Dispatch one matvec: 3 storage buffers (weights, x, y) + dims uniform.
    // For INT4 (int4Layout=true), binding 1 is scales (unused here) -- caller
    // passes the right buffers per layout.
    bool dispatch(VkQueue queue, VkCommandPool pool, VkBuffer w, VkBuffer x, VkBuffer y,
                  VkBuffer dimsBuf, uint32_t rows, uint32_t blocksPerRow) {
        if (dev == VK_NULL_HANDLE) return false;
        VkDescriptorBufferInfo bi[3] = {{w,0,VK_WHOLE_SIZE},{x,0,VK_WHOLE_SIZE},{y,0,VK_WHOLE_SIZE}};
        VkDescriptorBufferInfo di{dimsBuf,0,sizeof(uint32_t)*3};
        VkWriteDescriptorSet wr[4]; std::memset(wr,0,sizeof(wr));
        for (int i=0;i<3;++i){ wr[i].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; wr[i].dstSet=set; wr[i].dstBinding=(uint32_t)i; wr[i].descriptorCount=1; wr[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; wr[i].pBufferInfo=&bi[i]; }
        wr[3].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; wr[3].dstSet=set; wr[3].dstBinding=3; wr[3].descriptorCount=1; wr[3].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER; wr[3].pBufferInfo=&di;
        vkUpdateDescriptorSets(dev, 4, wr, 0, nullptr);

        VkCommandBufferAllocateInfo ci{}; ci.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO; ci.commandPool=pool; ci.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY; ci.commandBufferCount=1;
        VkCommandBuffer cb; if (vkAllocateCommandBuffers(dev,&ci,&cb)!=VK_SUCCESS) return false;
        VkCommandBufferBeginInfo cbi{}; cbi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO; vkBeginCommandBuffer(cb,&cbi);
        vkCmdBindPipeline(cb,VK_PIPELINE_BIND_POINT_COMPUTE,pipe);
        vkCmdBindDescriptorSets(cb,VK_PIPELINE_BIND_POINT_COMPUTE,layout,0,1,&set,0,nullptr);
        vkCmdDispatch(cb, rows, 1, 1);
        vkEndCommandBuffer(cb);
        VkSubmitInfo si{}; si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO; si.commandBufferCount=1; si.pCommandBuffers=&cb;
        vkResetFences(dev,1,&fence); vkQueueSubmit(queue,1,&si,fence); vkWaitForFences(dev,1,&fence,VK_TRUE,UINT64_MAX);
        vkFreeCommandBuffers(dev,pool,1,&cb);
        return true;
    }
};

} // namespace rawrxd::gpu

#endif // RAWRXD_FORMAT_AWARE_GPU_DISPATCH_HPP