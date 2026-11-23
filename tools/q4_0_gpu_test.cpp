// q4_0_gpu_test.cpp -- Stage 6H: native Q4_0 GPU execution. Uploads Q4_0
// blocks DIRECTLY (no F32 intermediate), dispatches q4_0_matvec.comp, and
// compares GPU output against the ggml CPU reference dequant + matvec.
// Build: g++ -std=c++17 -O2 -I include -I src tools/q4_0_gpu_test.cpp src/VulkanDevice.cpp -o q4g -lvulkan-1
// Usage: q4g [rows=64] [cols=1024]
#include "VulkanDevice.hpp"
#include "deep2/GgufQuantAdapter.hpp"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using namespace rawrxd::gguf;

// Minimal dedicated Q4_0 program (bindings: 0=q4, 1=x, 2=y, 3=dims UBO).
struct Q4Program {
    VkDevice dev = VK_NULL_HANDLE;
    VkShaderModule shader = VK_NULL_HANDLE;
    VkPipelineLayout layout = VK_NULL_HANDLE;
    VkPipeline pipe = VK_NULL_HANDLE;
    VkDescriptorSetLayout dsl = VK_NULL_HANDLE;
    VkDescriptorPool pool = VK_NULL_HANDLE;
    VkDescriptorSet set = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;

    bool init(VkDevice d, const std::string& spv) {
        dev = d;
        std::ifstream sf(spv, std::ios::binary | std::ios::ate);
        if (!sf) return false;
        std::streamsize sz = sf.tellg(); sf.seekg(0);
        std::vector<char> buf(sz); if (!sf.read(buf.data(), sz)) return false;
        VkShaderModuleCreateInfo smi{}; smi.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
        smi.codeSize = buf.size(); smi.pCode = (const uint32_t*)buf.data();
        if (vkCreateShaderModule(d, &smi, nullptr, &shader) != VK_SUCCESS) return false;
        VkPipelineShaderStageCreateInfo ssi{}; ssi.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        ssi.stage = VK_SHADER_STAGE_COMPUTE_BIT; ssi.module = shader; ssi.pName = "main";
        VkDescriptorSetLayoutBinding b[4] = {};
        b[0].binding=0; b[0].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; b[0].descriptorCount=1; b[0].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
        b[1].binding=1; b[1].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; b[1].descriptorCount=1; b[1].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
        b[2].binding=2; b[2].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; b[2].descriptorCount=1; b[2].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
        b[3].binding=3; b[3].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER; b[3].descriptorCount=1; b[3].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
        VkDescriptorSetLayoutCreateInfo dl{}; dl.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO; dl.bindingCount=4; dl.pBindings=b;
        if (vkCreateDescriptorSetLayout(d,&dl,nullptr,&dsl)!=VK_SUCCESS) return false;
        VkPipelineLayoutCreateInfo pl{}; pl.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO; pl.setLayoutCount=1; pl.pSetLayouts=&dsl;
        if (vkCreatePipelineLayout(d,&pl,nullptr,&layout)!=VK_SUCCESS) return false;
        VkComputePipelineCreateInfo cp{}; cp.sType=VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO; cp.layout=layout; cp.stage=ssi;
        if (vkCreateComputePipelines(d,nullptr,1,&cp,nullptr,&pipe)!=VK_SUCCESS) return false;
        VkDescriptorPoolSize ps[2]={{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,3},{VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,1}};
        VkDescriptorPoolCreateInfo dp{}; dp.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO; dp.maxSets=1; dp.poolSizeCount=2; dp.pPoolSizes=ps;
        if (vkCreateDescriptorPool(d,&dp,nullptr,&pool)!=VK_SUCCESS) return false;
        VkDescriptorSetAllocateInfo da{}; da.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO; da.descriptorPool=pool; da.descriptorSetCount=1; da.pSetLayouts=&dsl;
        if (vkAllocateDescriptorSets(d,&da,&set)!=VK_SUCCESS) return false;
        VkFenceCreateInfo fc{}; fc.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO; vkCreateFence(d,&fc,nullptr,&fence);
        return true;
    }
};

int main(int argc, char** argv) {
    uint32_t rows = argc>1?(uint32_t)std::stoul(argv[1]):64;
    uint32_t cols = argc>2?(uint32_t)std::stoul(argv[2]):1024;
    if(cols%32){std::fprintf(stderr,"cols must be multiple of 32\n");return 1;}
    const uint32_t bpr = cols/32, n_blocks = rows*bpr;

    std::mt19937 rng(42);
    std::vector<uint8_t> q4(n_blocks*18);
    for(auto&x:q4) x=(uint8_t)rng();
    std::vector<float> x(cols);
    for(size_t i=0;i<cols;++i) x[i]=std::sin((double)i)*0.1f;

    // CPU reference.
    std::vector<float> W; DequantizeQ4_0(q4.data(), n_blocks, W);
    std::vector<float> yCpu(rows);
    for(uint32_t r=0;r<rows;++r){float a=0;const float*wr=&W[(size_t)r*cols];for(uint32_t c=0;c<cols;++c)a+=wr[c]*x[c];yCpu[r]=a;}

    deep2::VulkanDevice vk;
    if(!vk.init()||!vk.gpuCount()){std::fprintf(stderr,"no Vulkan GPU\n");return 1;}
    const auto* gpu=vk.primary();
    std::printf("GPU: %s\n", gpu->name.c_str());

    Q4Program prog;
    if(!prog.init(gpu->device, "shaders/q4_0_matvec.spv")){std::fprintf(stderr,"program init failed\n");return 1;}

    // Buffers.
    VkBuffer q4b,xb,yb,db; VkDeviceMemory q4m,xm,ym,dm;
    void *q4p,*xp,*yp,*dp;
    auto mk=[&](VkDeviceSize sz,VkBuffer&b,VkDeviceMemory&m,void*&p){return vk.createBuffer(*gpu,sz,VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,b,m,&p);};
    // dims UBO buffer
    VkDeviceSize q4sz=q4.size(), xsz=cols*sizeof(float), ysz=rows*sizeof(float), dsz=12;
    if(!mk(q4sz,q4b,q4m,q4p)||!mk(xsz,xb,xm,xp)||!mk(ysz,yb,ym,yp)) return 1;
    // dims uniform (separate create with UNIFORM usage)
    VkBufferCreateInfo dbi{};dbi.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;dbi.size=dsz;dbi.usage=VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT;dbi.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    vkCreateBuffer(gpu->device,&dbi,nullptr,&db);VkMemoryRequirements dmr;vkGetBufferMemoryRequirements(gpu->device,db,&dmr);
    const VkPhysicalDeviceMemoryProperties& mp = gpu->memProps;
    uint32_t mt=UINT32_MAX;for(uint32_t i=0;i<mp.memoryTypeCount;++i)if((dmr.memoryTypeBits&(1u<<i))&&(mp.memoryTypes[i].propertyFlags&VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)){mt=i;break;}
    VkMemoryAllocateInfo dai{};dai.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;dai.allocationSize=dmr.size;dai.memoryTypeIndex=mt;
    vkAllocateMemory(gpu->device,&dai,nullptr,&dm);vkBindBufferMemory(gpu->device,db,dm,0);
    uint32_t dims[3]={rows,cols,bpr};void*dp2;vkMapMemory(gpu->device,dm,0,dsz,0,&dp2);std::memcpy(dp2,dims,dsz);vkUnmapMemory(gpu->device,dm);

    std::memcpy(q4p,q4.data(),q4sz);std::memcpy(xp,x.data(),xsz);std::memset(yp,0,ysz);

    // Descriptors.
    VkDescriptorBufferInfo bi[3]={{q4b,0,q4sz},{xb,0,xsz},{yb,0,ysz}};
    VkDescriptorBufferInfo di{db,0,dsz};
    VkWriteDescriptorSet w[4]={};
    for(int i=0;i<3;++i){w[i].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;w[i].dstSet=prog.set;w[i].dstBinding=i;w[i].descriptorCount=1;w[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;w[i].pBufferInfo=&bi[i];}
    w[3].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;w[3].dstSet=prog.set;w[3].dstBinding=3;w[3].descriptorCount=1;w[3].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;w[3].pBufferInfo=&di;
    vkUpdateDescriptorSets(gpu->device,4,w,0,nullptr);

    auto dispatch=[&](){
        VkCommandBufferAllocateInfo ci{};ci.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;ci.commandPool=gpu->pool;ci.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;ci.commandBufferCount=1;
        VkCommandBuffer cb;vkAllocateCommandBuffers(gpu->device,&ci,&cb);
        VkCommandBufferBeginInfo bi{};bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;vkBeginCommandBuffer(cb,&bi);
        vkCmdBindPipeline(cb,VK_PIPELINE_BIND_POINT_COMPUTE,prog.pipe);
        vkCmdBindDescriptorSets(cb,VK_PIPELINE_BIND_POINT_COMPUTE,prog.layout,0,1,&prog.set,0,nullptr);
        vkCmdDispatch(cb,rows,1,1);
        vkEndCommandBuffer(cb);
        VkSubmitInfo si{};si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;si.commandBufferCount=1;si.pCommandBuffers=&cb;
        vkResetFences(gpu->device,1,&prog.fence);
        vkQueueSubmit(gpu->queue,1,&si,prog.fence);
        vkWaitForFences(gpu->device,1,&prog.fence,VK_TRUE,UINT64_MAX);
        vkFreeCommandBuffers(gpu->device,gpu->pool,1,&cb);
    };
    dispatch();
    std::vector<float> y(rows); std::memcpy(y.data(),yp,ysz);
    // Debug: print first few values for small cases.
    if (rows <= 2 && cols <= 128) {
        for (uint32_t r = 0; r < rows; ++r) {
            std::printf("  row %u: y[0]=%g yCpu[0]=%g  y[1]=%g yCpu[1]=%g\n",
                        r, y[r*cols], yCpu[r*cols], y[r*cols+1], yCpu[r*cols+1]);
        }
        // Print block 1's d and first qs (if present).
        if (n_blocks >= 2) {
            uint16_t d1; std::memcpy(&d1, q4.data() + 18, 2);
            std::printf("  block1: d_bits=0x%04x qs[0]=0x%02x\n", d1, q4[20]);
        }
    }
    double maxd=0; for(uint32_t r=0;r<rows;++r) maxd=std::max(maxd,(double)std::fabs(y[r]-yCpu[r]));
    std::printf("RESULT rows=%u cols=%u blocks=%u maxDiff=%g %s\n",rows,cols,n_blocks,maxd,maxd<1e-3?"PASS":"FAIL");
    return maxd<1e-3?0:1;
}