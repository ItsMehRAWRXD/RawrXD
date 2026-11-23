// q4_k_gpu_test.cpp -- Stage 6I: native Q4_K GPU execution. Uploads Q4_K
// superblocks DIRECTLY (no F32 intermediate), dispatches q4_k_matvec.comp, and
// compares GPU output against the ggml CPU reference dequant + matvec.
// Build: g++ -std=c++17 -O2 -I include -I src tools/q4_k_gpu_test.cpp src/VulkanDevice.cpp -o q4k -lvulkan-1
// Usage: q4k [rows=16] [cols=256]
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

struct Q4KProgram {
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
        VkShaderModuleCreateInfo smi{}; smi.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO; smi.codeSize=buf.size(); smi.pCode=(const uint32_t*)buf.data();
        if (vkCreateShaderModule(d,&smi,nullptr,&shader)!=VK_SUCCESS) return false;
        VkPipelineShaderStageCreateInfo ssi{}; ssi.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO; ssi.stage=VK_SHADER_STAGE_COMPUTE_BIT; ssi.module=shader; ssi.pName="main";
        VkDescriptorSetLayoutBinding b[4]; std::memset(b,0,sizeof(b));
        b[0].binding=0;b[0].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;b[0].descriptorCount=1;b[0].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
        b[1].binding=1;b[1].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;b[1].descriptorCount=1;b[1].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
        b[2].binding=2;b[2].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;b[2].descriptorCount=1;b[2].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
        b[3].binding=3;b[3].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;b[3].descriptorCount=1;b[3].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
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
    uint32_t rows = argc>1?(uint32_t)std::stoul(argv[1]):16;
    uint32_t cols = argc>2?(uint32_t)std::stoul(argv[2]):256;
    if(cols%256){std::fprintf(stderr,"cols must be multiple of 256\n");return 1;}
    const uint32_t bpr=cols/256, n_blocks=rows*bpr;

    std::mt19937 rng(123);
    std::vector<uint8_t> q4k(n_blocks*144);
    for(auto&x:q4k) x=(uint8_t)rng();
    // Controlled d=1.0, dmin=0.0 for predictable math.
    for(uint32_t b=0;b<n_blocks;++b){ uint8_t* blk=q4k.data()+b*144; blk[0]=0x00;blk[1]=0x3C; blk[2]=0x00;blk[3]=0x00; }
    std::vector<float> x(cols);
    for(size_t i=0;i<cols;++i) x[i]=std::sin((double)i)*0.1f;

    std::vector<float> W; DequantizeQ4_K(q4k.data(), n_blocks, W);
    std::vector<float> yCpu(rows);
    for(uint32_t r=0;r<rows;++r){float a=0;const float*wr=&W[(size_t)r*cols];for(uint32_t c=0;c<cols;++c)a+=wr[c]*x[c];yCpu[r]=a;}

    deep2::VulkanDevice vk;
    if(!vk.init()||!vk.gpuCount()){std::fprintf(stderr,"no Vulkan GPU\n");return 1;}
    const auto* gpu=vk.primary();
    std::printf("GPU: %s\n",gpu->name.c_str());

    Q4KProgram prog;
    if(!prog.init(gpu->device,"shaders/q4_k_matvec.spv")){std::fprintf(stderr,"program init failed\n");return 1;}

    VkBuffer qb,xb,yb,db; VkDeviceMemory qm,xm,ym,dm;
    void *qp,*xp,*yp;
    auto mk=[&](VkDeviceSize sz,VkBuffer&b,VkDeviceMemory&m,void*&p){return vk.createBuffer(*gpu,sz,VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,b,m,&p);};
    VkDeviceSize qsz=q4k.size(), xsz=cols*sizeof(float), ysz=rows*sizeof(float), dsz=12;
    if(!mk(qsz,qb,qm,qp)||!mk(xsz,xb,xm,xp)||!mk(ysz,yb,ym,yp)) return 1;
    VkBufferCreateInfo dbi{};dbi.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;dbi.size=dsz;dbi.usage=VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT;dbi.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    vkCreateBuffer(gpu->device,&dbi,nullptr,&db);VkMemoryRequirements dmr;vkGetBufferMemoryRequirements(gpu->device,db,&dmr);
    const VkPhysicalDeviceMemoryProperties& mp=gpu->memProps;
    uint32_t mt=UINT32_MAX;for(uint32_t i=0;i<mp.memoryTypeCount;++i)if((dmr.memoryTypeBits&(1u<<i))&&(mp.memoryTypes[i].propertyFlags&VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)){mt=i;break;}
    VkMemoryAllocateInfo dai{};dai.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;dai.allocationSize=dmr.size;dai.memoryTypeIndex=mt;
    vkAllocateMemory(gpu->device,&dai,nullptr,&dm);vkBindBufferMemory(gpu->device,db,dm,0);
    uint32_t dims[3]={rows,cols,bpr};void*dp;vkMapMemory(gpu->device,dm,0,dsz,0,&dp);std::memcpy(dp,dims,dsz);vkUnmapMemory(gpu->device,dm);

    std::memcpy(qp,q4k.data(),qsz);std::memcpy(xp,x.data(),xsz);std::memset(yp,0,ysz);

    VkDescriptorBufferInfo bi[3]={{qb,0,qsz},{xb,0,xsz},{yb,0,ysz}};
    VkDescriptorBufferInfo di{db,0,dsz};
    VkWriteDescriptorSet w[4]; std::memset(w,0,sizeof(w));
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
    if(rows<=4){ for(uint32_t r=0;r<rows;++r) std::printf("  row %u: GPU=%g CPU=%g diff=%g\n",r,y[r],yCpu[r],(double)y[r]-(double)yCpu[r]); }
    double maxd=0; for(uint32_t r=0;r<rows;++r) maxd=std::max(maxd,(double)std::fabs(y[r]-yCpu[r]));
    std::printf("RESULT rows=%u cols=%u blocks=%u maxDiff=%g %s\n",rows,cols,n_blocks,maxd,maxd<1e-3?"PASS":"FAIL");
    return maxd<1e-3?0:1;
}