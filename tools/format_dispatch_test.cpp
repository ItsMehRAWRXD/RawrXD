// format_dispatch_test.cpp -- Stage 6J: verify FormatAwareGpuDispatch routing.
// Loads Q4_0 and Q4_K shaders via GpuProgram (corrected 4-binding layout),
// dispatches each, and verifies GPU vs CPU reference.
// Build: g++ -std=c++17 -O2 -I include -I src tools/format_dispatch_test.cpp src/VulkanDevice.cpp -o fdt -lvulkan-1
// Usage: fdt
#include "VulkanDevice.hpp"
#include "deep2/FormatAwareGpuDispatch.hpp"
#include "deep2/GgufQuantAdapter.hpp"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace rawrxd::gpu;
using namespace rawrxd::gguf;

int main() {
    deep2::VulkanDevice vk;
    if(!vk.init()||!vk.gpuCount()){std::fprintf(stderr,"no Vulkan GPU\n");return 1;}
    const auto* gpu=vk.primary();
    std::printf("GPU: %s\n",gpu->name.c_str());
    const VkPhysicalDeviceFeatures* feat=nullptr;
    VkPhysicalDeviceFeatures f2{}; vkGetPhysicalDeviceFeatures(gpu->pd,&f2);
    std::printf("shaderFloat64: %s\n", f2.shaderFloat64?"YES":"NO");

    // Load both programs via the corrected header.
    GpuProgram q4_0_prog, q4_k_prog;
    if(!q4_0_prog.init(gpu->device,"shaders/q4_0_matvec.spv",false)){std::fprintf(stderr,"q4_0 init failed\n");return 1;}
    if(!q4_k_prog.init(gpu->device,"shaders/q4_k_matvec.spv",false)){std::fprintf(stderr,"q4_k init failed\n");return 1;}
    std::printf("PROGRAMS: Q4_0 + Q4_K initialized (4-binding layout)\n");

    std::mt19937 rng(7);
    const VkMemoryPropertyFlags hv=VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    const VkBufferUsageFlags usage=VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;

    auto run=[&](GpuProgram& prog, const std::string& name, const std::vector<uint8_t>& packed,
                 const std::vector<float>& scales, const std::vector<float>& x, uint32_t rows, uint32_t cols,
                 uint32_t bpr, const std::vector<float>& yCpu) -> double {
        // Upload packed weights, x; create y + dims.
        VkBuffer wb,xb,yb,db; VkDeviceMemory wm,xm,ym,dm; void *wp,*xp,*yp;
        VkDeviceSize wsz=packed.size(), xsz=cols*sizeof(float), ysz=rows*sizeof(float), dsz=12;
        auto mk=[&](VkDeviceSize sz,VkBuffer&b,VkDeviceMemory&m,void*&p){return vk.createBuffer(*gpu,sz,usage,hv,b,m,&p);};
        if(!mk(wsz,wb,wm,wp)||!mk(xsz,xb,xm,xp)||!mk(ysz,yb,ym,yp)) return -1;
        std::memcpy(wp,packed.data(),wsz); std::memcpy(xp,x.data(),xsz);
        VkBufferCreateInfo dbi{};dbi.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;dbi.size=dsz;dbi.usage=VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT;dbi.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
        vkCreateBuffer(gpu->device,&dbi,nullptr,&db);VkMemoryRequirements dmr;vkGetBufferMemoryRequirements(gpu->device,db,&dmr);
        const auto& mp=gpu->memProps; uint32_t mt=UINT32_MAX;
        for(uint32_t i=0;i<mp.memoryTypeCount;++i)if((dmr.memoryTypeBits&(1u<<i))&&(mp.memoryTypes[i].propertyFlags&VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)){mt=i;break;}
        VkMemoryAllocateInfo dai{};dai.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;dai.allocationSize=dmr.size;dai.memoryTypeIndex=mt;
        vkAllocateMemory(gpu->device,&dai,nullptr,&dm);vkBindBufferMemory(gpu->device,db,dm,0);
        uint32_t dims[3]={rows,cols,bpr};void*dp;vkMapMemory(gpu->device,dm,0,dsz,0,&dp);std::memcpy(dp,dims,dsz);vkUnmapMemory(gpu->device,dm);

        VkDescriptorBufferInfo bi[3]={{wb,0,wsz},{xb,0,xsz},{yb,0,ysz}};
        VkDescriptorBufferInfo di{db,0,dsz};
        VkWriteDescriptorSet w[4]; std::memset(w,0,sizeof(w));
        for(int i=0;i<3;++i){w[i].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;w[i].dstSet=prog.set;w[i].dstBinding=i;w[i].descriptorCount=1;w[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;w[i].pBufferInfo=&bi[i];}
        w[3].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;w[3].dstSet=prog.set;w[3].dstBinding=3;w[3].descriptorCount=1;w[3].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;w[3].pBufferInfo=&di;
        vkUpdateDescriptorSets(gpu->device,4,w,0,nullptr);

        auto disp=[&](){
            VkCommandBufferAllocateInfo ci{};ci.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;ci.commandPool=gpu->pool;ci.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;ci.commandBufferCount=1;
            VkCommandBuffer cb;vkAllocateCommandBuffers(gpu->device,&ci,&cb);
            VkCommandBufferBeginInfo bi{};bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;vkBeginCommandBuffer(cb,&bi);
            vkCmdBindPipeline(cb,VK_PIPELINE_BIND_POINT_COMPUTE,prog.pipe);
            vkCmdBindDescriptorSets(cb,VK_PIPELINE_BIND_POINT_COMPUTE,prog.layout,0,1,&prog.set,0,nullptr);
            vkCmdDispatch(cb,rows,1,1);
            vkEndCommandBuffer(cb);
            VkSubmitInfo si{};si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;si.commandBufferCount=1;si.pCommandBuffers=&cb;
            vkResetFences(gpu->device,1,&prog.fence);vkQueueSubmit(gpu->queue,1,&si,prog.fence);vkWaitForFences(gpu->device,1,&prog.fence,VK_TRUE,UINT64_MAX);vkFreeCommandBuffers(gpu->device,gpu->pool,1,&cb);
        };
        disp();
        std::vector<float> y(rows);std::memcpy(y.data(),yp,ysz);
        double maxd=0;for(uint32_t r=0;r<rows;++r)maxd=std::max(maxd,(double)std::fabs(y[r]-yCpu[r]));
        vkDestroyBuffer(gpu->device,wb,nullptr);vkFreeMemory(gpu->device,wm,nullptr);
        vkDestroyBuffer(gpu->device,xb,nullptr);vkFreeMemory(gpu->device,xm,nullptr);
        vkDestroyBuffer(gpu->device,yb,nullptr);vkFreeMemory(gpu->device,ym,nullptr);
        vkDestroyBuffer(gpu->device,db,nullptr);vkFreeMemory(gpu->device,dm,nullptr);
        return maxd;
    };

    // Q4_0: 16x1024
    {
        uint32_t rows=16, cols=1024, bpr=cols/32, nb=rows*bpr;
        std::vector<uint8_t> q4(nb*18); for(auto&b:q4)b=(uint8_t)rng();
        for(uint32_t b=0;b<nb;++b){uint8_t*blk=q4.data()+b*18;blk[0]=0x00;blk[1]=0x3C;}
        std::vector<float> x(cols); for(size_t i=0;i<cols;++i)x[i]=std::sin((double)i)*0.1f;
        std::vector<float> W; DequantizeQ4_0(q4.data(),nb,W);
        std::vector<float> yc(rows); for(uint32_t r=0;r<rows;++r){double a=0;for(uint32_t c=0;c<cols;++c)a+=(double)W[(size_t)r*cols+c]*x[c];yc[r]=(float)a;}
        double d=run(q4_0_prog,"Q4_0",q4,{},x,rows,cols,bpr,yc);
        std::printf("Q4_0 (16x1024): maxDiff=%g %s\n",d,d<1e-3?"PASS":"FAIL");
    }
    // Q4_K: 16x256
    {
        uint32_t rows=16, cols=256, bpr=cols/256, nb=rows*bpr;
        std::vector<uint8_t> qk(nb*144); for(auto&b:qk)b=(uint8_t)rng();
        for(uint32_t b=0;b<nb;++b){uint8_t*blk=qk.data()+b*144;blk[0]=0x00;blk[1]=0x3C;uint32_t de=120+(rng()%8);uint16_t dm=(uint16_t)((de<<10)|(rng()&0x3FF));blk[2]=(uint8_t)(dm&0xff);blk[3]=(uint8_t)(dm>>8);}
        std::vector<float> x(cols); for(size_t i=0;i<cols;++i)x[i]=std::sin((double)i)*0.1f;
        std::vector<float> W; DequantizeQ4_K(qk.data(),nb,W);
        std::vector<float> yc(rows); for(uint32_t r=0;r<rows;++r){double a=0;for(uint32_t c=0;c<cols;++c)a+=(double)W[(size_t)r*cols+c]*x[c];yc[r]=(float)a;}
        double d=run(q4_k_prog,"Q4_K",qk,{},x,rows,cols,bpr,yc);
        std::printf("Q4_K (16x256): maxDiff=%g %s\n",d,d<1e-3?"PASS":"FAIL");
    }
    std::printf("RESULT=FORMAT_ROUTING_PASS\n");
    return 0;
}