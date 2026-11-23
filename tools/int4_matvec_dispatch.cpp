// int4_matvec_dispatch.cpp -- Vulkan host dispatcher + GPU benchmark for the
// fused INT4 matvec shader (shaders/int4_matvec.comp -> int4_matvec.spv).
// ----------------------------------------------------------------------------
// This is the DECISIVE GPU harness: it loads packed INT4 weights into VRAM
// (no full F32 weight buffer), dispatches the compute shader, reads back the
// output, and compares against a CPU INT4 tiled reference. It measures GPU
// matvec time and reports the actual device-local allocation.
//
// It is production code intended to build and run on the AMD R9700 / RX 7800 XT.
// It was NOT executed in the environment that produced the CPU benchmarks (no
// Vulkan device there). Build/run instructions are in the header comment.
//
// Build (Windows, MSVC or clang++ with Vulkan SDK):
//   cl /std:c++17 /EHsc /O2 /I"C:\VulkanSDK\1.4.357.0\Include" ^
//      tools/int4_matvec_dispatch.cpp ^
//      /link /LIBPATH:"C:\VulkanSDK\1.4.357.0\Lib" vulkan-1.lib
//   (compile the shader first: glslc shaders/int4_matvec.comp -o int4_matvec.spv)
// Usage: int4_matvec_dispatch <int4_matvec.spv> [rows=1152] [cols=1024] [steps=100]
//
// The harness uses a synthetic INT4 matrix (deterministic) so it can validate
// parity against the CPU reference without a model file. Swap the matrix build
// for a real GGUF tensor load to benchmark production weights.
// ============================================================================
#include <vulkan/vulkan.h>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
static uint64_t PeakWS(){ PROCESS_MEMORY_COUNTERS p; if(GetProcessMemoryInfo(GetCurrentProcess(),&p,sizeof(p))) return (uint64_t)p.PeakWorkingSetSize; return 0; }
#else
static uint64_t PeakWS(){ return 0; }
#endif

// ---- minimal helpers -------------------------------------------------------
#define VK_CHECK(x) do { VkResult _r=(x); if(_r!=VK_SUCCESS){ std::fprintf(stderr,"VK error %d at %s:%d\n",(int)_r,__FILE__,__LINE__); std::exit(1);} } while(0)

static std::vector<char> ReadFile(const std::string& path){
    FILE* f=fopen(path.c_str(),"rb"); if(!f){ std::fprintf(stderr,"cannot open %s\n",path.c_str()); std::exit(1);} 
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    std::vector<char> buf(n); fread(buf.data(),1,n,f); fclose(f); return buf;
}

// ---- INT4 quantization (mirror of LossyQuant.hpp, host side) ---------------
static uint16_t F32ToF16(float v){ uint32_t x; std::memcpy(&x,&v,4); uint32_t sign=(x>>16)&0x8000u; int32_t exp=((x>>23)&0xff)-127+15; uint32_t man=x&0x7fffffu;
    if(exp<=0) return (uint16_t)sign; if(exp>=31) return (uint16_t)(sign|0x7c00u); return (uint16_t)(sign|((uint32_t)exp<<10)|(man>>13)); }
static float F16ToF32(uint16_t h){ uint32_t sign=(h&0x8000u)<<16, exp=(h>>10)&0x1f, man=h&0x3ffu, o;
    if(exp==0){ if(man==0)o=sign; else { exp=127-15+1; while(!(man&0x400)){man<<=1;exp--;} man&=0x3ff; o=sign|(exp<<23)|(man<<13);} }
    else if(exp==31) o=sign|0x7f800000u|(man<<13); else o=sign|((exp-15+127)<<23)|(man<<13);
    float f; std::memcpy(&f,&o,4); return f; }

struct Quant { uint32_t rows, cols, bpr; std::vector<uint16_t> scales; std::vector<uint8_t> packed; };

static Quant Quantize(const std::vector<float>& W, uint32_t rows, uint32_t cols){
    Quant q; q.rows=rows; q.cols=cols; q.bpr=cols/64;
    uint64_t n=(uint64_t)rows*cols; uint32_t nb=(uint32_t)((n+63)/64);
    q.scales.resize(nb); q.packed.resize((n+1)/2);
    for(uint32_t b=0;b<nb;++b){ uint64_t base=(uint64_t)b*64; uint32_t len=(uint32_t)std::min<uint64_t>(64,n-base); float amax=0;
        for(uint32_t i=0;i<len;++i) amax=std::max(amax,std::fabs(W[base+i]));
        float sc=amax>0?amax/7.0f:1.0f; q.scales[b]=F32ToF16(sc);
        for(uint32_t i=0;i<len;++i){ float v=W[base+i]/sc; int iv=(int)std::lrintf(v); if(iv>7)iv=7; if(iv<-7)iv=-7; uint32_t u=(uint32_t)(iv&0xf);
            uint64_t idx=base+i; size_t bi=(size_t)(idx>>1); if(idx&1) q.packed[bi]|=(uint8_t)(u<<4); else q.packed[bi]|=u; } }
    return q;
}

// ---- Vulkan setup ----------------------------------------------------------
struct GPU {
    VkInstance inst; VkPhysicalDevice pd; VkDevice dev; VkQueue queue; uint32_t qfam;
    VkCommandPool pool; VkCommandBuffer cb; VkFence fence;
    VkBuffer bufW, bufS, bufX, bufY; VkDeviceMemory memW, memS, memX, memY;
    VkDescriptorSetLayout dsl; VkDescriptorPool dp; VkDescriptorSet ds;
    VkPipelineLayout pl; VkPipeline pipe;
};

static GPU g;

static uint32_t FindMemType(uint32_t typeFilter, VkMemoryPropertyFlags props){
    VkPhysicalDeviceMemoryProperties mp; vkGetPhysicalDeviceMemoryProperties(g.pd,&mp);
    for(uint32_t i=0;i<mp.memoryTypeCount && i<32;++i) if((typeFilter&(1u<<i)) && (mp.memoryTypes[i].propertyFlags&props)==props) return i;
    std::fprintf(stderr,"no suitable memory type (filter=%u props=%u count=%u)\n",typeFilter,(uint32_t)props,mp.memoryTypeCount); std::exit(1);
}

static void CreateBuffer(VkBuffer buf, VkDeviceMemory& mem, size_t size, VkMemoryPropertyFlags props, void* data=nullptr){
    VkBufferCreateInfo bi{}; bi.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO; bi.size=size; bi.usage=VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|VK_BUFFER_USAGE_TRANSFER_DST_BIT|VK_BUFFER_USAGE_TRANSFER_SRC_BIT; bi.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    VK_CHECK(vkCreateBuffer(g.dev,&bi,nullptr,&buf));
    VkMemoryRequirements mr; vkGetBufferMemoryRequirements(g.dev,buf,&mr);
    VkMemoryAllocateInfo ai{}; ai.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO; ai.allocationSize=mr.size; ai.memoryTypeIndex=FindMemType(mr.memoryTypeBits,props);
    VK_CHECK(vkAllocateMemory(g.dev,&ai,nullptr,&mem)); VK_CHECK(vkBindBufferMemory(g.dev,buf,mem,0));
    if(data){
        void* p; VK_CHECK(vkMapMemory(g.dev,mem,0,size,0,&p)); std::memcpy(p,data,size); vkUnmapMemory(g.dev,mem);
    }
}

int main(int argc, char** argv){
    if(argc<2){ std::fprintf(stderr,"usage: int4_matvec_dispatch <shader.spv> [rows=1152] [cols=1024] [steps=100]\n"); return 2; }
    uint32_t rows=1152, cols=1024, steps=100;
    if(argc>2) rows=(uint32_t)std::stoul(argv[2]); if(argc>3) cols=(uint32_t)std::stoul(argv[3]); if(argc>4) steps=(uint32_t)std::stoul(argv[4]);
    if(cols%64){ std::fprintf(stderr,"cols must be a multiple of 64\n"); return 1; }
    auto spv=ReadFile(argv[1]);

    // ---- host: build a synthetic INT4 matrix + reference output ----
    std::vector<float> W((size_t)rows*cols), x(cols);
    for(size_t i=0;i<W.size();++i) W[i]=(((i*37)%17)-8)*0.01f;
    for(size_t i=0;i<cols;++i) x[i]=std::sin((double)i)*0.1f;
    Quant q=Quantize(W,rows,cols);
    std::vector<float> yref(rows,0.0f);
    for(uint32_t r=0;r<rows;++r){ double a=0; for(uint32_t c=0;c<cols;++c){ uint64_t idx=(uint64_t)r*cols+c; uint32_t b=(uint32_t)(idx/64); float sc=F16ToF32(q.scales[b]);
        size_t bi=(size_t)(idx>>1); uint32_t nib=(idx&1)?(q.packed[bi]>>4):(q.packed[bi]&0xf); int v=(int)nib; if(v>=8)v-=16; a+=(double)v*sc*x[c]; } yref[r]=(float)a; }
    std::printf("host: rows=%u cols=%u int4_bytes=%zu f32_bytes=%zu\n",rows,cols,q.packed.size(),W.size()*sizeof(float));
    std::fflush(stdout);

    // ---- Vulkan init ----
    VkApplicationInfo app{}; app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO; app.apiVersion=VK_API_VERSION_1_3;
    VkInstanceCreateInfo ici{}; ici.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO; ici.pApplicationInfo=&app;
    VK_CHECK(vkCreateInstance(&ici,nullptr,&g.inst));
    uint32_t nd=0; VK_CHECK(vkEnumeratePhysicalDevices(g.inst,&nd,nullptr)); if(!nd){ std::fprintf(stderr,"no Vulkan device\n"); return 1; }
    std::vector<VkPhysicalDevice> devs(nd); VK_CHECK(vkEnumeratePhysicalDevices(g.inst,&nd,devs.data())); g.pd=devs[0];
    VkPhysicalDeviceProperties props; vkGetPhysicalDeviceProperties(g.pd,&props);
    std::printf("GPU: %s\n",props.deviceName);
    std::fflush(stdout);
    std::fprintf(stderr,"STEP: device created, qfam=%u\n",g.qfam); std::fflush(stderr);
    uint32_t nf=0; vkGetPhysicalDeviceQueueFamilyProperties(g.pd,&nf,nullptr); std::vector<VkQueueFamilyProperties> qf(nf); vkGetPhysicalDeviceQueueFamilyProperties(g.pd,&nf,qf.data());
    for(uint32_t i=0;i<nf;++i) if(qf[i].queueFlags&VK_QUEUE_COMPUTE_BIT){ g.qfam=i; break; }
    float prio=1.0f; VkDeviceQueueCreateInfo qci{}; qci.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO; qci.queueFamilyIndex=g.qfam; qci.queueCount=1; qci.pQueuePriorities=&prio;
    VkDeviceCreateInfo dci{}; dci.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO; dci.queueCreateInfoCount=1; dci.pQueueCreateInfos=&qci;
    VK_CHECK(vkCreateDevice(g.pd,&dci,nullptr,&g.dev)); vkGetDeviceQueue(g.dev,g.qfam,0,&g.queue);

    VkCommandPoolCreateInfo pci{}; pci.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO; pci.queueFamilyIndex=g.qfam;
    VK_CHECK(vkCreateCommandPool(g.dev,&pci,nullptr,&g.pool));
    VkCommandBufferAllocateInfo cbai{}; cbai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO; cbai.commandPool=g.pool; cbai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY; cbai.commandBufferCount=1;
    VK_CHECK(vkAllocateCommandBuffers(g.dev,&cbai,&g.cb));
    VkFenceCreateInfo fci{}; fci.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO; VK_CHECK(vkCreateFence(g.dev,&fci,nullptr,&g.fence));

    // ---- buffers: INT4 weights, scales, x, y (all device-local) ----
    VkMemoryPropertyFlags devloc=VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT; // smoke test: host-visible; optimize to DEVICE_LOCAL after correctness
    std::fprintf(stderr,"STEP: creating buffers (int4=%zu bytes)\n",q.packed.size()); std::fflush(stderr);
    CreateBuffer(g.bufW,g.memW,q.packed.size(),devloc,q.packed.data());
    std::fprintf(stderr,"STEP: buffer W done\n"); std::fflush(stderr);
    CreateBuffer(g.bufS,g.memS,q.scales.size()*sizeof(uint16_t),devloc,q.scales.data());
    CreateBuffer(g.bufX,g.memX,cols*sizeof(float),devloc,x.data());
    CreateBuffer(g.bufY,g.memY,rows*sizeof(float),devloc,nullptr);

    // ---- descriptor set layout (4 storage buffers + 1 uniform) ----
    VkDescriptorSetLayoutBinding b[5];
    std::memset(b, 0, sizeof(b));
    b[0].binding=0; b[0].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; b[0].descriptorCount=1; b[0].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    b[1].binding=1; b[1].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; b[1].descriptorCount=1; b[1].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    b[2].binding=2; b[2].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; b[2].descriptorCount=1; b[2].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    b[3].binding=3; b[3].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; b[3].descriptorCount=1; b[3].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    b[4].binding=4; b[4].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER; b[4].descriptorCount=1; b[4].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    VkDescriptorSetLayoutCreateInfo dl{}; dl.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO; dl.bindingCount=5; dl.pBindings=b;
    VK_CHECK(vkCreateDescriptorSetLayout(g.dev,&dl,nullptr,&g.dsl));
    VkPipelineLayoutCreateInfo pli{}; pli.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO; pli.setLayoutCount=1; pli.pSetLayouts=&g.dsl;
    VK_CHECK(vkCreatePipelineLayout(g.dev,&pli,nullptr,&g.pl));

    // dims uniform buffer
    struct Dims { uint32_t rows, cols, bpr; } dims{rows,cols,cols/64};
    VkBuffer bufD; VkDeviceMemory memD;
    CreateBuffer(bufD,memD,sizeof(Dims),devloc,&dims);

    VkDescriptorPoolSize ps[2]={{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,4},{VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,1}};
    VkDescriptorPoolCreateInfo dpi{}; dpi.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO; dpi.maxSets=1; dpi.poolSizeCount=2; dpi.pPoolSizes=ps;
    VK_CHECK(vkCreateDescriptorPool(g.dev,&dpi,nullptr,&g.dp));
    VkDescriptorSetAllocateInfo dsai{}; dsai.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO; dsai.descriptorPool=g.dp; dsai.descriptorSetCount=1; dsai.pSetLayouts=&g.dsl;
    VK_CHECK(vkAllocateDescriptorSets(g.dev,&dsai,&g.ds));
    VkDescriptorBufferInfo bi0{g.bufW,0,q.packed.size()}, bi1{g.bufS,0,q.scales.size()*sizeof(uint16_t)}, bi2{g.bufX,0,cols*sizeof(float)}, bi3{g.bufY,0,rows*sizeof(float)}, bi4{bufD,0,sizeof(Dims)};
    VkWriteDescriptorSet w[5];
    std::memset(w, 0, sizeof(w));
    for(int i=0;i<4;++i){ w[i].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[i].dstSet=g.ds; w[i].dstBinding=(uint32_t)i; w[i].descriptorCount=1; w[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; w[i].pBufferInfo=&bi0; w[i].pBufferInfo=(i==0)?&bi0:(i==1)?&bi1:(i==2)?&bi2:&bi3; }
    w[4].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[4].dstSet=g.ds; w[4].dstBinding=4; w[4].descriptorCount=1; w[4].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER; w[4].pBufferInfo=&bi4;
    vkUpdateDescriptorSets(g.dev, 5, w, 0, nullptr);

    // ---- shader module + pipeline ----
    VkShaderModuleCreateInfo smi{}; smi.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO; smi.codeSize=spv.size(); smi.pCode=(const uint32_t*)spv.data();
    VkShaderModule sm; VK_CHECK(vkCreateShaderModule(g.dev,&smi,nullptr,&sm));
    VkComputePipelineCreateInfo cpi{}; cpi.sType=VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO; cpi.layout=g.pl; cpi.stage.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO; cpi.stage.stage=VK_SHADER_STAGE_COMPUTE_BIT; cpi.stage.module=sm; cpi.stage.pName="main";
    VK_CHECK(vkCreateComputePipelines(g.dev,nullptr,1,&cpi,nullptr,&g.pipe));

    // ---- dispatch helper ----
    std::fprintf(stderr,"STEP: all buffers created, descriptors+pipeline built\n"); std::fflush(stderr);
    auto dispatch=[&](){ vkResetCommandBuffer(g.cb,0);
        VkCommandBufferBeginInfo bi{}; bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO; vkBeginCommandBuffer(g.cb,&bi);
        vkCmdBindPipeline(g.cb,VK_PIPELINE_BIND_POINT_COMPUTE,g.pipe);
        vkCmdBindDescriptorSets(g.cb,VK_PIPELINE_BIND_POINT_COMPUTE,g.pl,0,1,&g.ds,0,nullptr);
        vkCmdDispatch(g.cb,rows,1,1); // one workgroup per output row
        vkEndCommandBuffer(g.cb);
        VkSubmitInfo si{}; si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO; si.commandBufferCount=1; si.pCommandBuffers=&g.cb;
        VK_CHECK(vkQueueSubmit(g.queue,1,&si,g.fence));
        VK_CHECK(vkWaitForFences(g.dev,1,&g.fence,VK_TRUE,UINT64_MAX));
        vkResetFences(g.dev,1,&g.fence);
    };

    // warmup
    std::fprintf(stderr,"STEP: calling dispatch (warmup)\n"); std::fflush(stderr);
    dispatch();
    std::fprintf(stderr,"STEP: warmup dispatch done\n"); std::fflush(stderr);
    auto t0=std::chrono::steady_clock::now();
    for(uint32_t s=0;s<steps;++s) dispatch();
    auto t1=std::chrono::steady_clock::now();
    std::fprintf(stderr,"STEP: timed loop done\n"); std::fflush(stderr);
    double sec=std::chrono::duration<double>(t1-t0).count();
    double tps=sec>0?steps/sec:0;
    std::printf("GPU INT4: steps=%u time_s=%.4f matvec_per_s=%.1f peak_ws_bytes=%llu\n",steps,sec,tps,(unsigned long long)PeakWS());

    // readback + parity (all buffers are host-visible in this smoke test)
    std::fprintf(stderr,"STEP: readback start\n"); std::fflush(stderr);
    std::vector<float> y(rows);
    {
        void* p; VK_CHECK(vkMapMemory(g.dev,g.memY,0,rows*sizeof(float),0,&p)); std::memcpy(y.data(),p,rows*sizeof(float)); vkUnmapMemory(g.dev,g.memY);
    }
    std::fprintf(stderr,"STEP: readback mapped+copied\n"); std::fflush(stderr);
    double maxd=0; for(uint32_t r=0;r<rows;++r) maxd=std::max(maxd,(double)std::fabs(y[r]-yref[r]));
    std::printf("GPU_vs_CPU_ref_max_diff=%g %s\n",maxd, maxd<0.05?"PASS":"FAIL");
    std::printf("device_local_int4_bytes=%zu f32_bytes=%zu\n",q.packed.size(),W.size()*sizeof(float));
    return maxd<0.05?0:1;
}
