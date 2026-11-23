// f32_matvec_dispatch.cpp -- GPU F32 baseline matvec on the same device/shape
// as the INT4 dispatcher, for throughput comparison. Minimal Vulkan harness.
// Build: g++ -std=c++17 -O2 -I"<vulkan>/Include" tools/f32_matvec_dispatch.cpp -L"<vulkan>/Lib" -lvulkan-1 -o f32disp
// Usage: f32_matvec_dispatch <f32_matvec.spv> [rows=1152] [cols=1024] [steps=100]
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
#define VK_CHECK(x) do { VkResult _r=(x); if(_r!=VK_SUCCESS){ std::fprintf(stderr,"VK error %d at %d\n",(int)_r,__LINE__); std::exit(1);} } while(0)
static std::vector<char> ReadFile(const std::string& p){ FILE* f=fopen(p.c_str(),"rb"); if(!f){std::fprintf(stderr,"cannot open %s\n",p.c_str());std::exit(1);} fseek(f,0,SEEK_END);long n=ftell(f);fseek(f,0,SEEK_SET);std::vector<char> b(n);fread(b.data(),1,n,f);fclose(f);return b; }

struct GPU { VkInstance inst; VkPhysicalDevice pd; VkDevice dev; VkQueue q; uint32_t qfam; VkCommandPool pool; VkCommandBuffer cb; VkFence fence; VkDescriptorSetLayout dsl; VkDescriptorPool dp; VkDescriptorSet ds; VkPipelineLayout pl; VkPipeline pipe; };
static GPU g;
static uint32_t FindMem(uint32_t f, VkMemoryPropertyFlags p){ VkPhysicalDeviceMemoryProperties m; vkGetPhysicalDeviceMemoryProperties(g.pd,&m); for(uint32_t i=0;i<m.memoryTypeCount&&i<32;++i) if((f&(1u<<i))&&(m.memoryTypes[i].propertyFlags&p)==p) return i; std::fprintf(stderr,"no mem type\n");std::exit(1); }
static void Buf(VkBuffer& b, VkDeviceMemory& m, size_t sz, VkMemoryPropertyFlags p, void* d=nullptr){ VkBufferCreateInfo bi{};bi.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;bi.size=sz;bi.usage=VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;bi.sharingMode=VK_SHARING_MODE_EXCLUSIVE;VK_CHECK(vkCreateBuffer(g.dev,&bi,nullptr,&b));VkMemoryRequirements r;vkGetBufferMemoryRequirements(g.dev,b,&r);VkMemoryAllocateInfo ai{};ai.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;ai.allocationSize=r.size;ai.memoryTypeIndex=FindMem(r.memoryTypeBits,p);VK_CHECK(vkAllocateMemory(g.dev,&ai,nullptr,&m));VK_CHECK(vkBindBufferMemory(g.dev,b,m,0));if(d){void* q;VK_CHECK(vkMapMemory(g.dev,m,0,sz,0,&q));std::memcpy(q,d,sz);vkUnmapMemory(g.dev,m);} }

int main(int argc,char**argv){
    if(argc<2){std::fprintf(stderr,"usage: f32 <shader.spv> [rows=1152] [cols=1024] [steps=100]\n");return 2;}
    uint32_t rows=1152,cols=1024,steps=100;
    if(argc>2)rows=(uint32_t)std::stoul(argv[2]); if(argc>3)cols=(uint32_t)std::stoul(argv[3]); if(argc>4)steps=(uint32_t)std::stoul(argv[4]);
    if(cols%64){std::fprintf(stderr,"cols must be multiple of 64\n");return 1;}
    auto spv=ReadFile(argv[1]);
    std::vector<float> W((size_t)rows*cols), x(cols);
    for(size_t i=0;i<W.size();++i)W[i]=(((int)(i*37)%17)-8)*0.01f;
    for(size_t i=0;i<cols;++i)x[i]=std::sin((double)i)*0.1f;
    std::vector<float> yref(rows);
    for(uint32_t r=0;r<rows;++r){double a=0;for(uint32_t c=0;c<cols;++c)a+=(double)W[(size_t)r*cols+c]*x[c];yref[r]=(float)a;}
    std::printf("host F32: rows=%u cols=%u f32_bytes=%zu\n",rows,cols,W.size()*sizeof(float));std::fflush(stdout);

    VkApplicationInfo app{};app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;app.apiVersion=VK_API_VERSION_1_3;
    VkInstanceCreateInfo ici{};ici.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;ici.pApplicationInfo=&app;VK_CHECK(vkCreateInstance(&ici,nullptr,&g.inst));
    uint32_t nd=0;VK_CHECK(vkEnumeratePhysicalDevices(g.inst,&nd,nullptr));if(!nd)return 1;std::vector<VkPhysicalDevice> ds(nd);VK_CHECK(vkEnumeratePhysicalDevices(g.inst,&nd,ds.data()));g.pd=ds[0];
    VkPhysicalDeviceProperties pr;vkGetPhysicalDeviceProperties(g.pd,&pr);std::printf("GPU: %s\n",pr.deviceName);std::fflush(stdout);
    uint32_t nf=0;vkGetPhysicalDeviceQueueFamilyProperties(g.pd,&nf,nullptr);std::vector<VkQueueFamilyProperties> qf(nf);vkGetPhysicalDeviceQueueFamilyProperties(g.pd,&nf,qf.data());
    for(uint32_t i=0;i<nf;++i)if(qf[i].queueFlags&VK_QUEUE_COMPUTE_BIT){g.qfam=i;break;}
    float prio=1.f;VkDeviceQueueCreateInfo qci{};qci.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;qci.queueFamilyIndex=g.qfam;qci.queueCount=1;qci.pQueuePriorities=&prio;
    VkDeviceCreateInfo dci{};dci.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;dci.queueCreateInfoCount=1;dci.pQueueCreateInfos=&qci;VK_CHECK(vkCreateDevice(g.pd,&dci,nullptr,&g.dev));vkGetDeviceQueue(g.dev,g.qfam,0,&g.q);
    VkCommandPoolCreateInfo pci{};pci.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;pci.queueFamilyIndex=g.qfam;VK_CHECK(vkCreateCommandPool(g.dev,&pci,nullptr,&g.pool));
    VkCommandBufferAllocateInfo cbai{};cbai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;cbai.commandPool=g.pool;cbai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;cbai.commandBufferCount=1;VK_CHECK(vkAllocateCommandBuffers(g.dev,&cbai,&g.cb));
    VkFenceCreateInfo fci{};fci.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;VK_CHECK(vkCreateFence(g.dev,&fci,nullptr,&g.fence));

    VkMemoryPropertyFlags hv=VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    VkBuffer bW,bX,bY,bD;VkDeviceMemory mW,mX,mY,mD;
    Buf(bW,mW,W.size()*sizeof(float),hv,W.data());
    Buf(bX,mX,cols*sizeof(float),hv,x.data());
    Buf(bY,mY,rows*sizeof(float),hv,nullptr);
    struct Dims{uint32_t rows,cols,bpr;}dims{rows,cols,cols/64};
    Buf(bD,mD,sizeof(Dims),hv,&dims);

    VkDescriptorSetLayoutBinding b[4];std::memset(b,0,sizeof(b));
    b[0].binding=0;b[0].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;b[0].descriptorCount=1;b[0].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    b[1].binding=1;b[1].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;b[1].descriptorCount=1;b[1].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    b[2].binding=2;b[2].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;b[2].descriptorCount=1;b[2].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    b[3].binding=3;b[3].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;b[3].descriptorCount=1;b[3].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT;
    VkDescriptorSetLayoutCreateInfo dli{};dli.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;dli.bindingCount=4;dli.pBindings=b;VK_CHECK(vkCreateDescriptorSetLayout(g.dev,&dli,nullptr,&g.dsl));
    VkPipelineLayoutCreateInfo pli{};pli.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;pli.setLayoutCount=1;pli.pSetLayouts=&g.dsl;VK_CHECK(vkCreatePipelineLayout(g.dev,&pli,nullptr,&g.pl));
    VkDescriptorPoolSize ps[2]={{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,3},{VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,1}};
    VkDescriptorPoolCreateInfo dpi{};dpi.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;dpi.maxSets=1;dpi.poolSizeCount=2;dpi.pPoolSizes=ps;VK_CHECK(vkCreateDescriptorPool(g.dev,&dpi,nullptr,&g.dp));
    VkDescriptorSetAllocateInfo dsai{};dsai.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;dsai.descriptorPool=g.dp;dsai.descriptorSetCount=1;dsai.pSetLayouts=&g.dsl;VK_CHECK(vkAllocateDescriptorSets(g.dev,&dsai,&g.ds));
    VkDescriptorBufferInfo b0{bW,0,W.size()*sizeof(float)},b1{bX,0,cols*sizeof(float)},b2{bY,0,rows*sizeof(float)},b3{bD,0,sizeof(Dims)};
    VkWriteDescriptorSet w[4];std::memset(w,0,sizeof(w));
    for(int i=0;i<3;++i){w[i].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;w[i].dstSet=g.ds;w[i].dstBinding=(uint32_t)i;w[i].descriptorCount=1;w[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;w[i].pBufferInfo=(i==0)?&b0:(i==1)?&b1:&b2;}
    w[3].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;w[3].dstSet=g.ds;w[3].dstBinding=3;w[3].descriptorCount=1;w[3].descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;w[3].pBufferInfo=&b3;
    vkUpdateDescriptorSets(g.dev,4,w,0,nullptr);
    VkShaderModuleCreateInfo smi{};smi.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;smi.codeSize=spv.size();smi.pCode=(const uint32_t*)spv.data();VkShaderModule sm;VK_CHECK(vkCreateShaderModule(g.dev,&smi,nullptr,&sm));
    VkComputePipelineCreateInfo cpi{};cpi.sType=VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;cpi.layout=g.pl;cpi.stage.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;cpi.stage.stage=VK_SHADER_STAGE_COMPUTE_BIT;cpi.stage.module=sm;cpi.stage.pName="main";VK_CHECK(vkCreateComputePipelines(g.dev,nullptr,1,&cpi,nullptr,&g.pipe));

    auto disp=[&](){vkResetCommandBuffer(g.cb,0);VkCommandBufferBeginInfo bi{};bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;vkBeginCommandBuffer(g.cb,&bi);vkCmdBindPipeline(g.cb,VK_PIPELINE_BIND_POINT_COMPUTE,g.pipe);vkCmdBindDescriptorSets(g.cb,VK_PIPELINE_BIND_POINT_COMPUTE,g.pl,0,1,&g.ds,0,nullptr);vkCmdDispatch(g.cb,rows,1,1);vkEndCommandBuffer(g.cb);VkSubmitInfo si{};si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;si.commandBufferCount=1;si.pCommandBuffers=&g.cb;VK_CHECK(vkQueueSubmit(g.q,1,&si,g.fence));VK_CHECK(vkWaitForFences(g.dev,1,&g.fence,VK_TRUE,UINT64_MAX));vkResetFences(g.dev,1,&g.fence);};
    disp();
    auto t0=std::chrono::steady_clock::now();for(uint32_t s=0;s<steps;++s)disp();auto t1=std::chrono::steady_clock::now();
    double sec=std::chrono::duration<double>(t1-t0).count();double tps=sec>0?steps/sec:0;
    std::vector<float> y(rows);void* p;VK_CHECK(vkMapMemory(g.dev,mY,0,rows*sizeof(float),0,&p));std::memcpy(y.data(),p,rows*sizeof(float));vkUnmapMemory(g.dev,mY);
    // debug: read back weights + input to verify GPU sees correct data
    std::vector<float> wback(W.size()), xback(cols);
    { void* q; VK_CHECK(vkMapMemory(g.dev,mW,0,W.size()*sizeof(float),0,&q)); std::memcpy(wback.data(),q,W.size()*sizeof(float)); vkUnmapMemory(g.dev,mW); }
    { void* q; VK_CHECK(vkMapMemory(g.dev,mX,0,cols*sizeof(float),0,&q)); std::memcpy(xback.data(),q,cols*sizeof(float)); vkUnmapMemory(g.dev,mX); }
    std::printf("DEBUG y[0]=%g yref[0]=%g  w[0]=%g (cpu %g)  x[0]=%g (cpu %g)\n", y[0], yref[0], wback[0], W[0], xback[0], x[0]);
    double maxd=0;for(uint32_t r=0;r<rows;++r)maxd=std::max(maxd,(double)std::fabs(y[r]-yref[r]));
    std::printf("GPU F32: steps=%u time_s=%.4f matvec_per_s=%.1f peak_ws=%llu max_diff=%g %s\n",steps,sec,tps,(unsigned long long)PeakWS(),maxd,maxd<1e-4?"PASS":"FAIL");
    return 0;
}
