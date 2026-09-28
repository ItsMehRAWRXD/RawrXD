#include "VulkanExpertTransport.h"
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace rawrxd::deep2 {

#ifdef _WIN32
// Minimal Vulkan 1.0 ABI declarations used by this file only. Values are from the Vulkan ABI.
using VkFlags = uint32_t; using VkBool32 = uint32_t; using VkDeviceSize = uint64_t; using VkResult = int32_t;
using VkPhysicalDevice = void*; using VkDevice = void*; using VkQueue = void*; using VkCommandPool = uint64_t; using VkCommandBuffer = void*;
using VkBuffer = uint64_t; using VkDeviceMemory = uint64_t; using VkFence = uint64_t;
static constexpr VkResult VK_SUCCESS=0, VK_NOT_READY=1;
static constexpr uint32_t VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO=12, VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO=5,
    VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO=40, VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO=42,
    VK_STRUCTURE_TYPE_SUBMIT_INFO=4, VK_STRUCTURE_TYPE_FENCE_CREATE_INFO=8;
static constexpr VkFlags VK_BUFFER_USAGE_TRANSFER_SRC_BIT=0x1, VK_BUFFER_USAGE_TRANSFER_DST_BIT=0x2, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT=0x20;
static constexpr VkFlags VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT=0x1, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT=0x2, VK_MEMORY_PROPERTY_HOST_COHERENT_BIT=0x4;
static constexpr uint32_t VK_SHARING_MODE_EXCLUSIVE=0, VK_COMMAND_BUFFER_LEVEL_PRIMARY=0, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT=0x1;
struct VkBufferCreateInfo { uint32_t sType; const void* pNext; VkFlags flags; VkDeviceSize size; VkFlags usage; uint32_t sharingMode; uint32_t queueFamilyIndexCount; const uint32_t* pQueueFamilyIndices; };
struct VkMemoryRequirements { VkDeviceSize size; VkDeviceSize alignment; uint32_t memoryTypeBits; };
struct VkMemoryAllocateInfo { uint32_t sType; const void* pNext; VkDeviceSize allocationSize; uint32_t memoryTypeIndex; };
struct VkMemoryType { VkFlags propertyFlags; uint32_t heapIndex; };
struct VkMemoryHeap { VkDeviceSize size; VkFlags flags; };
struct VkPhysicalDeviceMemoryProperties { uint32_t memoryTypeCount; VkMemoryType memoryTypes[32]; uint32_t memoryHeapCount; VkMemoryHeap memoryHeaps[16]; };
struct VkCommandBufferAllocateInfo { uint32_t sType; const void* pNext; VkCommandPool commandPool; uint32_t level; uint32_t commandBufferCount; };
struct VkCommandBufferBeginInfo { uint32_t sType; const void* pNext; VkFlags flags; const void* pInheritanceInfo; };
struct VkBufferCopy { VkDeviceSize srcOffset; VkDeviceSize dstOffset; VkDeviceSize size; };
struct VkSubmitInfo { uint32_t sType; const void* pNext; uint32_t waitSemaphoreCount; const uint64_t* pWaitSemaphores; const VkFlags* pWaitDstStageMask; uint32_t commandBufferCount; const VkCommandBuffer* pCommandBuffers; uint32_t signalSemaphoreCount; const uint64_t* pSignalSemaphores; };
struct VkFenceCreateInfo { uint32_t sType; const void* pNext; VkFlags flags; };
using PFN_vkVoidFunction = void(*)();
using PFN_vkGetDeviceProcAddr = PFN_vkVoidFunction(*)(VkDevice,const char*);
using PFN_vkGetPhysicalDeviceMemoryProperties = void(*)(VkPhysicalDevice,VkPhysicalDeviceMemoryProperties*);
using PFN_vkCreateBuffer = VkResult(*)(VkDevice,const VkBufferCreateInfo*,const void*,VkBuffer*);
using PFN_vkDestroyBuffer = void(*)(VkDevice,VkBuffer,const void*);
using PFN_vkGetBufferMemoryRequirements = void(*)(VkDevice,VkBuffer,VkMemoryRequirements*);
using PFN_vkAllocateMemory = VkResult(*)(VkDevice,const VkMemoryAllocateInfo*,const void*,VkDeviceMemory*);
using PFN_vkFreeMemory = void(*)(VkDevice,VkDeviceMemory,const void*);
using PFN_vkBindBufferMemory = VkResult(*)(VkDevice,VkBuffer,VkDeviceMemory,VkDeviceSize);
using PFN_vkMapMemory = VkResult(*)(VkDevice,VkDeviceMemory,VkDeviceSize,VkDeviceSize,VkFlags,void**);
using PFN_vkUnmapMemory = void(*)(VkDevice,VkDeviceMemory);
using PFN_vkAllocateCommandBuffers = VkResult(*)(VkDevice,const VkCommandBufferAllocateInfo*,VkCommandBuffer*);
using PFN_vkFreeCommandBuffers = void(*)(VkDevice,VkCommandPool,uint32_t,const VkCommandBuffer*);
using PFN_vkBeginCommandBuffer = VkResult(*)(VkCommandBuffer,const VkCommandBufferBeginInfo*);
using PFN_vkEndCommandBuffer = VkResult(*)(VkCommandBuffer);
using PFN_vkCmdCopyBuffer = void(*)(VkCommandBuffer,VkBuffer,VkBuffer,uint32_t,const VkBufferCopy*);
using PFN_vkCreateFence = VkResult(*)(VkDevice,const VkFenceCreateInfo*,const void*,VkFence*);
using PFN_vkDestroyFence = void(*)(VkDevice,VkFence,const void*);
using PFN_vkQueueSubmit = VkResult(*)(VkQueue,uint32_t,const VkSubmitInfo*,VkFence);
using PFN_vkGetFenceStatus = VkResult(*)(VkDevice,VkFence);
using PFN_vkWaitForFences = VkResult(*)(VkDevice,uint32_t,const VkFence*,VkBool32,uint64_t);
#endif

struct VulkanExpertTransport::Impl {
    VulkanExpertTransportConfig cfg{};
    mutable std::mutex mu;
    VulkanExpertTransportStats st{};
    std::string error;
    bool ok=false;
    HostStagingRing ring;
#ifdef _WIN32
    HMODULE lib=nullptr;
    VkPhysicalDevice physical=nullptr; VkDevice device=nullptr; VkQueue queue=nullptr; VkCommandPool pool=0;
    VkBuffer stagingBuffer=0; VkDeviceMemory stagingMemory=0; uint8_t* mapped=nullptr;
    PFN_vkGetPhysicalDeviceMemoryProperties getMemProps=nullptr;
    PFN_vkCreateBuffer createBuffer=nullptr; PFN_vkDestroyBuffer destroyBuffer=nullptr; PFN_vkGetBufferMemoryRequirements getReq=nullptr;
    PFN_vkAllocateMemory allocMem=nullptr; PFN_vkFreeMemory freeMem=nullptr; PFN_vkBindBufferMemory bindMem=nullptr; PFN_vkMapMemory mapMem=nullptr; PFN_vkUnmapMemory unmapMem=nullptr;
    PFN_vkAllocateCommandBuffers allocCmd=nullptr; PFN_vkFreeCommandBuffers freeCmd=nullptr; PFN_vkBeginCommandBuffer beginCmd=nullptr; PFN_vkEndCommandBuffer endCmd=nullptr; PFN_vkCmdCopyBuffer cmdCopy=nullptr;
    PFN_vkCreateFence createFence=nullptr; PFN_vkDestroyFence destroyFence=nullptr; PFN_vkQueueSubmit queueSubmit=nullptr; PFN_vkGetFenceStatus fenceStatus=nullptr; PFN_vkWaitForFences waitFences=nullptr;
    struct Allocation { VkBuffer buffer=0; VkDeviceMemory memory=0; size_t bytes=0; };
    struct Flight { uint64_t ticket=0; VkFence fence=0; VkCommandBuffer cmd=nullptr; StagingSlice slice{}; };
    std::unordered_map<uint64_t,Flight> flights;
    uint64_t nextTicket=1;

    uint32_t memoryType(uint32_t bits, VkFlags flags) {
        VkPhysicalDeviceMemoryProperties p{}; getMemProps(physical,&p);
        for(uint32_t i=0;i<p.memoryTypeCount;i++) if((bits&(1u<<i)) && (p.memoryTypes[i].propertyFlags&flags)==flags) return i;
        return 0xffffffffu;
    }
    bool makeBuffer(size_t bytes,VkFlags usage,VkFlags memFlags,VkBuffer& b,VkDeviceMemory& m) {
        VkBufferCreateInfo bi{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,nullptr,0,(VkDeviceSize)bytes,usage,VK_SHARING_MODE_EXCLUSIVE,0,nullptr};
        if(createBuffer(device,&bi,nullptr,&b)!=VK_SUCCESS) return false;
        VkMemoryRequirements r{}; getReq(device,b,&r); uint32_t mt=memoryType(r.memoryTypeBits,memFlags);
        if(mt==0xffffffffu){destroyBuffer(device,b,nullptr);b=0;return false;}
        VkMemoryAllocateInfo ai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,nullptr,r.size,mt};
        if(allocMem(device,&ai,nullptr,&m)!=VK_SUCCESS){destroyBuffer(device,b,nullptr);b=0;return false;}
        if(bindMem(device,b,m,0)!=VK_SUCCESS){freeMem(device,m,nullptr);destroyBuffer(device,b,nullptr);m=b=0;return false;}
        return true;
    }
    bool cleanupFlight(uint64_t t,bool wait) {
        auto it=flights.find(t); if(it==flights.end()) return false;
        VkResult r=wait?waitFences(device,1,&it->second.fence,1,~uint64_t(0)):fenceStatus(device,it->second.fence);
        if(r!=VK_SUCCESS) return false;
        if(wait) ++st.waits; else ++st.pollsReady;
        destroyFence(device,it->second.fence,nullptr); freeCmd(device,pool,1,&it->second.cmd); ring.complete(t); flights.erase(it); return true;
    }
#endif
};

VulkanExpertTransport::VulkanExpertTransport(std::unique_ptr<Impl> p):impl_(std::move(p)){}

std::unique_ptr<VulkanExpertTransport> VulkanExpertTransport::create(const VulkanExpertTransportConfig& cfg) {
    auto p=std::make_unique<Impl>(); p->cfg=cfg; p->ring.reset(cfg.stagingBytes,cfg.stagingAlignment); p->st.stagingCapacity=cfg.stagingBytes;
#ifdef _WIN32
    p->physical=(VkPhysicalDevice)cfg.physicalDevice; p->device=(VkDevice)cfg.device; p->queue=(VkQueue)cfg.queue; p->pool=(VkCommandPool)(uintptr_t)cfg.commandPool;
    if(!p->physical||!p->device||!p->queue||!p->pool){p->error="missing Deep2 Vulkan handles";return std::unique_ptr<VulkanExpertTransport>(new VulkanExpertTransport(std::move(p)));}
    p->lib=LoadLibraryA("vulkan-1.dll"); if(!p->lib){p->error="vulkan-1.dll not found";return std::unique_ptr<VulkanExpertTransport>(new VulkanExpertTransport(std::move(p)));}
    auto gdpa=(PFN_vkGetDeviceProcAddr)GetProcAddress(p->lib,"vkGetDeviceProcAddr"); p->getMemProps=(PFN_vkGetPhysicalDeviceMemoryProperties)GetProcAddress(p->lib,"vkGetPhysicalDeviceMemoryProperties");
    if(!gdpa||!p->getMemProps){p->error="required Vulkan loader exports missing";return std::unique_ptr<VulkanExpertTransport>(new VulkanExpertTransport(std::move(p)));}
#define LOAD(name,type) p->name=(type)gdpa(p->device,"vk" #name)
    LOAD(createBuffer,PFN_vkCreateBuffer); LOAD(destroyBuffer,PFN_vkDestroyBuffer); LOAD(getReq,PFN_vkGetBufferMemoryRequirements);
#undef LOAD
    p->createBuffer=(PFN_vkCreateBuffer)gdpa(p->device,"vkCreateBuffer"); p->destroyBuffer=(PFN_vkDestroyBuffer)gdpa(p->device,"vkDestroyBuffer"); p->getReq=(PFN_vkGetBufferMemoryRequirements)gdpa(p->device,"vkGetBufferMemoryRequirements");
    p->allocMem=(PFN_vkAllocateMemory)gdpa(p->device,"vkAllocateMemory"); p->freeMem=(PFN_vkFreeMemory)gdpa(p->device,"vkFreeMemory"); p->bindMem=(PFN_vkBindBufferMemory)gdpa(p->device,"vkBindBufferMemory");
    p->mapMem=(PFN_vkMapMemory)gdpa(p->device,"vkMapMemory"); p->unmapMem=(PFN_vkUnmapMemory)gdpa(p->device,"vkUnmapMemory"); p->allocCmd=(PFN_vkAllocateCommandBuffers)gdpa(p->device,"vkAllocateCommandBuffers"); p->freeCmd=(PFN_vkFreeCommandBuffers)gdpa(p->device,"vkFreeCommandBuffers");
    p->beginCmd=(PFN_vkBeginCommandBuffer)gdpa(p->device,"vkBeginCommandBuffer"); p->endCmd=(PFN_vkEndCommandBuffer)gdpa(p->device,"vkEndCommandBuffer"); p->cmdCopy=(PFN_vkCmdCopyBuffer)gdpa(p->device,"vkCmdCopyBuffer"); p->createFence=(PFN_vkCreateFence)gdpa(p->device,"vkCreateFence"); p->destroyFence=(PFN_vkDestroyFence)gdpa(p->device,"vkDestroyFence");
    p->queueSubmit=(PFN_vkQueueSubmit)gdpa(p->device,"vkQueueSubmit"); p->fenceStatus=(PFN_vkGetFenceStatus)gdpa(p->device,"vkGetFenceStatus"); p->waitFences=(PFN_vkWaitForFences)gdpa(p->device,"vkWaitForFences");
    if(!p->createBuffer||!p->destroyBuffer||!p->getReq||!p->allocMem||!p->freeMem||!p->bindMem||!p->mapMem||!p->unmapMem||!p->allocCmd||!p->freeCmd||!p->beginCmd||!p->endCmd||!p->cmdCopy||!p->createFence||!p->destroyFence||!p->queueSubmit||!p->fenceStatus||!p->waitFences){p->error="required Vulkan device functions missing";return std::unique_ptr<VulkanExpertTransport>(new VulkanExpertTransport(std::move(p)));}
    if(!p->makeBuffer(cfg.stagingBytes,VK_BUFFER_USAGE_TRANSFER_SRC_BIT,VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,p->stagingBuffer,p->stagingMemory)){p->error="staging buffer allocation failed";return std::unique_ptr<VulkanExpertTransport>(new VulkanExpertTransport(std::move(p)));}
    void* mapped=nullptr; if(p->mapMem(p->device,p->stagingMemory,0,(VkDeviceSize)cfg.stagingBytes,0,&mapped)!=VK_SUCCESS){p->error="staging map failed";return std::unique_ptr<VulkanExpertTransport>(new VulkanExpertTransport(std::move(p)));}
    p->mapped=(uint8_t*)mapped; p->ok=true;
#else
    p->error="VulkanExpertTransport real backend is Windows-only in this source drop";
#endif
    return std::unique_ptr<VulkanExpertTransport>(new VulkanExpertTransport(std::move(p)));
}

VulkanExpertTransport::~VulkanExpertTransport(){
#ifdef _WIN32
    if(!impl_)return; std::lock_guard<std::mutex> lock(impl_->mu);
    std::vector<uint64_t> ts; for(auto& kv:impl_->flights)ts.push_back(kv.first); for(auto t:ts)impl_->cleanupFlight(t,true);
    if(impl_->mapped&&impl_->unmapMem)impl_->unmapMem(impl_->device,impl_->stagingMemory);
    if(impl_->stagingBuffer&&impl_->destroyBuffer)impl_->destroyBuffer(impl_->device,impl_->stagingBuffer,nullptr);
    if(impl_->stagingMemory&&impl_->freeMem)impl_->freeMem(impl_->device,impl_->stagingMemory,nullptr);
    if(impl_->lib)FreeLibrary(impl_->lib);
#endif
}

static uint64_t clockMicros(void*){return (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}

ExpertTransport VulkanExpertTransport::callbacks(){
    ExpertTransport t{}; t.user=this; t.nowMicros=&clockMicros;
#ifdef _WIN32
    t.allocDevice=[](void* u,size_t bytes,uint32_t)->void*{auto*self=(VulkanExpertTransport*)u;auto&p=*self->impl_;std::lock_guard<std::mutex>l(p.mu);if(!p.ok)return nullptr;auto*a=new Impl::Allocation{};if(!p.makeBuffer(bytes,VK_BUFFER_USAGE_TRANSFER_DST_BIT|VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,a->buffer,a->memory)){delete a;return nullptr;}a->bytes=bytes;++p.st.allocations;return a;};
    t.freeDevice=[](void* u,void* h,uint32_t){if(!h)return;auto*self=(VulkanExpertTransport*)u;auto&p=*self->impl_;std::lock_guard<std::mutex>l(p.mu);auto*a=(Impl::Allocation*)h;p.destroyBuffer(p.device,a->buffer,nullptr);p.freeMem(p.device,a->memory,nullptr);delete a;++p.st.frees;};
    t.submitUpload=[](void* u,void* h,const void*src,size_t bytes,uint32_t)->uint64_t{auto*self=(VulkanExpertTransport*)u;auto&p=*self->impl_;std::lock_guard<std::mutex>l(p.mu);if(!p.ok||!h||!src)return 0;auto*a=(Impl::Allocation*)h;if(bytes>a->bytes)return 0;uint64_t ticket=p.nextTicket++;auto slice=p.ring.reserve(bytes,ticket);if(!slice){++p.st.submitFailures;return 0;}std::memcpy(p.mapped+slice.offset,src,bytes);VkCommandBuffer cmd=nullptr;VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,nullptr,p.pool,VK_COMMAND_BUFFER_LEVEL_PRIMARY,1};if(p.allocCmd(p.device,&cai,&cmd)!=VK_SUCCESS){p.ring.complete(ticket);++p.st.submitFailures;return 0;}VkCommandBufferBeginInfo cbi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,nullptr,VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,nullptr};if(p.beginCmd(cmd,&cbi)!=VK_SUCCESS){p.freeCmd(p.device,p.pool,1,&cmd);p.ring.complete(ticket);++p.st.submitFailures;return 0;}VkBufferCopy c{(VkDeviceSize)slice.offset,0,(VkDeviceSize)bytes};p.cmdCopy(cmd,p.stagingBuffer,a->buffer,1,&c);if(p.endCmd(cmd)!=VK_SUCCESS){p.freeCmd(p.device,p.pool,1,&cmd);p.ring.complete(ticket);++p.st.submitFailures;return 0;}VkFence f=0;VkFenceCreateInfo fi{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,nullptr,0};if(p.createFence(p.device,&fi,nullptr,&f)!=VK_SUCCESS){p.freeCmd(p.device,p.pool,1,&cmd);p.ring.complete(ticket);++p.st.submitFailures;return 0;}VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO,nullptr,0,nullptr,nullptr,1,&cmd,0,nullptr};if(p.queueSubmit(p.queue,1,&si,f)!=VK_SUCCESS){p.destroyFence(p.device,f,nullptr);p.freeCmd(p.device,p.pool,1,&cmd);p.ring.complete(ticket);++p.st.submitFailures;return 0;}p.flights.emplace(ticket,Impl::Flight{ticket,f,cmd,slice});++p.st.submits;p.st.bytesSubmitted+=bytes;p.st.stagingUsed=p.ring.used();return ticket;};
    t.pollUpload=[](void* u,uint64_t ticket,uint32_t)->bool{auto*self=(VulkanExpertTransport*)u;auto&p=*self->impl_;std::lock_guard<std::mutex>l(p.mu);bool ok=p.cleanupFlight(ticket,false);p.st.stagingUsed=p.ring.used();return ok;};
    t.waitUpload=[](void* u,uint64_t ticket,uint32_t)->bool{auto*self=(VulkanExpertTransport*)u;auto&p=*self->impl_;std::lock_guard<std::mutex>l(p.mu);bool ok=p.cleanupFlight(ticket,true);p.st.stagingUsed=p.ring.used();return ok;};
    t.upload=[](void* u,void*h,const void*src,size_t bytes,uint32_t d)->bool{auto*self=(VulkanExpertTransport*)u;auto cb=self->callbacks();uint64_t q=cb.submitUpload(u,h,src,bytes,d);return q&&cb.waitUpload(u,q,d);};
#endif
    return t;
}

VulkanExpertTransportStats VulkanExpertTransport::stats() const{if(!impl_)return{};std::lock_guard<std::mutex>l(impl_->mu);auto s=impl_->st;s.stagingUsed=impl_->ring.used();return s;}
bool VulkanExpertTransport::binding(void*h,VulkanBufferBinding&out)const{
#ifdef _WIN32
    if(!h)return false;auto*a=(Impl::Allocation*)h;out.buffer=a->buffer;out.memory=a->memory;out.bytes=a->bytes;return true;
#else
    (void)h;(void)out;return false;
#endif
}
bool VulkanExpertTransport::ready()const noexcept{return impl_&&impl_->ok;}
const char* VulkanExpertTransport::lastError()const noexcept{return impl_?impl_->error.c_str():"no implementation";}

} // namespace rawrxd::deep2
