#pragma once
// Deep2PeerDeviceGroup.hpp — real Vulkan device-group peer capability probe.
#include "vulkan_compute.h"
#include <vulkan/vulkan.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace Deep2 {

struct PeerDeviceGroupProbe {
    bool sameDeviceGroup = false;
    bool logicalDeviceCreated = false;
    bool copyPeer = false;
    bool genericPeer = false;
    uint32_t groupSize = 0;
    uint32_t localIndex = UINT32_MAX;
    uint32_t remoteIndex = UINT32_MAX;
    uint32_t peerHeapCount = 0;
    VkResult createDeviceResult = VK_SUCCESS;
};

inline bool Deep2SamePhysicalIdentity(
    VkPhysicalDevice d, const VulkanPhysicalInfo& want)
{
    VkPhysicalDeviceProperties p{};
    vkGetPhysicalDeviceProperties(d,&p);
    return p.vendorID==want.vendorId &&
           p.deviceID==want.deviceId &&
           std::string(p.deviceName)==want.name;
}

inline PeerDeviceGroupProbe Deep2ProbePeerDeviceGroup(
    const VulkanPhysicalInfo& a, const VulkanPhysicalInfo& b)
{
    PeerDeviceGroupProbe r{};

    VkApplicationInfo app{};
    app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName="RawrXD Deep2 Peer Probe";
    app.apiVersion=VK_API_VERSION_1_1;
    VkInstanceCreateInfo ci{};
    ci.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo=&app;

    VkInstance instance=VK_NULL_HANDLE;
    if(vkCreateInstance(&ci,nullptr,&instance)!=VK_SUCCESS) return r;

    uint32_t count=0;
    if(vkEnumeratePhysicalDeviceGroups(instance,&count,nullptr)!=VK_SUCCESS ||
       count==0) {
        vkDestroyInstance(instance,nullptr);
        return r;
    }

    std::vector<VkPhysicalDeviceGroupProperties> groups(count);
    for(auto& g:groups) {
        g.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_GROUP_PROPERTIES;
        g.pNext=nullptr;
    }
    if(vkEnumeratePhysicalDeviceGroups(instance,&count,groups.data())!=VK_SUCCESS){
        vkDestroyInstance(instance,nullptr);
        return r;
    }

    std::vector<VkPhysicalDevice> chosen;
    for(const auto& g:groups){
        int ia=-1,ib=-1;
        for(uint32_t i=0;i<g.physicalDeviceCount;++i){
            if(Deep2SamePhysicalIdentity(g.physicalDevices[i],a)) ia=(int)i;
            if(Deep2SamePhysicalIdentity(g.physicalDevices[i],b)) ib=(int)i;
        }
        if(ia>=0 && ib>=0 && ia!=ib){
            r.sameDeviceGroup=true;
            r.groupSize=g.physicalDeviceCount;
            r.localIndex=(uint32_t)ia;
            r.remoteIndex=(uint32_t)ib;
            chosen.assign(g.physicalDevices,
                          g.physicalDevices+g.physicalDeviceCount);
            break;
        }
    }
    if(!r.sameDeviceGroup){
        vkDestroyInstance(instance,nullptr);
        return r;
    }

    uint32_t qn=0;
    vkGetPhysicalDeviceQueueFamilyProperties(chosen[0],&qn,nullptr);
    std::vector<VkQueueFamilyProperties> q(qn);
    vkGetPhysicalDeviceQueueFamilyProperties(chosen[0],&qn,q.data());
    int qf=-1;
    for(uint32_t i=0;i<qn;++i)
        if(q[i].queueCount && (q[i].queueFlags&VK_QUEUE_COMPUTE_BIT)){
            qf=(int)i;break;
        }
    if(qf<0){
        vkDestroyInstance(instance,nullptr);
        return r;
    }

    float priority=1.0f;
    VkDeviceQueueCreateInfo qi{};
    qi.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qi.queueFamilyIndex=(uint32_t)qf;
    qi.queueCount=1;
    qi.pQueuePriorities=&priority;

    VkDeviceGroupDeviceCreateInfo gi{};
    gi.sType=VK_STRUCTURE_TYPE_DEVICE_GROUP_DEVICE_CREATE_INFO;
    gi.physicalDeviceCount=(uint32_t)chosen.size();
    gi.pPhysicalDevices=chosen.data();

    VkDeviceCreateInfo di{};
    di.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    di.pNext=&gi;
    di.queueCreateInfoCount=1;
    di.pQueueCreateInfos=&qi;

    VkDevice device=VK_NULL_HANDLE;
    r.createDeviceResult=vkCreateDevice(chosen[0],&di,nullptr,&device);
    if(r.createDeviceResult!=VK_SUCCESS){
        vkDestroyInstance(instance,nullptr);
        return r;
    }
    r.logicalDeviceCreated=true;

    VkPhysicalDeviceMemoryProperties mp{};
    vkGetPhysicalDeviceMemoryProperties(chosen[0],&mp);
    for(uint32_t heap=0;heap<mp.memoryHeapCount;++heap){
        VkPeerMemoryFeatureFlags f01=0,f10=0;
        vkGetDeviceGroupPeerMemoryFeatures(
            device,heap,r.localIndex,r.remoteIndex,&f01);
        vkGetDeviceGroupPeerMemoryFeatures(
            device,heap,r.remoteIndex,r.localIndex,&f10);

        const VkPeerMemoryFeatureFlags copyNeed =
            VK_PEER_MEMORY_FEATURE_COPY_SRC_BIT |
            VK_PEER_MEMORY_FEATURE_COPY_DST_BIT;
        const VkPeerMemoryFeatureFlags genericNeed =
            VK_PEER_MEMORY_FEATURE_GENERIC_SRC_BIT |
            VK_PEER_MEMORY_FEATURE_GENERIC_DST_BIT;

        if((f01&copyNeed)==copyNeed && (f10&copyNeed)==copyNeed){
            r.copyPeer=true;
            ++r.peerHeapCount;
        }
        if((f01&genericNeed)==genericNeed && (f10&genericNeed)==genericNeed)
            r.genericPeer=true;
    }

    vkDestroyDevice(device,nullptr);
    vkDestroyInstance(instance,nullptr);
    return r;
}

} // namespace Deep2
