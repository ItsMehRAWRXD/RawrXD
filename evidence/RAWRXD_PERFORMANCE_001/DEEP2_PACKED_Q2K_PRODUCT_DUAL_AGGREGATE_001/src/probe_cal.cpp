#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <windows.h>
#include <stdio.h>
#include "../../DEEP2_DUAL_AGGREGATE_SSVK_BIND_001/src/d2_live_vk.h"
#include "../../DEEP2_MATERIAL_DUAL_OVERLAP_NODEP_20260912/include/d2_material_overlap.h"
extern "C" int d2_live_open(D2LiveCtx*);
extern "C" void d2_live_close(D2LiveCtx*);
int main(){
  D2LiveCtx c{}; if(!d2_live_open(&c)){puts("open fail");return 1;}
  auto gipa=(PFN_vkGetInstanceProcAddr)GetProcAddress((HMODULE)c.lib,"vkGetInstanceProcAddr");
  auto gdpa=(PFN_vkGetDeviceProcAddr)gipa((VkInstance)c.inst,"vkGetDeviceProcAddr");
  for(int i=0;i<2;i++){
    VkDevice d=(VkDevice)c.lane[i].dev;
    auto ext=(void*)gdpa(d,"vkGetCalibratedTimestampsEXT");
    auto props=(PFN_vkGetPhysicalDeviceProperties)gipa((VkInstance)c.inst,"vkGetPhysicalDeviceProperties");
    VkPhysicalDeviceProperties pr{}; props((VkPhysicalDevice)c.lane[i].phys,&pr);
    printf("lane%d cal=%p period=%f\n",i,ext,pr.limits.timestampPeriod);
    uint32_t n=0; auto gqf=(PFN_vkGetPhysicalDeviceQueueFamilyProperties)gipa((VkInstance)c.inst,"vkGetPhysicalDeviceQueueFamilyProperties");
    gqf((VkPhysicalDevice)c.lane[i].phys,&n,0); VkQueueFamilyProperties q[8]; if(n>8)n=8; gqf((VkPhysicalDevice)c.lane[i].phys,&n,q);
    printf("  ts_bits[0]=%u fam=%u\n",q[0].timestampValidBits,c.lane[i].qfam);
  }
  d2_live_close(&c); return 0;
}
