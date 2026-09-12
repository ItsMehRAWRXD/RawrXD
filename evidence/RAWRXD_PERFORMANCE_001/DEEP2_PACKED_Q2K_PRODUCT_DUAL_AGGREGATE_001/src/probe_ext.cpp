#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
int main(){
  HMODULE lib=LoadLibraryA("vulkan-1.dll");
  auto gipa=(PFN_vkGetInstanceProcAddr)GetProcAddress(lib,"vkGetInstanceProcAddr");
  auto ci=(PFN_vkCreateInstance)gipa(0,"vkCreateInstance");
  VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO}; app.apiVersion=VK_API_VERSION_1_2;
  VkInstanceCreateInfo ici{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO}; ici.pApplicationInfo=&app;
  VkInstance inst=0; ci(&ici,0,&inst);
  auto en=(PFN_vkEnumeratePhysicalDevices)gipa(inst,"vkEnumeratePhysicalDevices");
  auto props=(PFN_vkGetPhysicalDeviceProperties)gipa(inst,"vkGetPhysicalDeviceProperties");
  auto eext=(PFN_vkEnumerateDeviceExtensionProperties)gipa(inst,"vkEnumerateDeviceExtensionProperties");
  auto gqf=(PFN_vkGetPhysicalDeviceQueueFamilyProperties)gipa(inst,"vkGetPhysicalDeviceQueueFamilyProperties");
  auto cd=(PFN_vkCreateDevice)gipa(inst,"vkCreateDevice");
  uint32_t n=0; en(inst,&n,0); VkPhysicalDevice p[16]; if(n>16)n=16; en(inst,&n,p);
  for(uint32_t i=0;i<n;i++){
    VkPhysicalDeviceProperties pr{}; props(p[i],&pr);
    if(strstr(pr.deviceName,"Direct3D12")) continue;
    if(!strstr(pr.deviceName,"R9700") && !strstr(pr.deviceName,"7800 XT")) continue;
    uint32_t ne=0; eext(p[i],0,&ne,0);
    VkExtensionProperties* e=(VkExtensionProperties*)malloc(ne*sizeof(*e)); eext(p[i],0,&ne,e);
    int has=0; for(uint32_t j=0;j<ne;j++) if(!strcmp(e[j].extensionName,"VK_EXT_calibrated_timestamps")) has=1;
    free(e);
    float pri=1.f; uint32_t fam=0,nq=0; gqf(p[i],&nq,0); VkQueueFamilyProperties q[8]; if(nq>8)nq=8; gqf(p[i],&nq,q);
    for(uint32_t k=0;k<nq;k++) if(q[k].queueFlags&VK_QUEUE_COMPUTE_BIT){fam=k;break;}
    VkDeviceQueueCreateInfo qci{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO}; qci.queueFamilyIndex=fam; qci.queueCount=1; qci.pQueuePriorities=&pri;
    const char* dexts[]={"VK_EXT_calibrated_timestamps"};
    VkDeviceCreateInfo dci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO}; dci.queueCreateInfoCount=1; dci.pQueueCreateInfos=&qci;
    dci.enabledExtensionCount=1; dci.ppEnabledExtensionNames=dexts;
    VkDevice dev=0; VkResult r=cd(p[i],&dci,0,&dev);
    printf("%s has_ext=%d CreateDevice=%d\n", pr.deviceName, has, (int)r);
    if(r==0){
      auto gdpa=(PFN_vkGetDeviceProcAddr)gipa(inst,"vkGetDeviceProcAddr");
      auto cal=(PFN_vkGetCalibratedTimestampsEXT)gdpa(dev,"vkGetCalibratedTimestampsEXT");
      VkCalibratedTimestampInfoEXT ci2[2]={{VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT,0,VK_TIME_DOMAIN_DEVICE_EXT},{VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT,0,VK_TIME_DOMAIN_QUERY_PERFORMANCE_COUNTER_EXT}};
      uint64_t ts[2]={},devi=0; VkResult cr=cal?cal(dev,2,ci2,ts,&devi):(VkResult)-1;
      printf("  cal_fn=%p call=%d ts0=%llu ts1=%llu dev=%llu\n", (void*)cal,(int)cr,(unsigned long long)ts[0],(unsigned long long)ts[1],(unsigned long long)devi);
    }
  }
  return 0;
}
