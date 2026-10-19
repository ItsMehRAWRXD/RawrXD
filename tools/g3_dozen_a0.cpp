#define VK_USE_PLATFORM_WIN32_KHR
#include <windows.h>
#include <vulkan/vulkan.h>
#include <cstdio>
#include <cstring>
#include <vector>
int NameHas(const char* h, const char* n) {
  if (!h||!n) return 0; size_t N=strlen(n);
  for (const char* p=h;*p;++p){ size_t i=0; while(p[i]&&i<N){ char a=p[i],b=n[i];
    if(a>='a'&&a<='z')a-=32; if(b>='a'&&b<='z')b-=32; if(a!=b)break; ++i;} if(i==N)return 1;} return 0; }
int main(){
  printf("GATE=G3_GPU1_AMDVLK_UNBLOCK_001\nPHASE=P5_DOZEN\nPROMOTE=0\n");
  HMODULE vk = LoadLibraryA("vulkan-1.dll");
  if(!vk){ printf("VULKAN1_LOAD=FAIL\n"); return 10; }
  auto gipa=(PFN_vkGetInstanceProcAddr)GetProcAddress(vk,"vkGetInstanceProcAddr");
  auto CreateInstance=(PFN_vkCreateInstance)gipa(nullptr,"vkCreateInstance");
  VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO}; app.apiVersion=VK_API_VERSION_1_1;
  VkInstanceCreateInfo ci{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO}; ci.pApplicationInfo=&app;
  VkInstance inst=VK_NULL_HANDLE; VkResult r=CreateInstance(&ci,nullptr,&inst);
  printf("VK_CREATE_INSTANCE=%d\n",(int)r); if(r) return 11;
  auto EnumPD=(PFN_vkEnumeratePhysicalDevices)gipa(inst,"vkEnumeratePhysicalDevices");
  auto GetProps=(PFN_vkGetPhysicalDeviceProperties)gipa(inst,"vkGetPhysicalDeviceProperties");
  auto GetQ=(PFN_vkGetPhysicalDeviceQueueFamilyProperties)gipa(inst,"vkGetPhysicalDeviceQueueFamilyProperties");
  auto CreateDev=(PFN_vkCreateDevice)gipa(inst,"vkCreateDevice");
  auto DestroyInst=(PFN_vkDestroyInstance)gipa(inst,"vkDestroyInstance");
  auto DestroyDev=(PFN_vkDestroyDevice)gipa(inst,"vkDestroyDevice");
  uint32_t n=0; EnumPD(inst,&n,nullptr); std::vector<VkPhysicalDevice> pds(n); EnumPD(inst,&n,pds.data());
  printf("PHYS_COUNT=%u\n",n);
  VkPhysicalDevice hit=VK_NULL_HANDLE; VkPhysicalDeviceProperties props{};
  for(uint32_t i=0;i<n;i++){ GetProps(pds[i],&props);
    printf("PHYS[%u] name=%s type=%u vendor=%04X device=%04X\n",i,props.deviceName,props.deviceType,props.vendorID,props.deviceID);
    if(NameHas(props.deviceName,"7800")||props.deviceID==0x747E) hit=pds[i];
  }
  if(!hit && n){ hit=pds[0]; GetProps(hit,&props); printf("FALLBACK_FIRST name=%s\n",props.deviceName); }
  printf("HIT=%d name=%s\n",hit?1:0, hit?props.deviceName:"-");
  if(!hit) return 12;
  uint32_t qn=0; GetQ(hit,&qn,nullptr); std::vector<VkQueueFamilyProperties> qp(qn); GetQ(hit,&qn,qp.data());
  uint32_t fam=0; for(uint32_t i=0;i<qn;i++) if(qp[i].queueFlags&VK_QUEUE_COMPUTE_BIT){fam=i;break;}
  float prio=1.f; VkDeviceQueueCreateInfo qci{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
  qci.queueFamilyIndex=fam; qci.queueCount=1; qci.pQueuePriorities=&prio;
  VkDeviceCreateInfo dci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO}; dci.queueCreateInfoCount=1; dci.pQueueCreateInfos=&qci;
  VkDevice dev=VK_NULL_HANDLE; r=CreateDev(hit,&dci,nullptr,&dev);
  printf("DOZEN_A0_RESULT=%d\nDOZEN_A0=%s\n",(int)r,r==VK_SUCCESS?"PASS":"FAIL");
  if(dev) DestroyDev(dev,nullptr); DestroyInst(inst,nullptr); FreeLibrary(vk);
  return r==VK_SUCCESS?0:20;
}
