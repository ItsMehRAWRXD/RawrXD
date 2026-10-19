/* g3_wake_lease_r9700_main.cpp ? wake R9700 then direct ICD A0 */
#define VK_USE_PLATFORM_WIN32_KHR
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d12.h>
#include <vulkan/vulkan.h>
#include <vulkan/vk_icd.h>
#include <cstdio>
#include <cstring>
#include <vector>
HRESULT WakePci(uint32_t pci, ID3D12Device** outDev, ID3D12Resource** outBuf);
int NameHas(const char* hay, const char* n);
PFN_vk_icdGetInstanceProcAddr g_icdGipa = nullptr;
static PFN_vkVoidFunction Ipa(VkInstance i, const char* n) {
  return g_icdGipa ? g_icdGipa(i, n) : nullptr;
}
int main() {
  printf("GATE=P2_WAKE_R9700\nPROMOTE=0\n");
  ID3D12Device* d3=nullptr; ID3D12Resource* buf=nullptr;
  HRESULT hr = WakePci(0x7551, &d3, &buf);
  printf("D3D12_WAKE_HR=0x%08X D3D12_WAKE=%s\n", (unsigned)hr, SUCCEEDED(hr)?"PASS":"FAIL");
  if (FAILED(hr)) return 10;
  const char* path = "C:\\Windows\\System32\\DriverStore\\FileRepository\\amdvlk.inf_amd64_914ba89eaaafdf60\\amdvlk64.dll";
  HMODULE dll = LoadLibraryA(path);
  if (!dll) return 11;
  auto neg=(PFN_vk_icdNegotiateLoaderICDInterfaceVersion)GetProcAddress(dll,"vk_icdNegotiateLoaderICDInterfaceVersion");
  g_icdGipa=(PFN_vk_icdGetInstanceProcAddr)GetProcAddress(dll,"vk_icdGetInstanceProcAddr");
  uint32_t ver=CURRENT_LOADER_ICD_INTERFACE_VERSION; if(neg) neg(&ver);
  auto CreateInstance=(PFN_vkCreateInstance)Ipa(VK_NULL_HANDLE,"vkCreateInstance");
  VkApplicationInfo app{}; app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO; app.apiVersion=VK_API_VERSION_1_2;
  VkInstanceCreateInfo ici{}; ici.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO; ici.pApplicationInfo=&app;
  VkInstance inst=VK_NULL_HANDLE; VkResult r=CreateInstance(&ici,nullptr,&inst);
  printf("VK_CREATE_INSTANCE=%d\n",(int)r); if(r) return 12;
  auto EnumPD=(PFN_vkEnumeratePhysicalDevices)Ipa(inst,"vkEnumeratePhysicalDevices");
  auto GetProps=(PFN_vkGetPhysicalDeviceProperties)Ipa(inst,"vkGetPhysicalDeviceProperties");
  auto CreateDev=(PFN_vkCreateDevice)Ipa(inst,"vkCreateDevice");
  uint32_t n=0; EnumPD(inst,&n,nullptr); printf("PHYS_COUNT=%u\n",n);
  std::vector<VkPhysicalDevice> pds(n); EnumPD(inst,&n,pds.data());
  VkPhysicalDevice hit=VK_NULL_HANDLE; VkPhysicalDeviceProperties props{};
  for(uint32_t i=0;i<n;++i){ GetProps(pds[i],&props); printf("PHYS_%u=%s id=0x%X\n",i,props.deviceName,props.deviceID);
    if(props.deviceID==0x7551||NameHas(props.deviceName,"9700")) hit=pds[i]; }
  if(!hit){ printf("MATCH=0\nA0=FAIL\n"); return 13; }
  float pri=1.f; VkDeviceQueueCreateInfo qci{}; qci.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO; qci.queueCount=1; qci.pQueuePriorities=&pri;
  VkDeviceCreateInfo dci{}; dci.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO; dci.queueCreateInfoCount=1; dci.pQueueCreateInfos=&qci;
  VkDevice vdev=VK_NULL_HANDLE; r=CreateDev(hit,&dci,nullptr,&vdev);
  printf("WAKE_LEASE_A0_RESULT=%d A0=%s\n",(int)r,r==VK_SUCCESS?"PASS":"FAIL");
  return r==VK_SUCCESS?0:20;
}
