#define CINTERFACE
#define COBJMACROS
#define VK_USE_PLATFORM_WIN32_KHR
#include <windows.h>
#include <initguid.h>
#include <dxgi.h>
#include <vulkan/vulkan.h>
#include <vulkan/vk_icd.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "dxgi.lib")
__declspec(dllexport) const unsigned int D3D12SDKVersion = 613;
__declspec(dllexport) const char* D3D12SDKPath = ".\\D3D12\\";

typedef VkResult (VKAPI_PTR *PFN_enumAdapt)(VkInstance, LUID, uint32_t*, VkPhysicalDevice*);
static PFN_vk_icdGetInstanceProcAddr gipa;
static PFN_vkVoidFunction Ipa(VkInstance i, const char* n) { return gipa ? gipa(i, n) : NULL; }

static int FindAdapterLuid(uint32_t pciDev, LUID* out) {
  IDXGIFactory1* fac = NULL;
  if (FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void**)&fac))) return 0;
  IDXGIAdapter1* ad = NULL;
  for (UINT i = 0; fac->lpVtbl->EnumAdapters1(fac, i, &ad) != DXGI_ERROR_NOT_FOUND; ++i) {
    DXGI_ADAPTER_DESC1 d; ad->lpVtbl->GetDesc1(ad, &d);
    if (d.VendorId == 0x1002 && d.DeviceId == pciDev) {
      *out = d.AdapterLuid; ad->lpVtbl->Release(ad); fac->lpVtbl->Release(fac); return 1;
    }
    ad->lpVtbl->Release(ad);
  }
  fac->lpVtbl->Release(fac); return 0;
}

int main(int argc, char** argv) {
  const char* needle = argc >= 2 ? argv[1] : "7800";
  uint32_t pci = strstr(needle, "9700") ? 0x7551u : 0x747Eu;
  printf("GATE=P5_DOZEN_ADAPTER NEEDLE=%s PCI=0x%X\n", needle, pci); fflush(stdout);
  LUID luid; if (!FindAdapterLuid(pci, &luid)) { printf("DXGI_ADAPTER=MISS\n"); return 11; }
  printf("DXGI_LUID_HIGH=%ld LOW=%lu\n", (long)luid.HighPart, (unsigned long)luid.LowPart); fflush(stdout);
  HMODULE m = LoadLibraryA("C:\\Program Files\\WindowsApps\\Microsoft.D3DMappingLayers_1.2404.1.0_x64__8wekyb3d8bbwe\\x64\\vulkan_dzn.dll");
  if (!m) { printf("LoadFAIL %lu\n", GetLastError()); return 10; }
  PFN_vk_icdNegotiateLoaderICDInterfaceVersion neg = (PFN_vk_icdNegotiateLoaderICDInterfaceVersion)GetProcAddress(m, "vk_icdNegotiateLoaderICDInterfaceVersion");
  gipa = (PFN_vk_icdGetInstanceProcAddr)GetProcAddress(m, "vk_icdGetInstanceProcAddr");
  PFN_enumAdapt enumAd = (PFN_enumAdapt)GetProcAddress(m, "vk_icdEnumerateAdapterPhysicalDevices");
  uint32_t ver = CURRENT_LOADER_ICD_INTERFACE_VERSION; if (neg) neg(&ver);
  printf("ICD_VER=%u enumAd=%p\n", ver, (void*)enumAd); fflush(stdout);
  PFN_vkCreateInstance CreateInstance = (PFN_vkCreateInstance)Ipa(NULL, "vkCreateInstance");
  VkApplicationInfo app = {VK_STRUCTURE_TYPE_APPLICATION_INFO}; app.apiVersion = VK_API_VERSION_1_1;
  VkInstanceCreateInfo ici = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO}; ici.pApplicationInfo = &app;
  VkInstance inst = NULL; VkResult r = CreateInstance(&ici, NULL, &inst);
  printf("CreateInstance=%d\n", (int)r); fflush(stdout); if (r) return 12;
  if (!enumAd) { printf("NO_ENUM_ADAPTER\n"); return 14; }
  uint32_t n = 0; r = enumAd(inst, luid, &n, NULL);
  printf("EnumAdapter_count=%d n=%u\n", (int)r, n); fflush(stdout);
  VkPhysicalDevice pds[8]; if (n > 8) n = 8; r = enumAd(inst, luid, &n, pds);
  printf("EnumAdapter_fill=%d n=%u\n", (int)r, n); fflush(stdout);
  if (!n) { printf("MATCH=0\n"); return 13; }
  VkPhysicalDevice hit = pds[0];
  PFN_vkGetPhysicalDeviceProperties GetProps = (PFN_vkGetPhysicalDeviceProperties)Ipa(inst, "vkGetPhysicalDeviceProperties");
  VkPhysicalDeviceProperties props; GetProps(hit, &props);
  printf("MATCH=1 NAME=%s id=0x%X\n", props.deviceName, props.deviceID); fflush(stdout);
  float pri = 1.f;
  VkDeviceQueueCreateInfo qci = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO}; qci.queueCount = 1; qci.pQueuePriorities = &pri;
  VkDeviceCreateInfo dci = {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO}; dci.queueCreateInfoCount = 1; dci.pQueueCreateInfos = &qci;
  VkDevice dev = NULL;
  PFN_vkCreateDevice CreateDev = (PFN_vkCreateDevice)Ipa(inst, "vkCreateDevice");
  r = CreateDev(hit, &dci, NULL, &dev);
  printf("A0_RESULT=%d A0=%s\n", (int)r, r == VK_SUCCESS ? "PASS" : "FAIL"); fflush(stdout);
  return r == VK_SUCCESS ? 0 : 20;
}
