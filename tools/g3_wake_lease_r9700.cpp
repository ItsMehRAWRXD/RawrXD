/* g3_wake_lease_a0.cpp — P2: D3D12 wake + direct ICD A0 (≤99). */
#define VK_USE_PLATFORM_WIN32_KHR
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d12.h>
#include <vulkan/vulkan.h>
#include <vulkan/vk_icd.h>
#include <cstdio>
#include <cstring>
#include <vector>

HRESULT Wake7800(ID3D12Device** outDev, ID3D12Resource** outBuf);
int NameHas(const char* hay, const char* n);
PFN_vk_icdGetInstanceProcAddr g_icdGipa = nullptr;

static PFN_vkVoidFunction Ipa(VkInstance i, const char* n) {
    return g_icdGipa ? g_icdGipa(i, n) : nullptr;
}

int main() {
    std::printf("GATE=G3_GPU1_AMDVLK_UNBLOCK_001\nPHASE=P2_WAKE_LEASE\n"
                "VULKAN_LOADER_USED=0\nPROMOTE=0\n");
    ID3D12Device* d3 = nullptr;
    ID3D12Resource* buf = nullptr;
    HRESULT hr = Wake7800(&d3, &buf);
    std::printf("D3D12_WAKE_HR=0x%08X\nD3D12_WAKE=%s\n", (unsigned)hr,
                SUCCEEDED(hr) ? "PASS" : "FAIL");
    if (FAILED(hr)) return 10;

    const char* path =
        "C:\\Windows\\System32\\DriverStore\\FileRepository\\"
        "amdvlk.inf_amd64_914ba89eaaafdf60\\amdvlk64.dll";
    HMODULE dll = LoadLibraryA(path);
    std::printf("AMDVLK_LoadLibrary=%s\n", dll ? "PASS" : "FAIL");
    if (!dll) return 11;
    auto neg = (PFN_vk_icdNegotiateLoaderICDInterfaceVersion)GetProcAddress(
        dll, "vk_icdNegotiateLoaderICDInterfaceVersion");
    g_icdGipa = (PFN_vk_icdGetInstanceProcAddr)GetProcAddress(
        dll, "vk_icdGetInstanceProcAddr");
    if (!g_icdGipa) return 12;
    uint32_t ver = CURRENT_LOADER_ICD_INTERFACE_VERSION;
    if (neg) neg(&ver);

    auto CreateInstance =
        (PFN_vkCreateInstance)Ipa(VK_NULL_HANDLE, "vkCreateInstance");
    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.apiVersion = VK_API_VERSION_1_2;
    VkInstanceCreateInfo ici{};
    ici.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ici.pApplicationInfo = &app;
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = CreateInstance(&ici, nullptr, &inst);
    std::printf("VK_CREATE_INSTANCE=%d\n", (int)r);
    if (r != VK_SUCCESS) return 13;

    auto EnumPD =
        (PFN_vkEnumeratePhysicalDevices)Ipa(inst, "vkEnumeratePhysicalDevices");
    auto GetProps = (PFN_vkGetPhysicalDeviceProperties)Ipa(
        inst, "vkGetPhysicalDeviceProperties");
    auto GetQ = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)Ipa(
        inst, "vkGetPhysicalDeviceQueueFamilyProperties");
    auto CreateDev = (PFN_vkCreateDevice)Ipa(inst, "vkCreateDevice");
    auto DestroyInst = (PFN_vkDestroyInstance)Ipa(inst, "vkDestroyInstance");
    auto DestroyDev = (PFN_vkDestroyDevice)Ipa(inst, "vkDestroyDevice");

    uint32_t n = 0;
    EnumPD(inst, &n, nullptr);
    std::vector<VkPhysicalDevice> pds(n);
    EnumPD(inst, &n, pds.data());
    VkPhysicalDevice hit = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties props{};
    for (uint32_t i = 0; i < n; ++i) {
        GetProps(pds[i], &props);
        if (NameHas(props.deviceName, "7800")) {
            hit = pds[i];
            break;
        }
    }
    std::printf("VK_MATCH_7800=%d\nVK_NAME=%s\n", hit ? 1 : 0,
                hit ? props.deviceName : "-");
    if (!hit) return 14;

    uint32_t qn = 0;
    GetQ(hit, &qn, nullptr);
    std::vector<VkQueueFamilyProperties> qp(qn);
    GetQ(hit, &qn, qp.data());
    uint32_t fam = 0;
    for (uint32_t i = 0; i < qn; ++i)
        if (qp[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            fam = i;
            break;
        }
    float prio = 1.f;
    VkDeviceQueueCreateInfo qci{};
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = fam;
    qci.queueCount = 1;
    qci.pQueuePriorities = &prio;
    VkDeviceCreateInfo dci{};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    VkDevice vdev = VK_NULL_HANDLE;
    r = CreateDev(hit, &dci, nullptr, &vdev);
    std::printf("WAKE_LEASE_A0_RESULT=%d\nWAKE_LEASE_A0=%s\n", (int)r,
                r == VK_SUCCESS ? "PASS" : "FAIL");
    if (vdev && DestroyDev) DestroyDev(vdev, nullptr);
    if (DestroyInst) DestroyInst(inst, nullptr);
    FreeLibrary(dll);
    if (buf) buf->Release();
    if (d3) d3->Release();
    return r == VK_SUCCESS ? 0 : 20;
}
