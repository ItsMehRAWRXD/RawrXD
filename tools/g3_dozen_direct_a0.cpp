/* g3_dozen_direct_a0.cpp — P5 direct Dozen ICD A0 (no vulkan-1) ≤99. */
#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>
#include <vulkan/vk_icd.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>

static int NameHas(const char* hay, const char* n) {
    if (!hay || !n) return 0;
    size_t N = std::strlen(n);
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        while (p[i] && i < N) {
            char a = p[i], b = n[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
            ++i;
        }
        if (i == N) return 1;
    }
    return 0;
}

PFN_vk_icdGetInstanceProcAddr g_gipa;
static PFN_vkVoidFunction Ipa(VkInstance i, const char* n) {
    return g_gipa ? g_gipa(i, n) : nullptr;
}

int main(int argc, char** argv) {
    const char* needle = (argc >= 2) ? argv[1] : "7800";
    const char* path =
        "C:\\Program Files\\WindowsApps\\Microsoft.D3DMappingLayers_"
        "1.2404.1.0_x64__8wekyb3d8bbwe\\x64\\vulkan_dzn.dll";
    printf("GATE=G3_GPU1_AMDVLK_UNBLOCK_001/P5\nDIRECT_DOZEN=1\n"
           "NEEDLE=%s\nPROMOTE=0\n",
           needle);
    HMODULE dll = LoadLibraryA(path);
    printf("LoadLibrary=%s\n", dll ? "PASS" : "FAIL");
    if (!dll) {
        printf("GLE=%lu\n", GetLastError());
        return 10;
    }
    auto neg = (PFN_vk_icdNegotiateLoaderICDInterfaceVersion)GetProcAddress(
        dll, "vk_icdNegotiateLoaderICDInterfaceVersion");
    g_gipa = (PFN_vk_icdGetInstanceProcAddr)GetProcAddress(
        dll, "vk_icdGetInstanceProcAddr");
    if (!g_gipa) return 11;
    uint32_t ver = CURRENT_LOADER_ICD_INTERFACE_VERSION;
    if (neg) {
        VkResult nr = neg(&ver);
        printf("NEGOTIATE=%d VER=%u\n", (int)nr, ver);
    }
    auto CreateInstance =
        (PFN_vkCreateInstance)Ipa(VK_NULL_HANDLE, "vkCreateInstance");
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo ici{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    ici.pApplicationInfo = &app;
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = CreateInstance(&ici, nullptr, &inst);
    printf("vkCreateInstance=%d\n", (int)r);
    if (r) return 12;
    auto EnumPD =
        (PFN_vkEnumeratePhysicalDevices)Ipa(inst, "vkEnumeratePhysicalDevices");
    auto GetProps = (PFN_vkGetPhysicalDeviceProperties)Ipa(
        inst, "vkGetPhysicalDeviceProperties");
    auto GetQ = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)Ipa(
        inst, "vkGetPhysicalDeviceQueueFamilyProperties");
    auto CreateDev = (PFN_vkCreateDevice)Ipa(inst, "vkCreateDevice");
    uint32_t n = 0;
    EnumPD(inst, &n, nullptr);
    printf("PHYS_COUNT=%u\n", n);
    std::vector<VkPhysicalDevice> pds(n);
    EnumPD(inst, &n, pds.data());
    VkPhysicalDevice hit = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties props{};
    for (uint32_t i = 0; i < n; ++i) {
        GetProps(pds[i], &props);
        printf("PHYS_%u=%s id=0x%X\n", i, props.deviceName, props.deviceID);
        if (NameHas(props.deviceName, needle)) hit = pds[i];
    }
    if (!hit) {
        printf("MATCH=0\nA0=FAIL\n");
        return 13;
    }
    GetProps(hit, &props);
    printf("MATCH=1\nNAME=%s\n", props.deviceName);
    float pri = 1.f;
    VkDeviceQueueCreateInfo qci{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    qci.queueCount = 1;
    qci.pQueuePriorities = &pri;
    VkDeviceCreateInfo dci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    VkDevice dev = VK_NULL_HANDLE;
    r = CreateDev(hit, &dci, nullptr, &dev);
    printf("A0_RESULT=%d\nA0=%s\n", (int)r, r == VK_SUCCESS ? "PASS" : "FAIL");
    return r == VK_SUCCESS ? 0 : 20;
}
