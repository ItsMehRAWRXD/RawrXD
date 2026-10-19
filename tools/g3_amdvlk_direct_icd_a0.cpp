/* g3_amdvlk_direct_icd_a0.cpp — ICD GIPA create/enum/A0 (≤99). */
#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>
#include <vulkan/vk_icd.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>

extern PFN_vk_icdGetInstanceProcAddr g_icdGipa;

static PFN_vkVoidFunction Ipa(VkInstance i, const char* n) {
    return g_icdGipa ? g_icdGipa(i, n) : nullptr;
}

static int NameHas(const char* hay, const char* needle) {
    if (!hay || !needle) return 0;
    const size_t n = std::strlen(needle);
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        while (p[i] && i < n) {
            char a = p[i], b = needle[i];
            if (a >= 'a' && a <= 'z') a = (char)(a - 32);
            if (b >= 'a' && b <= 'z') b = (char)(b - 32);
            if (a != b) break;
            ++i;
        }
        if (i == n) return 1;
    }
    return 0;
}

int RunDirectIcdA0(HMODULE /*dll*/, const char* needle, const char* tag) {
    auto CreateInstance =
        (PFN_vkCreateInstance)Ipa(VK_NULL_HANDLE, "vkCreateInstance");
    std::printf("%s_DIRECT_ICD_CREATE_INSTANCE_FP=%s\n", tag,
                CreateInstance ? "PASS" : "FAIL");
    if (!CreateInstance) return 2;

    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "g3_amdvlk_direct_icd";
    app.apiVersion = VK_API_VERSION_1_2;
    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = CreateInstance(&ci, nullptr, &inst);
    std::printf("%s_DIRECT_ICD_CREATE_INSTANCE=%d\n", tag, (int)r);
    if (r != VK_SUCCESS || !inst) return 3;

    auto EnumPD =
        (PFN_vkEnumeratePhysicalDevices)Ipa(inst, "vkEnumeratePhysicalDevices");
    auto GetProps = (PFN_vkGetPhysicalDeviceProperties)Ipa(
        inst, "vkGetPhysicalDeviceProperties");
    auto GetQ = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)Ipa(
        inst, "vkGetPhysicalDeviceQueueFamilyProperties");
    auto CreateDev = (PFN_vkCreateDevice)Ipa(inst, "vkCreateDevice");
    auto DestroyInst = (PFN_vkDestroyInstance)Ipa(inst, "vkDestroyInstance");
    auto DestroyDev = (PFN_vkDestroyDevice)Ipa(inst, "vkDestroyDevice");
    if (!EnumPD || !GetProps || !GetQ || !CreateDev) {
        std::printf("%s_DIRECT_ICD_ENUM_PHYSICAL=FAIL_FP\n", tag);
        if (DestroyInst) DestroyInst(inst, nullptr);
        return 4;
    }

    uint32_t n = 0;
    EnumPD(inst, &n, nullptr);
    std::vector<VkPhysicalDevice> pds(n);
    EnumPD(inst, &n, pds.data());
    std::printf("%s_DIRECT_ICD_ENUM_PHYSICAL=%u\n", tag, n);

    VkPhysicalDevice hit = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties props{};
    for (uint32_t i = 0; i < n; ++i) {
        GetProps(pds[i], &props);
        if (NameHas(props.deviceName, needle)) {
            hit = pds[i];
            break;
        }
    }
    std::printf("%s_DIRECT_ICD_MATCH=%d\n%s_DIRECT_ICD_NAME=%s\n"
                "%s_DIRECT_ICD_DEVICE_ID=0x%04X\n",
                tag, hit ? 1 : 0, tag, hit ? props.deviceName : "-", tag,
                hit ? props.deviceID : 0);
    if (!hit) {
        if (DestroyInst) DestroyInst(inst, nullptr);
        return 5;
    }

    uint32_t qn = 0;
    GetQ(hit, &qn, nullptr);
    std::vector<VkQueueFamilyProperties> qp(qn);
    GetQ(hit, &qn, qp.data());
    uint32_t fam = UINT32_MAX;
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
    VkDevice dev = VK_NULL_HANDLE;
    r = CreateDev(hit, &dci, nullptr, &dev);
    std::printf("%s_DIRECT_ICD_A0_RESULT=%d\n%s_DIRECT_ICD_A0=%s\n", tag,
                (int)r, tag, r == VK_SUCCESS ? "PASS" : "FAIL");
    if (dev && DestroyDev) DestroyDev(dev, nullptr);
    if (DestroyInst) DestroyInst(inst, nullptr);
    return r == VK_SUCCESS ? 0 : 6;
}
