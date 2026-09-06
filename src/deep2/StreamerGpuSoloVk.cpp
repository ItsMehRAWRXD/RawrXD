// StreamerGpuSoloVk.cpp — enumerate all Vulkan physdevs, CreateDevice on R9700 only
#include "StreamerGpuSoloGate.hpp"
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#if defined(RAWR_ENABLE_VULKAN) || defined(RAWR_HAS_VULKAN)
#if __has_include(<vulkan/vulkan.h>)
#include <vulkan/vulkan.h>
#define DEEP2_SOLO_VK 1
#endif
#endif
#ifndef DEEP2_SOLO_VK
#define DEEP2_SOLO_VK 0
#endif

namespace Deep2 {

int RunStreamerGpuSoloVkProbe(GpuSoloReport& out) noexcept {
    out.vkCreateSelected = 0;
#if !DEEP2_SOLO_VK
    out.blocker = "VULKAN_HEADERS_ABSENT";
    return 0;
#else
#ifdef _WIN32
    HMODULE dll = LoadLibraryA("vulkan-1.dll");
    if (!dll) {
        out.blocker = "VULKAN_LOADER_ABSENT";
        return 0;
    }
    auto pCreateInst = (PFN_vkCreateInstance)GetProcAddress(dll, "vkCreateInstance");
    auto pDestroyInst = (PFN_vkDestroyInstance)GetProcAddress(dll, "vkDestroyInstance");
    auto pEnum = (PFN_vkEnumeratePhysicalDevices)GetProcAddress(dll, "vkEnumeratePhysicalDevices");
    auto pProps = (PFN_vkGetPhysicalDeviceProperties)GetProcAddress(dll, "vkGetPhysicalDeviceProperties");
    auto pQFam = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)
        GetProcAddress(dll, "vkGetPhysicalDeviceQueueFamilyProperties");
    auto pCreateDev = (PFN_vkCreateDevice)GetProcAddress(dll, "vkCreateDevice");
    auto pDestroyDev = (PFN_vkDestroyDevice)GetProcAddress(dll, "vkDestroyDevice");
    if (!pCreateInst || !pDestroyInst || !pEnum || !pProps || !pQFam || !pCreateDev || !pDestroyDev) {
        FreeLibrary(dll);
        out.blocker = "VULKAN_PROC_ABSENT";
        return 0;
    }
    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "Deep2GpuSolo";
    app.apiVersion = VK_API_VERSION_1_2;
    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;
    VkInstance inst = VK_NULL_HANDLE;
    if (pCreateInst(&ci, nullptr, &inst) != VK_SUCCESS || !inst) {
        FreeLibrary(dll);
        out.blocker = "VK_CREATE_INSTANCE_FAIL";
        return 0;
    }
    uint32_t n = 0;
    pEnum(inst, &n, nullptr);
    out.vkPhysCount = n;
    VkPhysicalDevice phys[8]{};
    if (n > 8) n = 8;
    pEnum(inst, &n, phys);
    VkPhysicalDevice want = VK_NULL_HANDLE;
    for (uint32_t i = 0; i < n; ++i) {
        VkPhysicalDeviceProperties props{};
        pProps(phys[i], &props);
        printf("DEEP2_VK_PHYS_%u_NAME=%s TYPE=%u\n", i, props.deviceName, props.deviceType);
        const char* p = props.deviceName;
        bool hit = false;
        for (; *p; ++p) {
            if ((p[0] == 'R' || p[0] == 'r') && p[1] == '9' && p[2] == '7' && p[3] == '0' && p[4] == '0')
                hit = true;
            if ((p[0] == 'A' || p[0] == 'a') && (p[1] == 'I' || p[1] == 'i') && p[2] == ' ' &&
                (p[3] == 'P' || p[3] == 'p'))
                hit = true;
        }
        if (hit) want = phys[i];
    }
    if (!want) {
        pDestroyInst(inst, nullptr);
        FreeLibrary(dll);
        out.blocker = "VK_R9700_NOT_IN_ENUM";
        return 0;
    }
    uint32_t qn = 0;
    pQFam(want, &qn, nullptr);
    VkQueueFamilyProperties qf[8]{};
    if (qn > 8) qn = 8;
    pQFam(want, &qn, qf);
    uint32_t qidx = 0;
    for (uint32_t i = 0; i < qn; ++i) {
        if (qf[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { qidx = i; break; }
    }
    float pri = 1.0f;
    VkDeviceQueueCreateInfo qci{};
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = qidx;
    qci.queueCount = 1;
    qci.pQueuePriorities = &pri;
    VkDeviceCreateInfo dci{};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    VkDevice dev = VK_NULL_HANDLE;
    VkResult cr = pCreateDev(want, &dci, nullptr, &dev);
    if (cr == VK_SUCCESS && dev) {
        out.vkCreateSelected = 1;
        pDestroyDev(dev, nullptr);
    } else {
        out.vkCreateSelected = 0;
        out.blocker = "VK_CREATE_DEVICE_FAIL";
    }
    pDestroyInst(inst, nullptr);
    FreeLibrary(dll);
    if (out.vkCreateSelected == 1 && out.openIndex >= 0)
        out.blocker = "GGUF_DECODE_NOT_ON_GPU";
    return out.vkCreateSelected;
#else
    out.blocker = "VULKAN_PROBE_NON_WIN32";
    return 0;
#endif
#endif
}

} // namespace Deep2
