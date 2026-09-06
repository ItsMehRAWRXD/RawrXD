// StreamerGpuSoloVk.cpp — enum all physdevs; CreateDevice on planned primary only
#include "StreamerGpuSoloGate.hpp"
#include "Deep2DeviceManager.hpp"
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
namespace {
bool HasI(const char* s, const char* n) noexcept {
    if (!s || !n || !*n) return false;
    for (; *s; ++s) {
        const char* a = s; const char* b = n;
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
            if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
            if (ca != cb) break;
            ++a; ++b;
        }
        if (!*b) return true;
    }
    return false;
}
} // namespace

int RunStreamerGpuSoloVkProbe(GpuSoloReport& out) noexcept {
    out.vkCreateSelected = 0;
#if !DEEP2_SOLO_VK
    out.blocker = "VULKAN_HEADERS_ABSENT";
    return 0;
#else
#ifdef _WIN32
    Deep2DevicePlan plan{};
    Deep2Device_Enumerate(plan);
    Deep2Device_ApplyPolicy(plan);
    const char* wantName = Deep2Device_VulkanNeedle(plan);
    if (!wantName || !*wantName) {
        out.blocker = "NO_COMPUTE_PRIMARY";
        return 0;
    }

    HMODULE dll = LoadLibraryA("vulkan-1.dll");
    if (!dll) { out.blocker = "VULKAN_LOADER_ABSENT"; return 0; }
    auto pCreateInst = (PFN_vkCreateInstance)GetProcAddress(dll, "vkCreateInstance");
    auto pDestroyInst = (PFN_vkDestroyInstance)GetProcAddress(dll, "vkDestroyInstance");
    auto pEnum = (PFN_vkEnumeratePhysicalDevices)GetProcAddress(dll, "vkEnumeratePhysicalDevices");
    auto pProps = (PFN_vkGetPhysicalDeviceProperties)GetProcAddress(dll, "vkGetPhysicalDeviceProperties");
    auto pMem = (PFN_vkGetPhysicalDeviceMemoryProperties)GetProcAddress(dll, "vkGetPhysicalDeviceMemoryProperties");
    auto pQFam = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)
        GetProcAddress(dll, "vkGetPhysicalDeviceQueueFamilyProperties");
    auto pCreateDev = (PFN_vkCreateDevice)GetProcAddress(dll, "vkCreateDevice");
    auto pDestroyDev = (PFN_vkDestroyDevice)GetProcAddress(dll, "vkDestroyDevice");
    if (!pCreateInst || !pDestroyInst || !pEnum || !pProps || !pMem || !pQFam ||
        !pCreateDev || !pDestroyDev) {
        FreeLibrary(dll);
        out.blocker = "VULKAN_PROC_ABSENT";
        return 0;
    }

    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "Deep2DeviceSolo";
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
    uint64_t bestVram = 0;
    for (uint32_t i = 0; i < n; ++i) {
        VkPhysicalDeviceProperties props{};
        pProps(phys[i], &props);
        printf("DEEP2_VK_PHYS_%u_NAME=%s TYPE=%u\n", i, props.deviceName, props.deviceType);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU)
            continue;
        if (!HasI(props.deviceName, wantName) && !HasI(wantName, props.deviceName)) {
            bool hit = false;
            const char* t = wantName;
            while (*t) {
                while (*t == ' ' || *t == '(' || *t == ')') ++t;
                char tok[32]{};
                size_t k = 0;
                while (*t && *t != ' ' && *t != '(' && k + 1 < sizeof(tok))
                    tok[k++] = *t++;
                if (k >= 4 && HasI(props.deviceName, tok)) { hit = true; break; }
            }
            if (!hit) continue;
        }
        VkPhysicalDeviceMemoryProperties mem{};
        pMem(phys[i], &mem);
        uint64_t vram = 0;
        for (uint32_t h = 0; h < mem.memoryHeapCount; ++h) {
            if (mem.memoryHeaps[h].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)
                if (mem.memoryHeaps[h].size > vram) vram = mem.memoryHeaps[h].size;
        }
        if (!want || vram > bestVram) {
            want = phys[i];
            bestVram = vram;
        }
    }
    if (!want) {
        pDestroyInst(inst, nullptr);
        FreeLibrary(dll);
        out.blocker = "VK_PRIMARY_NOT_IN_ENUM";
        return 0;
    }

    uint32_t qn = 0;
    pQFam(want, &qn, nullptr);
    VkQueueFamilyProperties qf[8]{};
    if (qn > 8) qn = 8;
    pQFam(want, &qn, qf);
    uint32_t qidx = 0;
    for (uint32_t i = 0; i < qn; ++i)
        if (qf[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { qidx = i; break; }
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
    if (pCreateDev(want, &dci, nullptr, &dev) == VK_SUCCESS && dev) {
        out.vkCreateSelected = 1;
        pDestroyDev(dev, nullptr);
        out.blocker = "GGUF_DECODE_NOT_ON_GPU";
    } else {
        out.vkCreateSelected = 0;
        out.blocker = "VK_CREATE_DEVICE_FAIL";
    }
    pDestroyInst(inst, nullptr);
    FreeLibrary(dll);
    return out.vkCreateSelected;
#else
    out.blocker = "VULKAN_PROBE_NON_WIN32";
    return 0;
#endif
#endif
}

} // namespace Deep2
