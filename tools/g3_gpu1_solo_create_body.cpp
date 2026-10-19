/* g3_gpu1_solo_create_body.cpp — queue provenance + A0 create (≤99). */
#include "dual_vk_probe_util.hpp"
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

void ProbeFillPhys(VkPhysicalDevice pd, uint32_t idx, ProbePhys& o);
VkResult LadderCreateRung(VkPhysicalDevice pd, uint32_t fam, int rung,
                          VkDevice* out);

int FindGpuNeedle(VkInstance inst, const char* needle, ProbePhys* out) {
    uint32_t n = 0;
    vkEnumeratePhysicalDevices(inst, &n, nullptr);
    std::vector<VkPhysicalDevice> pds(n);
    vkEnumeratePhysicalDevices(inst, &n, pds.data());
    for (uint32_t i = 0; i < n; ++i) {
        ProbePhys t;
        ProbeFillPhys(pds[i], i, t);
        if (!t.discrete || !ProbeNameHas(t.props.deviceName, needle)) continue;
        *out = t;
        return 1;
    }
    return 0;
}

void EmitQueueProvenance(const char* tag, const ProbePhys& o) {
    uint32_t qn = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(o.pd, &qn, nullptr);
    std::vector<VkQueueFamilyProperties> qp(qn);
    vkGetPhysicalDeviceQueueFamilyProperties(o.pd, &qn, qp.data());
    std::printf("%s_NAME=%s\n%s_DEVICE_ID=0x%04X\n%s_LUID=%s\n"
                "%s_UUID=%s\n%s_ENUM_INDEX=%u\n%s_QUEUE_FAMILY_COUNT=%u\n"
                "%s_SELECTED_QUEUE_FAMILY=%u\n%s_SELECTED_QUEUE_COUNT=%u\n"
                "%s_SELECTED_QUEUE_FLAGS=0x%X\n%s_VRAM_BYTES=%llu\n",
                tag, o.props.deviceName, tag, o.props.deviceID, tag, o.luidHex,
                tag, o.uuidHex, tag, o.enumIndex, tag, qn, tag, o.computeFamily,
                tag, o.queueCount, tag,
                (o.computeFamily < qn) ? qp[o.computeFamily].queueFlags : 0u,
                tag, (unsigned long long)o.vramBytes);
    VkPhysicalDeviceMemoryProperties mem{};
    vkGetPhysicalDeviceMemoryProperties(o.pd, &mem);
    std::printf("%s_MEMORY_HEAP_COUNT=%u\n", tag, mem.memoryHeapCount);
    for (uint32_t h = 0; h < mem.memoryHeapCount && h < 4; ++h) {
        std::printf("%s_HEAP_%u_SIZE=%llu %s_HEAP_%u_FLAGS=0x%X\n", tag, h,
                    (unsigned long long)mem.memoryHeaps[h].size, tag, h,
                    mem.memoryHeaps[h].flags);
    }
}

int EmitA0Create(const char* tag, const ProbePhys& o, int retries) {
    int pass = 0, fail = 0, last = 0;
    for (int i = 0; i < retries; ++i) {
        VkDevice dev = VK_NULL_HANDLE;
        const VkResult r = LadderCreateRung(o.pd, o.computeFamily, 0, &dev);
        last = (int)r;
        std::printf("%s_A0_TRY_%d=%s VK_RESULT=%d\n", tag, i,
                    r == VK_SUCCESS ? "PASS" : "FAIL", (int)r);
        if (r == VK_SUCCESS) {
            ++pass;
            if (dev) vkDestroyDevice(dev, nullptr);
        } else {
            ++fail;
        }
#ifdef _WIN32
        if (r != VK_SUCCESS && i + 1 < retries) Sleep(50);
#endif
    }
    std::printf("%s_A0_PASS_COUNT=%d\n%s_A0_FAIL_COUNT=%d\n"
                "%s_A0_LAST_VK_RESULT=%d\n%s_A0_CREATE=%s\n",
                tag, pass, tag, fail, tag, last, tag,
                pass > 0 ? "PASS" : "FAIL");
    return pass > 0 ? 0 : 1;
}
