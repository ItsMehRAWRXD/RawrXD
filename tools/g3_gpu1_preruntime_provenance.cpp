/* g3_gpu1_preruntime_provenance.cpp — A0 solo/order/qfam discrim (≤99). */
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

static int FindByNeedle(VkInstance inst, const char* needle, ProbePhys* out) {
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

static void EmitQFam(const char* tag, const ProbePhys& o) {
    uint32_t qn = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(o.pd, &qn, nullptr);
    std::vector<VkQueueFamilyProperties> qp(qn);
    vkGetPhysicalDeviceQueueFamilyProperties(o.pd, &qn, qp.data());
    const uint32_t fam = o.computeFamily;
    const uint32_t flags = (fam < qn) ? qp[fam].queueFlags : 0u;
    const uint32_t qc = (fam < qn) ? qp[fam].queueCount : 0u;
    std::printf("%s_NAME=%s\n%s_API=0x%08X\n%s_VRAM_BYTES=%llu\n"
                "%s_QFAM_COUNT=%u\n%s_QFAM_IDX=%u\n%s_QFAM_FLAGS=0x%X\n"
                "%s_QFAM_QCOUNT=%u\n%s_LUID=%s\n",
                tag, o.props.deviceName, tag, o.props.apiVersion, tag,
                (unsigned long long)o.vramBytes, tag, qn, tag, fam, tag, flags,
                tag, qc, tag, o.luidHex);
}

static VkResult EmitA0(const char* tag, const ProbePhys& o, int retries) {
    EmitQFam(tag, o);
    VkResult last = VK_ERROR_UNKNOWN;
    for (int i = 0; i < retries; ++i) {
        VkDevice dev = VK_NULL_HANDLE;
        last = LadderCreateRung(o.pd, o.computeFamily, 0, &dev);
        std::printf("%s_A0_TRY=%d\n%s_A0_CREATE=%s\n%s_A0_VK_RESULT=%d\n", tag,
                    i, tag, ProbeVkResStr(last), tag, (int)last);
        if (dev) vkDestroyDevice(dev, nullptr);
        if (last == VK_SUCCESS) break;
#ifdef _WIN32
        Sleep(200);
#endif
    }
    return last;
}

int main(int argc, char** argv) {
    const char* mode = (argc > 1) ? argv[1] : "order=r9700_first";
    std::printf("GATE=G3_GPU1_A0_CONTEXT_DISCRIM_001\nMODE=%s\n"
                "BEHAVIOR_PATCH=0\nPROMOTE=0\nSTREAMER_EXE=FROZEN\n",
                mode);
    VkInstance inst = VK_NULL_HANDLE;
    if (ProbeMakeInstance(&inst) != VK_SUCCESS) return 10;
    ProbePhys a{}, b{};
    const int okA = FindByNeedle(inst, "R9700", &a);
    const int okB = FindByNeedle(inst, "7800", &b);
    std::printf("R9700_FOUND=%d\nRX7800XT_FOUND=%d\n", okA, okB);
    if (std::strcmp(mode, "solo=R9700") == 0) {
        if (!okA) return 11;
        EmitA0("SOLO_R9700", a, 3);
    } else if (std::strcmp(mode, "solo=7800") == 0) {
        if (!okB) return 11;
        EmitA0("SOLO_7800", b, 3);
    } else if (std::strcmp(mode, "order=7800_first") == 0) {
        if (!okA || !okB) return 11;
        EmitA0("FIRST_7800", b, 1);
        EmitA0("SECOND_R9700", a, 1);
    } else {
        if (!okA || !okB) return 11;
        EmitA0("FIRST_R9700", a, 1);
        EmitA0("SECOND_7800", b, 1);
    }
    std::printf("A0_CREATE_SHAPE=queue_only features=null pNext=null ext=0 "
                "QUEUE_COUNT=1\n");
    vkDestroyInstance(inst, nullptr);
    return 0;
}
