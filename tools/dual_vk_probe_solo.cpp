/* dual_vk_probe_solo.cpp — solo create + Q1 retry + R9700 control. */
#include "dual_vk_probe_util.hpp"

VkResult ProbeCreateComputeDevice(VkPhysicalDevice pd, uint32_t fam,
                                  uint32_t availQ, VkDevice* out,
                                  const char* tag);
VkResult ProbeCreateComputeDeviceN(VkPhysicalDevice pd, uint32_t fam,
                                   uint32_t nQ, VkDevice* out,
                                   const char* tag);
int ProbeFindByUuid(VkInstance inst, const char* uuid, const char* luidOpt,
                    ProbePhys* filled);

static const char* LuidOrNull(const ProbePhys& p) {
    return p.idProps.deviceLUIDValid ? p.luidHex : nullptr;
}

static int SoloOne(const ProbePhys& target, const char* label, int* vkOut) {
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = ProbeMakeInstance(&inst);
    std::printf("VK_STAGE=vkCreateInstance\nVK_TAG=%s\nVK_RESULT=%d\n"
                "VK_RESULT_STR=%s\n",
                label, (int)r, ProbeVkResStr(r));
    if (r != VK_SUCCESS) {
        if (vkOut) *vkOut = (int)r;
        return 1;
    }
    ProbePhys live{};
    if (!ProbeFindByUuid(inst, target.uuidHex, LuidOrNull(target), &live)) {
        std::printf("VK_STAGE=reEnumerateIdentify\nVK_TAG=%s\nVK_RESULT=-1\n"
                    "VK_RESULT_STR=UUID_REBIND_FAIL\n%s_CREATE=FAIL\n"
                    "%s_VK_RESULT=-1\n",
                    label, label, label);
        if (vkOut) *vkOut = -1;
        vkDestroyInstance(inst, nullptr);
        return 2;
    }
    VkDevice dev = VK_NULL_HANDLE;
    const uint32_t want = live.queueCount >= 2u ? 2u : 1u;
    r = ProbeCreateComputeDeviceN(live.pd, live.computeFamily, want, &dev,
                                  label);
    std::printf("%s_CREATE=%s\n%s_VK_RESULT=%d\n", label,
                r == VK_SUCCESS ? "PASS" : "FAIL", label, (int)r);
    if (r != VK_SUCCESS && want > 1u) {
        r = ProbeCreateComputeDeviceN(live.pd, live.computeFamily, 1u, &dev,
                                      "retry_q1");
        std::printf("%s_RETRY_Q1=%s\n%s_RETRY_Q1_VK_RESULT=%d\n", label,
                    r == VK_SUCCESS ? "PASS" : "FAIL", label, (int)r);
    }
    if (vkOut) *vkOut = (int)r;
    if (dev) vkDestroyDevice(dev, nullptr);
    vkDestroyInstance(inst, nullptr);
    return r == VK_SUCCESS ? 0 : 3;
}

int ProbeSolo7800(const ProbePhys& stick1, int* vkResultOut) {
    std::printf("PHASE=SOLO_7800\n");
    return SoloOne(stick1, "SOLO_7800", vkResultOut);
}

int ProbeSoloR9700(const ProbePhys& stick0, int* vkResultOut) {
    std::printf("PHASE=SOLO_R9700\n");
    return SoloOne(stick0, "SOLO_R9700", vkResultOut);
}
