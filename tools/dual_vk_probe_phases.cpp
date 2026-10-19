/* dual_vk_probe_phases.cpp — solo / same-instance / separate-instance. */
#include "dual_vk_probe_util.hpp"

VkResult ProbeCreateComputeDevice(VkPhysicalDevice pd, uint32_t fam,
                                  uint32_t availQ, VkDevice* out,
                                  const char* tag);
int ProbeFindByUuid(VkInstance inst, const char* uuid, const char* luidOpt,
                    ProbePhys* filled);

static const char* LuidOrNull(const ProbePhys& p) {
    return p.idProps.deviceLUIDValid ? p.luidHex : nullptr;
}

int ProbeSolo7800(const ProbePhys& stick1, int* vkResultOut) {
    std::printf("PHASE=SOLO_7800\n");
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = ProbeMakeInstance(&inst);
    std::printf("VK_STAGE=vkCreateInstance\nVK_TAG=solo_7800\nVK_RESULT=%d\n"
                "VK_RESULT_STR=%s\n",
                (int)r, ProbeVkResStr(r));
    if (r != VK_SUCCESS) {
        if (vkResultOut) *vkResultOut = (int)r;
        return 1;
    }
    ProbePhys live{};
    if (!ProbeFindByUuid(inst, stick1.uuidHex, LuidOrNull(stick1), &live)) {
        std::printf("VK_STAGE=reEnumerateIdentify\nVK_TAG=solo_7800\n"
                    "VK_RESULT=-1\nVK_RESULT_STR=UUID_REBIND_FAIL\n"
                    "SOLO_7800_CREATE=FAIL\nSOLO_7800_VK_RESULT=-1\n");
        if (vkResultOut) *vkResultOut = -1;
        vkDestroyInstance(inst, nullptr);
        return 2;
    }
    VkDevice solo = VK_NULL_HANDLE;
    r = ProbeCreateComputeDevice(live.pd, live.computeFamily, live.queueCount,
                                 &solo, "solo_7800");
    std::printf("SOLO_7800_CREATE=%s\nSOLO_7800_VK_RESULT=%d\n",
                r == VK_SUCCESS ? "PASS" : "FAIL", (int)r);
    if (vkResultOut) *vkResultOut = (int)r;
    /* Destroy device BEFORE same-instance dual — no three-device lifetime. */
    if (solo) {
        vkDestroyDevice(solo, nullptr);
        solo = VK_NULL_HANDLE;
    }
    vkDestroyInstance(inst, nullptr);
    return r == VK_SUCCESS ? 0 : 3;
}

int ProbeSameInstanceDual(const ProbePhys& s0, const ProbePhys& s1) {
    std::printf("PHASE=SAME_INSTANCE_DUAL\nINSTANCE_COUNT=1\n");
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = ProbeMakeInstance(&inst);
    std::printf("VK_STAGE=vkCreateInstance\nVK_TAG=same_dual\nVK_RESULT=%d\n"
                "VK_RESULT_STR=%s\n",
                (int)r, ProbeVkResStr(r));
    if (r != VK_SUCCESS) return 1;
    ProbePhys a{}, b{};
    if (!ProbeFindByUuid(inst, s0.uuidHex, LuidOrNull(s0), &a) ||
        !ProbeFindByUuid(inst, s1.uuidHex, LuidOrNull(s1), &b)) {
        std::printf("VK_STAGE=reEnumerateIdentify\nVK_TAG=same_dual\n"
                    "VK_RESULT=-1\nSAME_INSTANCE_DUAL=FAIL\n");
        vkDestroyInstance(inst, nullptr);
        return 2;
    }
    VkDevice d0 = VK_NULL_HANDLE, d1 = VK_NULL_HANDLE;
    r = ProbeCreateComputeDevice(a.pd, a.computeFamily, a.queueCount, &d0,
                                 "same_r9700");
    std::printf("SAME_INSTANCE_R9700_CREATE=%s\nSAME_INSTANCE_R9700_VK_RESULT=%d\n",
                r == VK_SUCCESS ? "PASS" : "FAIL", (int)r);
    if (r != VK_SUCCESS) {
        vkDestroyInstance(inst, nullptr);
        std::printf("SAME_INSTANCE_7800_CREATE=FAIL\nSAME_INSTANCE_DUAL=FAIL\n");
        return 3;
    }
    r = ProbeCreateComputeDevice(b.pd, b.computeFamily, b.queueCount, &d1,
                                 "same_7800");
    std::printf("SAME_INSTANCE_7800_CREATE=%s\nSAME_INSTANCE_7800_VK_RESULT=%d\n",
                r == VK_SUCCESS ? "PASS" : "FAIL", (int)r);
    const int ok = (r == VK_SUCCESS);
    std::printf("SAME_INSTANCE_DUAL=%s\n", ok ? "PASS" : "FAIL");
    if (d1) vkDestroyDevice(d1, nullptr);
    if (d0) vkDestroyDevice(d0, nullptr);
    vkDestroyInstance(inst, nullptr);
    return ok ? 0 : 4;
}

int ProbeSeparateInstances(const ProbePhys& s0, const ProbePhys& s1) {
    std::printf("PHASE=SEPARATE_INSTANCE\nINSTANCE_COUNT=2\n");
    VkInstance i0 = VK_NULL_HANDLE, i1 = VK_NULL_HANDLE;
    VkResult r = ProbeMakeInstance(&i0);
    std::printf("VK_STAGE=vkCreateInstance\nVK_TAG=sep_inst0\nVK_RESULT=%d\n",
                (int)r);
    if (r != VK_SUCCESS) return 1;
    r = ProbeMakeInstance(&i1);
    std::printf("VK_STAGE=vkCreateInstance\nVK_TAG=sep_inst1\nVK_RESULT=%d\n",
                (int)r);
    if (r != VK_SUCCESS) {
        vkDestroyInstance(i0, nullptr);
        return 2;
    }
    ProbePhys a{}, b{};
    VkDevice d0 = VK_NULL_HANDLE, d1 = VK_NULL_HANDLE;
    if (!ProbeFindByUuid(i0, s0.uuidHex, LuidOrNull(s0), &a)) {
        std::printf("VK_STAGE=reEnumerateIdentify\nVK_TAG=sep_r9700\n"
                    "VK_RESULT=-1\nSEPARATE_INSTANCE_R9700_CREATE=FAIL\n"
                    "SEPARATE_INSTANCE_DUAL=FAIL\n");
        vkDestroyInstance(i1, nullptr);
        vkDestroyInstance(i0, nullptr);
        return 3;
    }
    r = ProbeCreateComputeDevice(a.pd, a.computeFamily, a.queueCount, &d0,
                                 "sep_r9700");
    std::printf("SEPARATE_INSTANCE_R9700_CREATE=%s\n"
                "SEPARATE_INSTANCE_R9700_VK_RESULT=%d\n",
                r == VK_SUCCESS ? "PASS" : "FAIL", (int)r);
    VkResult r1 = VK_ERROR_INITIALIZATION_FAILED;
    if (ProbeFindByUuid(i1, s1.uuidHex, LuidOrNull(s1), &b))
        r1 = ProbeCreateComputeDevice(b.pd, b.computeFamily, b.queueCount, &d1,
                                      "sep_7800");
    else
        std::printf("VK_STAGE=reEnumerateIdentify\nVK_TAG=sep_7800\n"
                    "VK_RESULT=-1\n");
    std::printf("SEPARATE_INSTANCE_7800_CREATE=%s\n"
                "SEPARATE_INSTANCE_7800_VK_RESULT=%d\n"
                "SEPARATE_INSTANCE_DUAL=%s\n",
                r1 == VK_SUCCESS ? "PASS" : "FAIL", (int)r1,
                (r == VK_SUCCESS && r1 == VK_SUCCESS) ? "PASS" : "FAIL");
    if (d1) vkDestroyDevice(d1, nullptr);
    if (d0) vkDestroyDevice(d0, nullptr);
    vkDestroyInstance(i1, nullptr);
    vkDestroyInstance(i0, nullptr);
    return (r == VK_SUCCESS && r1 == VK_SUCCESS) ? 0 : 5;
}
