/* dual_vk_probe_device.cpp — vkCreateDevice + UUID rebind (≤99). */
#include "dual_vk_probe_util.hpp"

VkResult ProbeCreateComputeDeviceN(VkPhysicalDevice pd, uint32_t fam,
                                   uint32_t nQ, VkDevice* out,
                                   const char* tag) {
    if (fam == UINT32_MAX) {
        std::printf("VK_STAGE=queueFamilySelect\nVK_TAG=%s\nVK_RESULT=-1\n"
                    "VK_RESULT_STR=NO_COMPUTE_QUEUE\n",
                    tag);
        return VK_ERROR_INITIALIZATION_FAILED;
    }
    if (nQ < 1) nQ = 1;
    float prios[2] = {1.f, 1.f};
    VkDeviceQueueCreateInfo qci{};
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = fam;
    qci.queueCount = nQ;
    qci.pQueuePriorities = prios;
    VkDeviceCreateInfo dci{};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    const VkResult r = vkCreateDevice(pd, &dci, nullptr, out);
    std::printf("VK_STAGE=vkCreateDevice\nVK_TAG=%s\nVK_QUEUE_COUNT=%u\n"
                "VK_RESULT=%d\nVK_RESULT_STR=%s\n",
                tag, nQ, (int)r, ProbeVkResStr(r));
    return r;
}

VkResult ProbeCreateComputeDevice(VkPhysicalDevice pd, uint32_t fam,
                                  uint32_t availQ, VkDevice* out,
                                  const char* tag) {
    const uint32_t nQ = availQ >= 2u ? 2u : 1u;
    return ProbeCreateComputeDeviceN(pd, fam, nQ, out, tag);
}

int ProbeFindByUuid(VkInstance inst, const char* uuid, const char* luidOpt,
                    ProbePhys* filled) {
    uint32_t count = 0;
    vkEnumeratePhysicalDevices(inst, &count, nullptr);
    std::vector<VkPhysicalDevice> pds(count);
    vkEnumeratePhysicalDevices(inst, &count, pds.data());
    for (uint32_t i = 0; i < count; ++i) {
        ProbePhys t;
        ProbeFillPhys(pds[i], i, t);
        if (std::strcmp(t.uuidHex, uuid) == 0) {
            if (filled) *filled = t;
            return 1;
        }
    }
    if (!luidOpt || !luidOpt[0] || std::strcmp(luidOpt, "-") == 0) return 0;
    for (uint32_t i = 0; i < count; ++i) {
        ProbePhys t;
        ProbeFillPhys(pds[i], i, t);
        if (!t.idProps.deviceLUIDValid) continue;
        if (std::strcmp(t.luidHex, luidOpt) != 0) continue;
        if (filled) *filled = t;
        std::printf("REBIND_FALLBACK=LUID uuid=%s\n", uuid);
        return 1;
    }
    return 0;
}
