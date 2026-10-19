/* dual_vk_7800_ladder_rungs.cpp — A0–A5 create bodies (≤99). */
#include "dual_vk_probe_util.hpp"
#include <vector>

VkResult LadderCreateRung(VkPhysicalDevice pd, uint32_t fam, int rung,
                          VkDevice* out) {
    float prio = 1.f;
    float prios2[2] = {1.f, 1.f};
    VkDeviceQueueCreateInfo qci{};
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = fam;
    qci.queueCount = 1;
    qci.pQueuePriorities = &prio;

    VkPhysicalDeviceFeatures feats{};
    VkPhysicalDeviceFeatures2 feats2{};
    feats2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;

    const char* exts[4] = {};
    uint32_t extN = 0;
    std::vector<VkExtensionProperties> avail;
    if (rung >= 3) {
        uint32_t n = 0;
        vkEnumerateDeviceExtensionProperties(pd, nullptr, &n, nullptr);
        avail.resize(n);
        vkEnumerateDeviceExtensionProperties(pd, nullptr, &n, avail.data());
        auto has = [&](const char* name) {
            for (auto& e : avail)
                if (std::strcmp(e.extensionName, name) == 0) return true;
            return false;
        };
        if (has("VK_KHR_maintenance1")) exts[extN++] = "VK_KHR_maintenance1";
        if (rung >= 4 && has("VK_KHR_storage_buffer_storage_class"))
            exts[extN++] = "VK_KHR_storage_buffer_storage_class";
        if (rung >= 4 && has("VK_KHR_shader_float16_int8"))
            exts[extN++] = "VK_KHR_shader_float16_int8";
    }

    VkDeviceCreateInfo dci{};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;

    if (rung == 1) {
        dci.pEnabledFeatures = &feats;
    } else if (rung == 2) {
        dci.pNext = &feats2;
    } else if (rung == 3 || rung == 4) {
        dci.pEnabledFeatures = &feats;
        dci.enabledExtensionCount = extN;
        dci.ppEnabledExtensionNames = extN ? exts : nullptr;
    } else if (rung == 5) {
        uint32_t qn = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &qn, nullptr);
        std::vector<VkQueueFamilyProperties> qp(qn);
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &qn, qp.data());
        const uint32_t availQ = (fam < qn) ? qp[fam].queueCount : 1u;
        qci.queueCount = availQ >= 2u ? 2u : 1u;
        qci.pQueuePriorities = prios2;
        dci.pEnabledFeatures = &feats;
    }
    /* rung 0: queue only — all null/zero */

    const VkResult r = vkCreateDevice(pd, &dci, nullptr, out);
    std::printf("VK_STAGE=vkCreateDevice\nVK_RESULT=%d\nVK_RESULT_STR=%s\n"
                "ENABLED_EXT_COUNT=%u\nQUEUE_COUNT=%u\n",
                (int)r, ProbeVkResStr(r), dci.enabledExtensionCount,
                qci.queueCount);
    return r;
}
