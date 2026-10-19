/* g3_gpu1_diag_ladder.cpp — create reduction ladder (≤99). */
#include "dual_vk_probe_util.hpp"
#include <vector>

/* rung: 0=minimal core 1=zeroed features 2=features2 pNext
   3=req ext if present 4=opt ext 5=baseline 2q production-shaped */
VkResult DiagCreateRung(VkPhysicalDevice pd, uint32_t fam, int rung,
                        uint32_t* outExtN, uint32_t* outQ, VkDevice* out) {
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
                if (!std::strcmp(e.extensionName, name)) return true;
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
        const uint32_t aq = (fam < qn) ? qp[fam].queueCount : 1u;
        qci.queueCount = aq >= 2u ? 2u : 1u;
        qci.pQueuePriorities = prios2;
        dci.pEnabledFeatures = &feats; /* production Deep2: ext=0 */
    }

    const VkResult r = vkCreateDevice(pd, &dci, nullptr, out);
    if (outExtN) *outExtN = dci.enabledExtensionCount;
    if (outQ) *outQ = qci.queueCount;
    return r;
}

void DiagRunLadder(const char* tag, const ProbePhys& o) {
    static const char* ids[] = {
        "CREATE_MINIMAL_CORE_ONLY", "CREATE_NO_OPTIONAL_FEATURES",
        "CREATE_FEATURES2_PNEXT", "CREATE_NO_OPTIONAL_EXTENSIONS",
        "CREATE_WITH_OPTIONAL_EXTENSIONS", "CREATE_BASELINE_CURRENT_ARGS"};
    static const char* deltas[] = {
        "queue_only features=null pNext=null ext=0 q=1",
        "+ zeroed VkPhysicalDeviceFeatures",
        "+ Features2 pNext chain",
        "+ maintenance1 if advertised + zeroed features",
        "+ optional storage/float16 exts if advertised",
        "production-shaped: <=2q + zeroed features + ext=0"};
    std::printf("\n=== LADDER_%s ===\n", tag);
    int firstFail = -1, firstPass = -1;
    for (int i = 0; i < 6; ++i) {
        VkDevice dev = VK_NULL_HANDLE;
        uint32_t extN = 0, qn = 0;
        VkResult r = DiagCreateRung(o.pd, o.computeFamily, i, &extN, &qn, &dev);
        std::printf("%s=%s\n%s_VK_RESULT=%d\n%s_VK_RESULT_STR=%s\n"
                    "REQUESTED_EXTENSION_COUNT=%u\nSELECTED_QUEUE_COUNT=%u\n"
                    "DELTA=%s\n",
                    ids[i], r == VK_SUCCESS ? "PASS" : "FAIL", ids[i], (int)r,
                    ids[i], ProbeVkResStr(r), extN, qn, deltas[i]);
        if (r != VK_SUCCESS && firstFail < 0) firstFail = i;
        if (r == VK_SUCCESS && firstPass < 0) firstPass = i;
        if (dev) vkDestroyDevice(dev, nullptr);
    }
    std::printf("FIRST_FAIL_RUNG=%d\nFIRST_PASS_RUNG=%d\n", firstFail,
                firstPass);
}
