/* g3_gpu1_diag_caps.cpp — identity/queue/ext dump (≤99). */
#include "dual_vk_probe_util.hpp"
#include <vector>

void ProbeFillPhys(VkPhysicalDevice pd, uint32_t idx, ProbePhys& o);

static const char* QFlagStr(uint32_t f, char* buf, size_t cap) {
    size_t used = 0;
    buf[0] = '\0';
    auto append = [&](const char* s) {
        if (!s || used >= cap - 1) return;
        const size_t n = std::strlen(s);
        const size_t take = (n < cap - used - 1) ? n : (cap - used - 1);
        std::memcpy(buf + used, s, take);
        used += take;
        buf[used] = '\0';
    };
    if (f & VK_QUEUE_GRAPHICS_BIT) append("G|");
    if (f & VK_QUEUE_COMPUTE_BIT) append("C|");
    if (f & VK_QUEUE_TRANSFER_BIT) append("T|");
    if (f & VK_QUEUE_SPARSE_BINDING_BIT) append("S|");
    return buf;
}

void DiagDumpPhys(const char* tag, const ProbePhys& o) {
    std::printf("\n=== CAPS_%s ===\n", tag);
    std::printf("PHYSICAL_DEVICE_NAME=%s\nVENDOR_ID=0x%04X\nDEVICE_ID=0x%04X\n",
                o.props.deviceName, o.props.vendorID, o.props.deviceID);
    std::printf("DRIVER_VERSION=0x%08X\nAPI_VERSION=0x%08X\n",
                o.props.driverVersion, o.props.apiVersion);
    std::printf("DEVICE_UUID=%s\nDEVICE_LUID=%s\nLUID_VALID=%d\nDISCRETE=%d\n"
                "VRAM_BYTES=%llu\n",
                o.uuidHex, o.luidHex, o.idProps.deviceLUIDValid ? 1 : 0,
                o.discrete, (unsigned long long)o.vramBytes);

    uint32_t qn = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(o.pd, &qn, nullptr);
    std::vector<VkQueueFamilyProperties> qp(qn);
    vkGetPhysicalDeviceQueueFamilyProperties(o.pd, &qn, qp.data());
    std::printf("QUEUE_FAMILY_COUNT=%u\n", qn);
    char fl[32]{};
    for (uint32_t i = 0; i < qn; ++i) {
        QFlagStr(qp[i].queueFlags, fl, sizeof(fl));
        std::printf("QUEUE_FAMILY_%u_FLAGS=%s queueCount=%u\n", i, fl,
                    qp[i].queueCount);
    }
    std::printf("SELECTED_QUEUE_FAMILY=%u\nSELECTED_QUEUE_FLAGS=",
                o.computeFamily);
    if (o.computeFamily < qn)
        std::printf("%s\nSELECTED_QUEUE_COUNT=%u\n",
                    QFlagStr(qp[o.computeFamily].queueFlags, fl, sizeof(fl)),
                    qp[o.computeFamily].queueCount);
    else
        std::printf("NONE\nSELECTED_QUEUE_COUNT=0\n");

    uint32_t en = 0;
    vkEnumerateDeviceExtensionProperties(o.pd, nullptr, &en, nullptr);
    std::vector<VkExtensionProperties> ex(en);
    vkEnumerateDeviceExtensionProperties(o.pd, nullptr, &en, ex.data());
    std::printf("DEVICE_EXTENSION_COUNT=%u\n", en);
    static const char* keys[] = {
        "VK_KHR_maintenance1", "VK_KHR_storage_buffer_storage_class",
        "VK_KHR_shader_float16_int8", "VK_KHR_timeline_semaphore",
        "VK_EXT_memory_budget", nullptr};
    for (int k = 0; keys[k]; ++k) {
        int has = 0;
        for (uint32_t i = 0; i < en; ++i)
            if (!std::strcmp(ex[i].extensionName, keys[k])) has = 1;
        std::printf("EXT_SUPPORT_%s=%d\n", keys[k], has);
    }

    VkPhysicalDeviceFeatures feats{};
    vkGetPhysicalDeviceFeatures(o.pd, &feats);
    std::printf("FEAT_shaderInt16=%u FEAT_shaderFloat64=%u "
                "FEAT_shaderStorageImageExtendedFormats=%u\n",
                feats.shaderInt16, feats.shaderFloat64,
                feats.shaderStorageImageExtendedFormats);
}
