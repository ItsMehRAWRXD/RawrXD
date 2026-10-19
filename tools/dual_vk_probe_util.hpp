/* dual_vk_probe_util.hpp — shared types/helpers (≤99). */
#pragma once
#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

inline bool ProbeNameHas(const char* hay, const char* needle) {
    if (!hay || !needle || !*needle) return false;
    const size_t nlen = std::strlen(needle);
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        while (p[i] && i < nlen) {
            char a = p[i], b = needle[i];
            if (a >= 'a' && a <= 'z') a = (char)(a - 32);
            if (b >= 'a' && b <= 'z') b = (char)(b - 32);
            if (a != b) break;
            ++i;
        }
        if (i == nlen) return true;
    }
    return false;
}

inline const char* ProbeVkResStr(VkResult r) {
    if (r == VK_SUCCESS) return "VK_SUCCESS";
    if (r == VK_ERROR_OUT_OF_HOST_MEMORY) return "VK_ERROR_OUT_OF_HOST_MEMORY";
    if (r == VK_ERROR_OUT_OF_DEVICE_MEMORY) return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
    if (r == VK_ERROR_INITIALIZATION_FAILED) return "VK_ERROR_INITIALIZATION_FAILED";
    if (r == VK_ERROR_DEVICE_LOST) return "VK_ERROR_DEVICE_LOST";
    if (r == VK_ERROR_EXTENSION_NOT_PRESENT) return "VK_ERROR_EXTENSION_NOT_PRESENT";
    if (r == VK_ERROR_FEATURE_NOT_PRESENT) return "VK_ERROR_FEATURE_NOT_PRESENT";
    if (r == VK_ERROR_TOO_MANY_OBJECTS) return "VK_ERROR_TOO_MANY_OBJECTS";
    if (r == VK_ERROR_INCOMPATIBLE_DRIVER) return "VK_ERROR_INCOMPATIBLE_DRIVER";
    if (r == VK_ERROR_UNKNOWN) return "VK_ERROR_UNKNOWN";
    return "VK_RESULT_OTHER";
}

struct ProbePhys {
    VkPhysicalDevice pd = VK_NULL_HANDLE;
    uint32_t enumIndex = 0;
    VkPhysicalDeviceProperties props{};
    VkPhysicalDeviceIDProperties idProps{};
    uint32_t computeFamily = UINT32_MAX;
    uint32_t queueCount = 0;
    uint64_t vramBytes = 0;
    int discrete = 0;
    int pciAvail = 0;
    uint32_t pciDomain = 0, pciBus = 0, pciDevice = 0, pciFunction = 0;
    char uuidHex[65]{};
    char luidHex[17]{};
};

inline void ProbeFmtUuid(char* out, size_t n, const uint8_t* u) {
    for (int i = 0; i < 16 && (size_t)(i * 2 + 2) < n; ++i)
        std::snprintf(out + i * 2, 3, "%02X", u[i]);
}

inline VkResult ProbeMakeInstance(VkInstance* out) {
    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "dual_vk_open_probe";
    app.apiVersion = VK_API_VERSION_1_2;
    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;
    return vkCreateInstance(&ci, nullptr, out);
}

void ProbeFillPhys(VkPhysicalDevice pd, uint32_t idx, ProbePhys& o);
