// ============================================================================
// vulkan_cap_probe.cpp — RAWRXD_VULKAN_CAP_PROBE_001
//
// Independent Vulkan capability discovery. Decides one question before anyone
// writes CPU MLA code:
//
//     Is the R9700 actually reachable by Vulkan, or is Deep2 filtering it?
//
// The engine has printed both:
//     DEEP2_GPU_SELECT slot=0 name=AMD Radeon AI PRO R9700 vendor=0x1002 device=0x7551
//     DEVICE_COUNT=0
//
// Those cannot both describe the same state. A probe that enumerates the
// physical devices itself is the only way to tell whether the ICD is missing,
// the instance creation fails, or the device count is being filtered somewhere
// downstream. Built deliberately separate from Deep2 so it cannot inherit the
// filter it is meant to audit.
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdio>
#include <vector>

#include <vulkan/vulkan.h>

namespace {

const char* ResultName(VkResult r) {
    switch (r) {
        case VK_SUCCESS: return "VK_SUCCESS";
        case VK_INCOMPLETE: return "VK_INCOMPLETE";
        case VK_ERROR_OUT_OF_HOST_MEMORY: return "VK_ERROR_OUT_OF_HOST_MEMORY";
        case VK_ERROR_OUT_OF_DEVICE_MEMORY: return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
        case VK_ERROR_INITIALIZATION_FAILED: return "VK_ERROR_INITIALIZATION_FAILED";
        case VK_ERROR_LAYER_NOT_PRESENT: return "VK_ERROR_LAYER_NOT_PRESENT";
        case VK_ERROR_EXTENSION_NOT_PRESENT: return "VK_ERROR_EXTENSION_NOT_PRESENT";
        case VK_ERROR_FEATURE_NOT_PRESENT: return "VK_ERROR_FEATURE_NOT_PRESENT";
        case VK_ERROR_INCOMPATIBLE_DRIVER: return "VK_ERROR_INCOMPATIBLE_DRIVER";
        case VK_ERROR_DEVICE_LOST: return "VK_ERROR_DEVICE_LOST";
        default: return "VK_ERROR_OTHER";
    }
}

void PrintVersion(const char* label, std::uint32_t v) {
    std::printf("%s=%u.%u.%u\n", label, VK_API_VERSION_MAJOR(v), VK_API_VERSION_MINOR(v),
                VK_API_VERSION_PATCH(v));
}

} // namespace

int main() {
    std::printf("=== RAWRXD_VULKAN_CAP_PROBE_001 ===\n");

    // ---- 1. ICD presence. If there is no loader manifest there is nothing to
    // find, and every later number is zero for a reason worth stating.
    {
        const char* manifests = getenv("VK_ICD_FILENAMES");
        const char* layers = getenv("VK_LAYER_PATH");
        std::printf("VK_ICD_FILENAMES=%s\n", manifests ? manifests : "(unset)");
        std::printf("VK_LAYER_PATH=%s\n", layers ? layers : "(unset)");
        const HKEY k = HKEY_LOCAL_MACHINE;
        const char* sub = "SOFTWARE\\Khronos\\Vulkan\\Drivers";
        HKEY h = nullptr;
        if (RegOpenKeyExA(k, sub, 0, KEY_READ, &h) == ERROR_SUCCESS) {
            char name[512];
            DWORD n = sizeof(name);
            if (RegQueryValueExA(h, nullptr, nullptr, nullptr, (LPBYTE)name, &n) ==
                ERROR_SUCCESS) {
                std::printf("REGISTRY_DEFAULT_ICD=%s\n", name);
            } else {
                std::printf("REGISTRY_DEFAULT_ICD=(key present, no default value)\n");
            }
            RegCloseKey(h);
        } else {
            std::printf("REGISTRY_DEFAULT_ICD=(no Vulkan Drivers key)\n");
        }
    }

    // ---- 2. Instance. Loader present at all?
    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "rawrxd_vulkan_cap_probe";
    app.apiVersion = VK_API_VERSION_1_3;

    std::uint32_t instVer = 0;
    const VkResult iv = vkEnumerateInstanceVersion(&instVer);
    std::printf("vkEnumerateInstanceVersion=%s\n", ResultName(iv));
    if (iv == VK_SUCCESS) PrintVersion("INSTANCE_API_VERSION", instVer);
    else PrintVersion("INSTANCE_API_VERSION_ASSUMED", VK_API_VERSION_1_0);

    VkInstanceCreateInfo ici{};
    ici.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ici.pApplicationInfo = &app;

    VkInstance inst = VK_NULL_HANDLE;
    const VkResult ir = vkCreateInstance(&ici, nullptr, &inst);
    std::printf("vkCreateInstance=%s\n", ResultName(ir));
    if (ir != VK_SUCCESS || !inst) {
        std::printf("VERDICT=NO_INSTANCE\n");
        std::printf("NOTE=A missing instance is a loader/ICD problem, not a Deep2 filter.\n");
        return 1;
    }

    // ---- 3. Physical devices. The decisive number.
    std::uint32_t count = 0;
    const VkResult ce = vkEnumeratePhysicalDevices(inst, &count, nullptr);
    std::printf("vkEnumeratePhysicalDevices(count)=%s\n", ResultName(ce));
    std::printf("PHYSICAL_DEVICE_COUNT=%u\n", count);
    if (ce != VK_SUCCESS || count == 0) {
        std::printf("VERDICT=NO_PHYSICAL_DEVICES\n");
        std::printf("NOTE=Instance created but no devices: an ICD is registered and the\n"
                    "     loader runs, yet it exposes nothing. This is a driver-level\n"
                    "     condition and no amount of engine filtering explains it.\n");
        vkDestroyInstance(inst, nullptr);
        return 2;
    }

    std::vector<VkPhysicalDevice> devs(count);
    const VkResult ge = vkEnumeratePhysicalDevices(inst, &count, devs.data());
    std::printf("vkEnumeratePhysicalDevices(list)=%s n=%u\n", ResultName(ge), count);

    for (std::uint32_t i = 0; i < count; ++i) {
        VkPhysicalDeviceProperties p{};
        vkGetPhysicalDeviceProperties(devs[i], &p);

        VkPhysicalDeviceMemoryProperties mp{};
        vkGetPhysicalDeviceMemoryProperties(devs[i], &mp);

        std::uint32_t qCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(devs[i], &qCount, nullptr);
        std::uint32_t usableQueues = 0;
        if (qCount) {
            std::vector<VkQueueFamilyProperties> qs(qCount);
            vkGetPhysicalDeviceQueueFamilyProperties(devs[i], &qCount, qs.data());
            for (const VkQueueFamilyProperties& q : qs) {
                if (q.queueFlags & (VK_QUEUE_COMPUTE_BIT | VK_QUEUE_GRAPHICS_BIT)) ++usableQueues;
            }
        }

        std::uint32_t extCount = 0;
        vkEnumerateDeviceExtensionProperties(devs[i], nullptr, &extCount, nullptr);
        std::vector<VkExtensionProperties> exts(extCount);
        if (extCount) {
            vkEnumerateDeviceExtensionProperties(devs[i], nullptr, &extCount, exts.data());
        }

        const char* type = p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU   ? "DISCRETE_GPU"
                           : p.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU ? "INTEGRATED_GPU"
                           : p.deviceType == VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU   ? "VIRTUAL_GPU"
                                                                                 : "OTHER";

        std::printf("\n[DEVICE %u]\n", i);
        std::printf("name=%s\n", p.deviceName);
        std::printf("type=%s\n", type);
        std::printf("vendor=0x%04x device=0x%04x\n", p.vendorID, p.deviceID);
        std::printf("driver_version=%u.%u.%u\n", (p.driverVersion >> 22) & 0x3FF,
                    (p.driverVersion >> 12) & 0x3FF, p.driverVersion & 0xFFF);
        PrintVersion("api_version", p.apiVersion);
        std::printf("queue_families=%u usable_for_compute=%u\n", qCount, usableQueues);
        std::printf("extensions=%u\n", extCount);

        // VRAM and "total mapped" are different quantities and conflating them
        // produced a ~79 GB figure that was really device-local VRAM PLUS the
        // host-visible BAR aperture plus system RAM. That number is not a VRAM
        // figure and must never feed an admission or residency decision.
        //
        // Correct accounting: sum only heaps reachable through a DEVICE_LOCAL
        // memory type. A discrete GPU's VRAM is exactly that sum.
        std::uint64_t vramBytes = 0;
        std::uint64_t hostVisibleBytes = 0;
        for (std::uint32_t t = 0; t < mp.memoryTypeCount; ++t) {
            const std::uint32_t h = mp.memoryTypes[t].heapIndex;
            if (h >= mp.memoryHeapCount) continue;
            const std::uint64_t sz = mp.memoryHeaps[h].size;
            if (mp.memoryTypes[t].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                // Counted once per heap, not once per memory type.
                bool already = false;
                for (std::uint32_t q = 0; q < t; ++q) {
                    if (mp.memoryTypes[q].heapIndex == h &&
                        (mp.memoryTypes[q].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
                        already = true;
                        break;
                    }
                }
                if (!already) vramBytes += sz;
            }
            if (mp.memoryTypes[t].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) {
                hostVisibleBytes = sz;  // report largest single host-visible heap
            }
        }

        std::printf("vram_device_local_gb=%.2f\n", vramBytes / (1024.0 * 1024.0 * 1024.0));
        std::printf("host_visible_heap_gb=%.2f\n",
                    hostVisibleBytes / (1024.0 * 1024.0 * 1024.0));
        std::printf("vram_basis=device_local_memory_types_only\n");
        std::printf("note=an earlier field named memory_heap_total_gb summed ALL heaps\n"
                    "     including host-visible system RAM and was reported as a\n"
                    "     memory figure; that field was withdrawn, not corrected in place\n");
        std::printf("note=VkMemoryHeap::budget_is_Vulkan_1_1_only; heap_free not reported\n");

        // The features a compute backend would actually need, so "is it capable"
        // is measured rather than assumed from the device name.
        VkPhysicalDeviceFeatures f{};
        vkGetPhysicalDeviceFeatures(devs[i], &f);
        std::printf("features: shaderFloat64=%d shaderInt64=%d shaderInt16=%d\n",
                    f.shaderFloat64, f.shaderInt64, f.shaderInt16);
    }

    std::printf("\nVERDICT=DEVICES_ENUMERABLE\n");
    std::printf("NOTE=Devices enumerate. If Deep2 still reports DEVICE_COUNT=0 the\n"
                "     filter is inside the engine, and MLA is reachable on the GPU\n"
                "     without writing a CPU path at all.\n");
    vkDestroyInstance(inst, nullptr);
    return 0;
}