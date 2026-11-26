// VulkanMemoryBudget.hpp — K2-L04 / MB-01..07
//
// Real per-device memory-budget acquisition via VK_EXT_memory_budget.
// Distinguishes the driver's CURRENT budget (heapBudget) from heap CAPACITY
// (memoryHeaps[].size): available headroom = max(0, heapBudget - heapUsage),
// summed over DEVICE-LOCAL heaps only. Provenance is tracked so a caller can
// never silently substitute total capacity for the current budget.
//
// The budget/usage values are driver estimates of current conditions, NOT
// physical bandwidth counters and NOT a guaranteed allocation limit.
#pragma once
#include <vulkan/vulkan.h>
#include <cstdint>
#include <vector>
#include <cstring>

namespace rawrxd {
namespace vkbudget {

struct DeviceMemoryBudget {
    bool     extSupported = false;   // MB-01: VK_EXT_memory_budget present
    bool     queried      = false;   // MB-02: EXT query actually ran
    bool     provenanceIsBudget = false; // true ONLY when real budget (not capacity)
    uint64_t deviceLocalCapacityBytes = 0; // sum of device-local heap SIZE (capacity)
    uint64_t heapBudgetBytes    = 0;   // sum of driver heapBudget (device-local)
    uint64_t heapUsageBytes     = 0;   // sum of driver heapUsage  (device-local)
    uint64_t availableHeadroomBytes = 0; // sum max(0, budget-usage) per heap
};

// MB-01: detect VK_EXT_memory_budget on the selected physical device.
inline bool HasMemoryBudgetExtension(VkPhysicalDevice pd) {
    if (!pd) return false;
    uint32_t count = 0;
    if (vkEnumerateDeviceExtensionProperties(pd, nullptr, &count, nullptr) != VK_SUCCESS)
        return false;
    if (count == 0) return false;
    std::vector<VkExtensionProperties> exts(count);
    if (vkEnumerateDeviceExtensionProperties(pd, nullptr, &count, exts.data()) != VK_SUCCESS)
        return false;
    for (const auto& e : exts) {
        if (std::strcmp(e.extensionName, VK_EXT_MEMORY_BUDGET_EXTENSION_NAME) == 0)
            return true;
    }
    return false;
}

// MB-02..07: query the current device-local memory budget. Returns a struct
// whose `provenanceIsBudget` is true only when the EXT query succeeded. If the
// extension is unsupported the result has extSupported=false and all byte
// fields 0 — the caller MUST fail closed under the locked profile (MB-10) and
// MUST NOT fall back to `deviceLocalCapacityBytes` as a budget.
inline DeviceMemoryBudget QueryDeviceMemoryBudget(VkPhysicalDevice pd) {
    DeviceMemoryBudget b;
    if (!HasMemoryBudgetExtension(pd)) return b; // unsupported -> fail closed
    b.extSupported = true;

    VkPhysicalDeviceMemoryBudgetPropertiesEXT budget{};
    budget.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_BUDGET_PROPERTIES_EXT;
    budget.pNext = nullptr;

    VkPhysicalDeviceMemoryProperties2 props{};
    props.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2;
    props.pNext = &budget;

    vkGetPhysicalDeviceMemoryProperties2(pd, &props);

    const uint32_t heaps = props.memoryProperties.memoryHeapCount;
    for (uint32_t i = 0; i < heaps; ++i) {
        const VkMemoryHeap& h = props.memoryProperties.memoryHeaps[i];
        const bool deviceLocal = (h.flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) != 0;
        if (!deviceLocal) continue;              // MB-03: exclude host/system heaps
        b.deviceLocalCapacityBytes += h.size;    // capacity (provenance-tagged)
        const uint64_t hb = budget.heapBudget[i];
        const uint64_t hu = budget.heapUsage[i];
        b.heapBudgetBytes += hb;
        b.heapUsageBytes  += hu;
        b.availableHeadroomBytes += (hb > hu) ? (hb - hu) : 0ull; // MB-04 safe
    }
    b.queried = true;
    b.provenanceIsBudget = true;                 // MB-07: real budget, not capacity
    return b;
}

// MB-05: apply a safety reservation fraction to the available headroom so
// admission respects existing allocations. fraction in (0,1]; 1.0 = no reserve.
inline uint64_t SafeBudgetBytes(const DeviceMemoryBudget& b, double residentFraction = 1.0) {
    if (!b.provenanceIsBudget) return 0;         // never substitute capacity
    if (residentFraction <= 0.0) return 0;
    if (residentFraction > 1.0) residentFraction = 1.0;
    const long double v = (long double)b.availableHeadroomBytes * (long double)residentFraction;
    return (uint64_t)v;
}

} // namespace vkbudget
} // namespace rawrxd