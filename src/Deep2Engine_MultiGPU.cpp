// Multi-GPU device discovery and asymmetric row distribution.
//
// This file used to be a sketch that no build target referenced. It could not
// have compiled: the definition of CalculateRowSplitIndex() was missing the
// `const` qualifier its declaration carried, the members it used
// (PhysicalDeviceWeight, activeNodes, totalSystemWeight) were declared
// nowhere, and it referenced an undeclared `memProps` instead of the
// `memProperties` it had just filled in.
//
// The row-splitting math itself now lives in core/QuantBlockTraits.hpp so
// that the engine and the golden-vector tests exercise the same function.

#include "Deep2Engine.hpp"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <vector>

namespace {

// Device-local VRAM available to the engine, in bytes.
size_t QueryDeviceLocalVram(VkPhysicalDevice device) {
    VkPhysicalDeviceMemoryProperties memProperties{};
    vkGetPhysicalDeviceMemoryProperties(device, &memProperties);

    size_t deviceVRAM = 0;
    for (uint32_t i = 0; i < memProperties.memoryHeapCount; ++i) {
        if (memProperties.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
            deviceVRAM += memProperties.memoryHeaps[i].size;
        }
    }
    return deviceVRAM;
}

}  // namespace

bool Deep2Engine::InitializeMultiGPU() {
    m_deviceAllocationWeights.clear();
    m_deviceVramBytes.clear();

    VkInstance instance = VK_NULL_HANDLE;
    if (vkCreateInstance(nullptr, nullptr, &instance) != VK_SUCCESS || instance == VK_NULL_HANDLE) {
        std::clog << "[MULTI_GPU_INIT] No Vulkan instance; row splits fall back to a single device.\n";
        return false;
    }

    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        std::clog << "[MULTI_GPU_INIT] No physical devices found.\n";
        vkDestroyInstance(instance, nullptr);
        return false;
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

    size_t totalMemoryPool = 0;
    for (const auto& device : devices) {
        const size_t deviceVRAM = QueryDeviceLocalVram(device);
        m_deviceVramBytes.push_back(deviceVRAM);
        totalMemoryPool += deviceVRAM;
    }

    if (totalMemoryPool == 0) {
        std::clog << "[MULTI_GPU_INIT] Devices report no device-local VRAM.\n";
        vkDestroyInstance(instance, nullptr);
        m_deviceVramBytes.clear();
        return false;
    }

    for (const size_t deviceVRAM : m_deviceVramBytes) {
        const float weight = static_cast<float>(deviceVRAM) / static_cast<float>(totalMemoryPool);
        m_deviceAllocationWeights.push_back(weight);
        std::clog << "[MULTI_GPU_INIT] Node Allocated | Weight: "
                  << (weight * 100.0f) << "% | VRAM: "
                  << (deviceVRAM / (1024ull * 1024ull * 1024ull)) << " GB\n";
    }

    vkDestroyInstance(instance, nullptr);
    return true;
}

deep2::Quant::RowSplitPlan Deep2Engine::PlanRowSplit(uint32_t totalRows,
                                                     uint32_t cols,
                                                     ggml_type type,
                                                     float weightOverride,
                                                     uint64_t budgetBytes0,
                                                     uint64_t budgetBytes1) const {
    float weight = weightOverride;
    if (weightOverride < 0.0f) {
        // No override: use the weight measured from the real VRAM.
        weight = m_deviceAllocationWeights.empty() ? 1.0f : m_deviceAllocationWeights[0];
    }
    return deep2::Quant::CalculateRowSplitIndex(totalRows, cols, type, weight,
                                                 budgetBytes0, budgetBytes1);
}

size_t Deep2Engine::CalculateRowSplitIndex(uint32_t totalRows,
                                            uint32_t cols,
                                            ggml_type type,
                                            float weightOverride,
                                            uint64_t budgetBytes0,
                                            uint64_t budgetBytes1) const {
    return PlanRowSplit(totalRows, cols, type, weightOverride,
                        budgetBytes0, budgetBytes1).device0Rows;
}
