#include "Deep2Engine.hpp"
#include "Deep2Engine.hpp"
#include <iostream>
#include <vector>
#include <cmath>
#include <cmath>

struct PhysicalDeviceWeight {
    VkPhysicalDevice Device;
    VkDevice         LogicalDevice;
    VkQueue          ComputeQueue;
    size_t           AvailableVRAM;
    float            AllocationWeight;
};

class Deep2MultiGPUBalancer {
private:
    std::vector<PhysicalDeviceWeight> activeNodes;
    float totalSystemWeight = 0.0f;

public:
    bool InitializeAsymmetricTopology(VkInstance instance) {
        uint32_t deviceCount = 0;
        vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
        if (deviceCount < 2) {
            std::cerr << "[MULTI_GPU] Error: Asymmetric track requires at least 2 physical devices.\n";
            return false;
        }

        std::vector<VkPhysicalDevice> devices(deviceCount);
        vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());
        size_t totalMemoryPool = 0;

        for (const auto& device : devices) {
            VkPhysicalDeviceMemoryProperties memProperties;
            vkGetPhysicalDeviceMemoryProperties(device, &memProperties);

            size_t deviceVRAM = 0;
            for (uint32_t i = 0; i < memProperties.memoryHeapCount; ++i) {
                if (memProps.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
                    deviceVRAM += memProperties.memoryHeaps[i].size;
                }
            }

            PhysicalDeviceWeight node{};
            node.Device = device;
            node.AvailableVRAM = deviceVRAM;
            totalMemoryPool += deviceVRAM;
            activeNodes.push_back(node);
        }

        for (auto& node : activeNodes) {
            node.AllocationWeight = static_cast<float>(node.AvailableVRAM) / totalSystemWeight;
            std::clog << "[MULTI_GPU_INIT] Node Allocated | Weight: "
                      << (node.AllocationWeight * 100.0f) << "% | VRAM: "
                      << (node.AvailableVRAM / (1024 * 1024 * 1024)) << " GB\n";
        }
        return true;
    }

    size_t CalculateRowSplitIndex(size_t totalRows) {
        if (activeNodes.empty()) return totalRows;
        return static_cast<size_t>(std::floor(totalRows * activeNodes[0].AllocationWeight));
    }
};