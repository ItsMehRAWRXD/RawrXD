#include "VulkanDeviceAllocator.hpp"
#include <iostream>

namespace Deep2EngineVulkan {

    VulkanDeviceAllocator::~VulkanDeviceAllocator() {
        for (auto& gpu : m_gpu_profiles) {
            if (gpu.logical_device != VK_NULL_HANDLE) {
                ::vkDeviceWaitIdle(gpu.logical_device);
                ::vkDestroyDevice(gpu.logical_device, nullptr);
            }
        }
    }

    bool VulkanDeviceAllocator::initialize_gpu_topology(VkInstance instance) {
        m_vk_instance = instance;
        uint32_t device_count = 0;
        ::vkEnumeratePhysicalDevices(m_vk_instance, &device_count, nullptr);

        if (device_count == 0) {
            std::cerr << "[Vulkan] Error: No physical graphics adapters enumerated.\n";
            return false;
        }

        std::vector<VkPhysicalDevice> physical_devices(device_count);
        ::vkEnumeratePhysicalDevices(m_vk_instance, &device_count, physical_devices.data());

        for (uint32_t i = 0; i < device_count; ++i) {
            VkPhysicalDeviceProperties props;
            ::vkGetPhysicalDeviceProperties(physical_devices[i], &props);

            // Fetch VRAM sizing constraints from memory heap properties
            VkPhysicalDeviceMemoryProperties mem_props;
            ::vkGetPhysicalDeviceMemoryProperties(physical_devices[i], &mem_props);

            VkDeviceSize total_vram = 0;
            for (uint32_t j = 0; j < mem_props.memoryHeapCount; ++j) {
                if (mem_props.memoryHeaps[j].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
                    total_vram += mem_props.memoryHeaps[j].size;
                }
            }

            GpuDeviceProfile profile{};
            profile.physical_device = physical_devices[i];
            profile.total_vram = total_vram;
            profile.device_index = i;
            profile.device_name = props.deviceName;
            
            // Flag the massive 32GB adapter as primary compute anchor
            if (total_vram > (24ULL * 1024 * 1024 * 1024)) { 
                profile.is_primary_compute = true;
            }

            // Minimal queue assembly logic setup for logical device instantiation
            float queue_priority = 1.0f;
            VkDeviceQueueCreateInfo queue_info{};
            queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
            queue_info.queueFamilyIndex = 0; // Target universal graphics/compute stream
            queue_info.queueCount = 1;
            queue_info.pQueuePriorities = &queue_priority;

            VkDeviceCreateInfo device_info{};
            device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
            device_info.queueCreateInfoCount = 1;
            device_info.pQueueCreateInfos = &queue_info;

            if (::vkCreateDevice(profile.physical_device, &device_info, nullptr, &profile.logical_device) == VK_SUCCESS) {
                m_gpu_profiles.push_back(profile);
                std::cout << "[Vulkan] Discovered Adapter [" << i << "]: " << profile.device_name 
                          << " | VRAM Capacity: " << (total_vram / (1024 * 1024 * 1024)) << " GB\n";
            }
        }

        return !m_gpu_profiles.empty();
    }

    // --- MOVE 7 IMPLEMENTATION: ASYMMETRIC LAYER MAPPING STRATEGY ---
    uint8_t VulkanDeviceAllocator::balance_layer_residency(uint32_t layer_idx, uint32_t total_layers) const {
        // Compute strict VRAM balance metrics across your hardware setup (32GB vs 16GB)
        // Allocates roughly 2/3 of total layers to W7900, remaining 1/3 to 7800 XT.
        uint32_t primary_layer_cutoff = (total_layers * 2) / 3;

        if (layer_idx < primary_layer_cutoff) {
            return 1; // Route to Device 1: Radeon Pro W7900 (32GB VRAM anchor)
        } else {
            return 2; // Route to Device 2: RX 7800 XT (16GB VRAM acceleration tier)
        }
    }

    bool VulkanDeviceAllocator::allocate_device_tensor_buffer(uint32_t device_idx, VkDeviceSize size, VkBuffer& out_buffer, VkDeviceMemory& out_memory) {
        if (device_idx >= m_gpu_profiles.size()) return false;
        VkDevice logical = m_gpu_profiles[device_idx].logical_device;

        VkBufferCreateInfo buffer_info{};
        buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        buffer_info.size = size;
        buffer_info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
        buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

        if (::vkCreateBuffer(logical, &buffer_info, nullptr, &out_buffer) != VK_SUCCESS) return false;

        VkMemoryRequirements mem_reqs;
        ::vkGetBufferMemoryRequirements(logical, out_buffer, &mem_reqs);

        VkMemoryAllocateInfo alloc_info{};
        alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        alloc_info.allocationSize = mem_reqs.size;
        alloc_info.memoryTypeIndex = 0; // Map to local high-speed VRAM layout pools

        if (::vkAllocateMemory(logical, &alloc_info, nullptr, &out_memory) != VK_SUCCESS) {
            ::vkDestroyBuffer(logical, out_buffer, nullptr);
            return false;
        }

        ::vkBindBufferMemory(logical, out_buffer, out_memory, 0);
        return true;
    }
}  // namespace Deep2EngineVulkan