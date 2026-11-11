#pragma once
#include <vulkan/vulkan.h>
#include <windows.h>
#include <vector>
#include <string>

namespace Deep2EngineVulkan {

    struct GpuDeviceProfile {
        VkPhysicalDevice physical_device{ VK_NULL_HANDLE };
        VkDevice         logical_device{ VK_NULL_HANDLE };
        VkDeviceSize     total_vram{ 0 };
        uint32_t         device_index{ 0 };
        std::string      device_name;
        bool             is_primary_compute{ false }; // True for W7900 (32GB)
    };

    class VulkanDeviceAllocator {
    public:
        VulkanDeviceAllocator() = default;
        ~VulkanDeviceAllocator();

        bool initialize_gpu_topology(VkInstance instance);
        
        // --- MOVE 7: ASYMMETRIC WEIGHT BALANCE CALCULATOR ---
        // Determines target residency mapping assignments based on raw hardware VRAM pools
        [[nodiscard]] uint8_t balance_layer_residency(uint32_t layer_idx, uint32_t total_layers) const;

        bool allocate_device_tensor_buffer(uint32_t device_idx, VkDeviceSize size, VkBuffer& out_buffer, VkDeviceMemory& out_memory);

    private:
        std::vector<GpuDeviceProfile> m_gpu_profiles;
        VkInstance m_vk_instance{ VK_NULL_HANDLE };
    };
}  // namespace Deep2EngineVulkan