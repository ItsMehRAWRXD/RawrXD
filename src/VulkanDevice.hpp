#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <vulkan/vulkan.h>

namespace deep2 {

// Minimal Vulkan compute context for the emulator's GPU path.
// Discovers AMD discrete GPUs (R9700 primary, 7800 XT secondary) and exposes
// buffer allocation/upload and compute dispatch. All dispatches are synchronous
// in this milestone (correctness first; async streams come in Phase C).
class VulkanDevice {
public:
    struct Gpu {
        VkInstance instance = VK_NULL_HANDLE;
        VkPhysicalDevice pd = VK_NULL_HANDLE;
        VkDevice device = VK_NULL_HANDLE;
        VkQueue queue = VK_NULL_HANDLE;
        VkCommandPool pool = VK_NULL_HANDLE;
        uint32_t queueFamily = UINT32_MAX;
        VkPhysicalDeviceProperties props{};
        VkPhysicalDeviceMemoryProperties memProps{};
        std::string name;
        uint64_t vramBytes = 0;
        bool operator==(const Gpu&) const = delete;
    };

    VulkanDevice();
    ~VulkanDevice();

    VulkanDevice(const VulkanDevice&) = delete;
    VulkanDevice& operator=(const VulkanDevice&) = delete;

    bool init();
    void shutdown();

    std::size_t gpuCount() const { return m_gpus.size(); }
    const Gpu* gpu(std::size_t i) const { return i < m_gpus.size() ? &m_gpus[i] : nullptr; }
    const Gpu* primary() const  { return gpuCount() > 0 ? &m_gpus[0] : nullptr; }
    const Gpu* secondary() const { return gpuCount() > 1 ? &m_gpus[1] : nullptr; }

    // Allocate buffer on `gpu`. If memProps includes HOST_VISIBLE, returns mapped pointer.
    bool createBuffer(const Gpu& gpu, VkDeviceSize size, VkBufferUsageFlags usage,
                      VkMemoryPropertyFlags memProps, VkBuffer& buf, VkDeviceMemory& mem,
                      void** mapped = nullptr);
    void destroyBuffer(const Gpu& gpu, VkBuffer buf, VkDeviceMemory mem);

    // One-time host->device upload through a staging buffer.
    bool uploadToBuffer(const Gpu& gpu, VkBuffer dst, VkDeviceSize dstOffset,
                        const void* data, VkDeviceSize size);

    // Immediate (synchronous) host pointer copy for small constant data.
    bool writeMapped(const Gpu& gpu, VkDeviceMemory mem, VkDeviceSize offset,
                     const void* data, VkDeviceSize size);

private:
    bool pickMemoryType(const Gpu& gpu, uint32_t typeBits, VkMemoryPropertyFlags props,
                        uint32_t& index) const;

    VkInstance m_instance = VK_NULL_HANDLE;
    std::vector<Gpu> m_gpus;
};

// One precompiled SPIR-V compute shader bound to a device.
class VulkanProgram {
public:
    VulkanProgram();
    ~VulkanProgram();

    VulkanProgram(const VulkanProgram&) = delete;
    VulkanProgram& operator=(const VulkanProgram&) = delete;

    // Load SPIR-V from `spvPath` and create the compute pipeline on `device`.
    bool init(VkDevice device, const std::string& spvPath);
    void destroy(VkDevice device);

    // Dispatch gemv-style compute on `gpu`. Buffers must already live on `gpu` memory.
    bool dispatch(const VulkanDevice::Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                  uint32_t rows, uint32_t cols);

private:
    VkDevice m_device = VK_NULL_HANDLE;
    VkShaderModule m_shader = VK_NULL_HANDLE;
    VkPipelineLayout m_layout = VK_NULL_HANDLE;
    VkPipeline m_pipeline = VK_NULL_HANDLE;
    VkDescriptorSetLayout m_dsl = VK_NULL_HANDLE;
    VkDescriptorPool m_pool = VK_NULL_HANDLE;
    VkDescriptorSet m_set = VK_NULL_HANDLE;
    VkCommandBuffer m_cmd = VK_NULL_HANDLE;
    VkFence m_fence = VK_NULL_HANDLE;
    VkQueue m_queue = VK_NULL_HANDLE;
};

} // namespace deep2
