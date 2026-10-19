#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vulkan/vulkan.h>

namespace deep2 {

// One precompiled SPIR-V compute shader bound to a device. Defined at the
// bottom of this header; VulkanDevice only holds pointers to it.
class VulkanProgram;

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

    // Cached per-device compute programs. A program is built the first time a
    // device is used and kept until that device is torn down, so alternating
    // between two devices costs a map lookup rather than a pipeline rebuild.
    // Rebuilding a pipeline on every device switch is what made the earlier
    // static-singleton form of this slower than it had to be.
    bool ensureProgram(const Gpu& gpu, const std::string& spvPath);
    bool dispatchProgram(const Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                         uint32_t rows, uint32_t cols);

private:
    bool pickMemoryType(const Gpu& gpu, uint32_t typeBits, VkMemoryPropertyFlags props,
                        uint32_t& index) const;
    // Destroys the cached programs. Must run before the devices are destroyed.
    void destroyPrograms();

    std::unordered_map<VkDevice, std::unique_ptr<VulkanProgram>> m_programs;
    std::mutex m_programMutex;

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
    // A program belongs to exactly one device, and dispatch mutates its
    // descriptor set and fence, so dispatches on one program are serialised.
    // Programs on different devices have separate locks, so the two halves of
    // a split can still run concurrently.
    std::mutex m_dispatchMutex;
};

} // namespace deep2
