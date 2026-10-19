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

// A dispatch that has been recorded and submitted to a queue but has not
// necessarily finished yet.
//
// The handle owns the command buffer until the work is known to be complete,
// and it holds the program's dispatch lock for that whole window. The
// descriptor set and the fence belong to the program, so a second dispatch on
// the same device would otherwise rewrite the descriptor set and reset the
// fence while the first one is still in flight.
//
// Two programs on two different devices have separate locks, so the two
// halves of a split GEMV can be in flight at the same time.
//
// This lives outside VulkanProgram because VulkanDevice has to name it in a
// method signature, and VulkanProgram has to name VulkanDevice::Gpu, so the
// two classes cannot be defined in either order.
class VulkanDispatch {
public:
    VulkanDispatch() = default;
    ~VulkanDispatch();

    VulkanDispatch(const VulkanDispatch&) = delete;
    VulkanDispatch& operator=(const VulkanDispatch&) = delete;
    VulkanDispatch(VulkanDispatch&& other) noexcept;
    VulkanDispatch& operator=(VulkanDispatch&& other) noexcept;

    bool valid() const { return m_program != nullptr; }

    // Waits for the submitted work to complete and releases the command
    // buffer and the program's dispatch lock. Idempotent: a handle that
    // has already been waited on is a no-op.
    bool wait();

private:
    friend class VulkanProgram;
    VulkanProgram* m_program = nullptr;
    VkDevice m_device = VK_NULL_HANDLE;
    VkCommandPool m_pool = VK_NULL_HANDLE;
    VkCommandBuffer m_cmd = VK_NULL_HANDLE;
    VkFence m_fence = VK_NULL_HANDLE;
    std::unique_lock<std::mutex> m_lock;
};

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

    // A device-resident cache of the per-layer key and value rows.
    //
    // The keys and values are produced by the projection GEMV, so the rows
    // already exist in device memory when the projection finishes. The cache
    // is where they are kept between positions, so the attention can read
    // them in place instead of pulling the whole context back across PCIe on
    // every layer.
    //
    // The layout is [layer][position][hiddenDim], so a position's rows for
    // one layer are contiguous and a position's rows for every layer are
    // evenly spaced.
    struct KvCache {
        VkBuffer keyBuffer = VK_NULL_HANDLE;
        VkBuffer valueBuffer = VK_NULL_HANDLE;
        VkDeviceMemory keyMemory = VK_NULL_HANDLE;
        VkDeviceMemory valueMemory = VK_NULL_HANDLE;
        uint32_t layers = 0;
        uint32_t seqCapacity = 0;   // positions the cache can hold
        uint32_t hiddenDim = 0;

        VkDeviceSize bytesPerBuffer() const {
            return static_cast<VkDeviceSize>(layers) * seqCapacity * hiddenDim * sizeof(float);
        }
        VkDeviceSize totalBytes() const { return bytesPerBuffer() * 2; }
    };

    // Bytes a KV cache of the given shape needs on one device.
    static VkDeviceSize KvCacheBytes(uint32_t layers, uint32_t seqCapacity, uint32_t hiddenDim) {
        return static_cast<VkDeviceSize>(layers) * seqCapacity * hiddenDim * sizeof(float) * 2;
    }

    // Allocate the cache on `gpu`. `budgetBytes` is what the caller has
    // left for it; the allocation is refused rather than allowed to push
    // the device past its VRAM. A zero budget means the device's whole
    // VRAM.
    bool createKvCache(const Gpu& gpu, uint32_t layers, uint32_t seqCapacity,
                       uint32_t hiddenDim, VkDeviceSize budgetBytes, KvCache& out);
    void destroyKvCache(const Gpu& gpu, KvCache& cache);

    // Append one position's key and value rows for `layer`.
    bool appendKvPosition(const Gpu& gpu, KvCache& cache, uint32_t layer,
                           uint32_t position, const float* keys, const float* values);

    // Record and submit a dispatch on `gpu` without waiting for it to
    // finish. The caller waits on the returned handle.
    bool beginDispatchProgram(const Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                              uint32_t rows, uint32_t cols, VulkanDispatch& out);

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

    // A dispatch that has been recorded and submitted to a queue but has not
    // necessarily finished yet. See VulkanDispatch above for the rationale
    // behind it living outside this class.
    using Dispatch = VulkanDispatch;

    // Load SPIR-V from `spvPath` and create the compute pipeline on `device`.
    bool init(VkDevice device, const std::string& spvPath);
    void destroy(VkDevice device);

    // Dispatch gemv-style compute on `gpu`. Buffers must already live on `gpu` memory.
    // This form submits the work and waits for it to finish before it returns.
    bool dispatch(const VulkanDevice::Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                  uint32_t rows, uint32_t cols);

    // Record and submit the same work without waiting for it. The caller
    // waits on the returned handle.
    bool beginDispatch(const VulkanDevice::Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                       uint32_t rows, uint32_t cols, Dispatch& out);

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
