#pragma once

#include "../elastic/ElasticResidencyManager.hpp"

#if defined(RAWR_ENABLE_VULKAN) || defined(RAWR_HAS_VULKAN)
    #if __has_include(<vulkan/vulkan.h>)
        #include <vulkan/vulkan.h>
        #define RAWR_VULKAN_AVAILABLE 1
    #else
        #define RAWR_VULKAN_AVAILABLE 0
    #endif
#else
    #define RAWR_VULKAN_AVAILABLE 0
#endif

#if !RAWR_VULKAN_AVAILABLE
    #ifndef VK_VERSION_1_0
    typedef void* VkBuffer;
    typedef void* VkDeviceMemory;
    typedef void* VkPhysicalDevice;
    typedef void* VkDevice;
    typedef void* VkQueue;
    typedef void* VkCommandPool;
    typedef uint32_t VkMemoryPropertyFlags;
    #ifndef VK_NULL_HANDLE
    #define VK_NULL_HANDLE nullptr
    #endif
    #endif
#endif

#include <cstdint>
#include <string>

namespace RawrXD::Elastic {

// ============================================================================
// VulkanTensorResidencyBackend
// ============================================================================
// Implements the GpuAllocator / GpuDeallocator callbacks for
// ElasticResidencyManager using actual Vulkan buffer allocation.
//
// Usage:
//   VulkanTensorResidencyBackend backend(device, physicalDevice);
//   residency_mgr.SetGpuCallbacks(
//       backend.GetAllocator(),
//       backend.GetDeallocator()
//   );
// ============================================================================

struct VulkanTensorHandle {
    VkBuffer       buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    uint64_t       allocated_bytes = 0;
    uint64_t       requested_bytes = 0;
};

class VulkanTensorResidencyBackend {
public:
    explicit VulkanTensorResidencyBackend(VkDevice device, VkPhysicalDevice physDevice,
                                          VkQueue queue = VK_NULL_HANDLE,
                                          VkCommandPool cmdPool = VK_NULL_HANDLE);
    ~VulkanTensorResidencyBackend();

    // Non-copyable
    VulkanTensorResidencyBackend(const VulkanTensorResidencyBackend&) = delete;
    VulkanTensorResidencyBackend& operator=(const VulkanTensorResidencyBackend&) = delete;

    // Callbacks compatible with ElasticResidencyManager::SetGpuCallbacks
    ElasticResidencyManager::GpuAllocator  GetAllocator();
    ElasticResidencyManager::GpuDeallocator GetDeallocator();

    // Direct allocation (returns opaque handle cast to void*)
    void* AllocateTensor(uint64_t requested_bytes, uint64_t& out_allocated_bytes);
    void  FreeTensor(void* opaque_handle);

    // Upload CPU data into an allocated tensor
    bool UploadData(void* opaque_handle, const void* src_data, uint64_t bytes);

    // Retrieve VkBuffer from opaque handle
    static VkBuffer GetVkBuffer(void* opaque_handle);

    // Stats
    uint64_t TotalAllocatedBytes() const { return total_allocated_.load(); }
    uint64_t TensorCount() const { return tensor_count_.load(); }

private:
    VkDevice         m_device = VK_NULL_HANDLE;
    VkPhysicalDevice m_physDevice = VK_NULL_HANDLE;
    VkQueue          m_queue = VK_NULL_HANDLE;
    VkCommandPool    m_cmdPool = VK_NULL_HANDLE;

    std::atomic<uint64_t> total_allocated_{0};
    std::atomic<uint64_t> tensor_count_{0};

    uint32_t FindMemoryType(uint32_t typeBits, VkMemoryPropertyFlags props);
    bool SubmitCopyBuffer(VkBuffer src, VkBuffer dst, uint64_t bytes);
};

} // namespace RawrXD::Elastic
