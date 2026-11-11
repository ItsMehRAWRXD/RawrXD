// ============================================================================
// RawrXD Vulkan Synchronization Interface
// C++ wrapper for MASM GPU fence lifecycle management
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// Vulkan opaque handles (forward declarations)
using VkDevice = void*;
using VkFence = void*;
using VkCommandPool = void*;
using VkCommandBuffer = void*;
using VkDescriptorSet = void*;
using VkPipeline = void*;
using VkPipelineLayout = void*;
using VkDeviceMemory = void*;
using VkBuffer = void*;

// VkResult codes
constexpr int32_t VK_SUCCESS = 0;
constexpr int32_t VK_NOT_READY = 1;
constexpr int32_t VK_TIMEOUT = 2;
constexpr int32_t VK_ERROR_DEVICE_LOST = -4;

// Fence status
constexpr uint32_t VK_FENCE_UNSIGNALED = 0;
constexpr uint32_t VK_FENCE_SIGNALED = 1;

// Model Descriptor GPU State (matches MASM structure)
#pragma pack(push, 8)
struct ModelDescriptorGPU {
    VkDevice        vk_device;              // +0x00
    VkFence         vk_fence;               // +0x08
    VkCommandPool   vk_cmd_pool;            // +0x10
    VkCommandBuffer vk_cmd_buffer;          // +0x18
    VkDescriptorSet vk_descriptor_set;    // +0x20
    VkPipeline      vk_pipeline;            // +0x28
    VkPipelineLayout vk_pipeline_layout;   // +0x30
    uint32_t        fence_status;           // +0x38
    uint32_t        cmd_buffer_pending;     // +0x3C
    VkBuffer        weight_buffer_device;   // +0x40
    uint64_t        weight_buffer_size;     // +0x48
    VkBuffer        uniform_buffer;         // +0x50
    uint64_t        completion_timestamp;   // +0x58
};
static_assert(sizeof(ModelDescriptorGPU) == 0x60, "ModelDescriptorGPU size mismatch");
#pragma pack(pop)

// Synchronization statistics
struct VulkanSyncStats {
    uint64_t fence_waits;
    uint64_t fence_timeouts;
    uint64_t deferred_swaps;
    uint64_t immediate_swaps;
    uint64_t gpu_idle_checks;
};

extern "C" {
    // Initialize Vulkan synchronization functions
    // Must be called before any other sync functions
    // Returns 0 on success, negative on error
    int32_t Vulkan_InitSynchronization(
        VkDevice device,
        void* vkGetDeviceProcAddr
    );

    // Check GPU fence status (non-blocking)
    // Returns: 0 = idle, 1 = pending, -1 = error
    int32_t Vulkan_CheckFenceStatus(ModelDescriptorGPU* model);

    // Wait for GPU completion (blocking with timeout)
    // Returns: 0 = success, -1 = timeout, -2 = error
    int32_t Vulkan_WaitForFenceBlocking(
        ModelDescriptorGPU* model,
        uint64_t timeout_ns
    );

    // Insert pipeline barrier for memory visibility
    // Ensures all previous GPU writes are visible
    int32_t Vulkan_InsertPipelineBarrier(ModelDescriptorGPU* model);

    // Attempt hotpatch with GPU completion check
    // Called at layer boundary when epoch is odd
    // Returns: 0 = swap complete, 1 = deferred, -1 = error
    int32_t RawrXD_TryHotpatchWithGPUCheck(ModelDescriptorGPU* current_model);

    // Mark model work as submitted
    // Call after vkQueueSubmit to track pending work
    int32_t RawrXD_SubmitModelWork(ModelDescriptorGPU* model);
}

// C++ wrapper class for RAII-style fence management
class VulkanModelGuard {
public:
    explicit VulkanModelGuard(ModelDescriptorGPU* model);
    ~VulkanModelGuard();

    // Non-copyable
    VulkanModelGuard(const VulkanModelGuard&) = delete;
    VulkanModelGuard& operator=(const VulkanModelGuard&) = delete;

    // Movable
    VulkanModelGuard(VulkanModelGuard&& other) noexcept;
    VulkanModelGuard& operator=(VulkanModelGuard&& other) noexcept;

    // Wait for GPU completion
    bool WaitForCompletion(uint64_t timeout_ns = 100000000); // 100ms default

    // Check if GPU work is complete
    bool IsComplete();

    // Release ownership without waiting
    void Release();

private:
    ModelDescriptorGPU* model_;
};

// Global synchronization statistics
extern "C" VulkanSyncStats* GetVulkanSyncStats();
