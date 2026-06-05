// ============================================================================
// RawrXD_VulkanAccelerator.cpp — Data Plane GPU Accelerator Implementation
// ============================================================================
//
// C++ bridge between Control Plane (LlamaNativeBridge) and MASM hot-path
// dispatch (RawrXD_Vulkan_Shim.asm).
//
// Design rules:
//   - No Qt, no exceptions, no STL heavyweights in hot path.
//   - All Vulkan details hidden behind PIMPL (Impl struct).
//   - ASM dispatch functions linked via extern "C" for zero-overhead.
//   - Q4_K_M quantized tensors stay quantized in VRAM until dequant kernel.
//   - KV cache is permanently resident in VRAM; only token IDs cross PCIe.
//
// Target GPU: AMD Radeon RX 7800 XT (16 GB VRAM, Vulkan 1.4)
// ============================================================================

#include "RawrXD_VulkanAccelerator.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <chrono>
#include <thread>
#include <atomic>

// ============================================================================
// Vulkan includes (only in .cpp, never in .h to keep Control Plane clean)
// ============================================================================

#if RAWR_HAS_VULKAN
#ifdef _WIN32
#   define VK_USE_PLATFORM_WIN32_KHR
#endif
#include <vulkan/vulkan.h>
#else
// Stubs when Vulkan SDK is not available
using VkInstance = void*;
using VkDevice = void*;
using VkPhysicalDevice = void*;
using VkQueue = void*;
using VkCommandPool = void*;
using VkCommandBuffer = void*;
using VkFence = void*;
using VkDeviceMemory = void*;
using VkBuffer = void*;
using VkSemaphore = void*;
using VkShaderModule = void*;
using VkPipeline = void*;
using VkPipelineLayout = void*;
using VkQueryPool = void*;
using VkDescriptorSet = void*;
using VkDescriptorSetLayout = void*;
using VkDescriptorPool = void*;
constexpr void* VK_NULL_HANDLE = nullptr;
constexpr uint32_t VK_QUEUE_COMPUTE_BIT = 0x00000002;
constexpr uint32_t VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT = 0x00000002;
constexpr uint32_t VK_MEMORY_PROPERTY_HOST_COHERENT_BIT = 0x00000004;
constexpr uint32_t VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT = 0x00000001;
constexpr uint32_t VK_MEMORY_HEAP_DEVICE_LOCAL_BIT = 0x00000001;
constexpr uint32_t VK_BUFFER_USAGE_TRANSFER_SRC_BIT = 0x00000001;
constexpr uint32_t VK_BUFFER_USAGE_TRANSFER_DST_BIT = 0x00000002;
constexpr uint32_t VK_BUFFER_USAGE_STORAGE_BUFFER_BIT = 0x00000020;
constexpr uint32_t VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT = 0x00000002;
constexpr uint32_t VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT = 0x00000001;
constexpr uint32_t VK_COMMAND_BUFFER_USAGE_SIMULTANEOUS_USE_BIT = 0x00000004;
constexpr uint32_t VK_STRUCTURE_TYPE_APPLICATION_INFO = 0;
constexpr uint32_t VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1;
constexpr uint32_t VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO = 2;
constexpr uint32_t VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO = 3;
constexpr uint32_t VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO = 4;
constexpr uint32_t VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO = 5;
constexpr uint32_t VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO = 6;
constexpr uint32_t VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO = 7;
constexpr uint32_t VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO = 8;
constexpr uint32_t VK_STRUCTURE_TYPE_FENCE_CREATE_INFO = 9;
constexpr uint32_t VK_STRUCTURE_TYPE_SUBMIT_INFO = 10;
constexpr uint32_t VK_STRUCTURE_TYPE_BUFFER_COPY = 11;
constexpr uint32_t VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO = 12;
constexpr uint32_t VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO = 13;
constexpr uint32_t VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO = 14;
constexpr uint32_t VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO = 15;
constexpr uint32_t VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO = 16;
constexpr uint32_t VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO = 17;
constexpr uint32_t VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET = 18;
constexpr uint32_t VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO = 19;
constexpr uint32_t VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER = 20;
constexpr uint32_t VK_DESCRIPTOR_TYPE_STORAGE_BUFFER = 7;
constexpr uint32_t VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER = 6;
constexpr uint32_t VK_QUERY_TYPE_TIMESTAMP = 2;
constexpr uint32_t VK_QUERY_RESULT_64_BIT = 0x00000001;
constexpr uint32_t VK_QUERY_RESULT_WAIT_BIT = 0x00000002;
constexpr uint32_t VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT = 0x00000001;
constexpr uint32_t VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT = 0x00002000;
constexpr uint32_t VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT = 0x00000800;
constexpr uint32_t VK_ACCESS_SHADER_READ_BIT = 0x00000020;
constexpr uint32_t VK_ACCESS_SHADER_WRITE_BIT = 0x00000040;
constexpr uint32_t VK_SHADER_STAGE_COMPUTE_BIT = 0x00000020;
constexpr uint32_t VK_PIPELINE_BIND_POINT_COMPUTE = 1;
constexpr uint32_t VK_WHOLE_SIZE = 0xFFFFFFFFFFFFFFFFull;
constexpr uint32_t VK_QUEUE_FAMILY_IGNORED = 0xFFFFFFFFu;
constexpr uint32_t VK_MAKE_VERSION(uint32_t major, uint32_t minor, uint32_t patch) { return (major << 22) | (minor << 12) | patch; }
constexpr uint32_t VK_API_VERSION_1_2 = VK_MAKE_VERSION(1, 2, 0);
constexpr uint32_t VK_SHARING_MODE_EXCLUSIVE = 0;
constexpr uint32_t VK_COMMAND_BUFFER_LEVEL_PRIMARY = 0;
constexpr uint32_t VK_TRUE = 1;
inline void* vkGetDeviceProcAddr(void*, const char*) { return nullptr; }
inline void vkGetPhysicalDeviceQueueFamilyProperties(void*, uint32_t*, void*) {}
inline void vkGetPhysicalDeviceMemoryProperties(void*, void*) {}
inline void vkGetPhysicalDeviceProperties(void*, void*) {}
inline void vkGetBufferMemoryRequirements(void*, void*, void*) {}
inline void vkBindBufferMemory(void*, void*, void*, uint64_t) {}
inline void vkMapMemory(void*, void*, uint64_t, uint64_t, uint32_t, void**) {}
inline void vkDestroyBuffer(void*, void*, void*) {}
inline void vkFreeMemory(void*, void*, void*) {}
inline void vkDestroyFence(void*, void*, void*) {}
inline void vkDestroyCommandPool(void*, void*, void*) {}
inline void vkDestroyDevice(void*, void*) {}
inline void vkDestroyInstance(void*, void*) {}
inline void vkGetDeviceQueue(void*, uint32_t, uint32_t, void**) {}
inline void vkDeviceWaitIdle(void*) {}
inline void vkDestroyShaderModule(void*, void*, void*) {}
inline void vkDestroyPipeline(void*, void*, void*) {}
inline void vkDestroyPipelineLayout(void*, void*, void*) {}
inline void vkDestroyDescriptorSetLayout(void*, void*, void*) {}
inline void vkDestroyDescriptorPool(void*, void*, void*) {}
inline void vkDestroyQueryPool(void*, void*, void*) {}
inline void vkUpdateDescriptorSets(void*, uint32_t, void*, uint32_t, void*) {}
inline void vkCmdBindPipeline(void*, uint32_t, void*) {}
inline void vkCmdBindDescriptorSets(void*, uint32_t, void*, uint32_t, uint32_t, void*, uint32_t, void*) {}
inline void vkCmdPushConstants(void*, void*, uint32_t, uint32_t, uint32_t, const void*) {}
inline uint32_t vkCreateInstance(void*, void*, void**) { return 1; }
inline uint32_t vkEnumeratePhysicalDevices(void*, uint32_t*, void*) { return 1; }
inline uint32_t vkCreateDevice(void*, void*, void*, void**) { return 1; }
inline uint32_t vkCreateCommandPool(void*, void*, void*, void**) { return 1; }
inline uint32_t vkAllocateCommandBuffers(void*, void*, void**) { return 1; }
inline uint32_t vkCreateFence(void*, void*, void*, void**) { return 1; }
inline uint32_t vkCreateBuffer(void*, void*, void*, void**) { return 1; }
inline uint32_t vkAllocateMemory(void*, void*, void*, void**) { return 1; }
inline uint32_t vkBeginCommandBuffer(void*, void*) { return 0; }
inline uint32_t vkEndCommandBuffer(void*) { return 0; }
inline uint32_t vkQueueSubmit(void*, uint32_t, void*, void*) { return 0; }
inline uint32_t vkWaitForFences(void*, uint32_t, void*, uint32_t, uint64_t) { return 0; }
inline uint32_t vkResetFences(void*, uint32_t, void*) { return 0; }
inline uint32_t vkResetCommandBuffer(void*, uint32_t) { return 0; }
inline uint32_t vkQueueWaitIdle(void*) { return 0; }
inline uint32_t vkCreateShaderModule(void*, void*, void*, void**) { return 0; }
inline uint32_t vkCreateDescriptorSetLayout(void*, void*, void*, void**) { return 0; }
inline uint32_t vkCreatePipelineLayout(void*, void*, void*, void**) { return 0; }
inline uint32_t vkCreateComputePipelines(void*, void*, uint32_t, void*, void*, void**) { return 0; }
inline uint32_t vkCreateDescriptorPool(void*, void*, void*, void**) { return 0; }
inline uint32_t vkAllocateDescriptorSets(void*, void*, void**) { return 0; }
inline uint32_t vkFreeDescriptorSets(void*, void*, uint32_t, const void*) { return 0; }
inline uint32_t vkCreateQueryPool(void*, void*, void*, void**) { return 0; }
inline void vkCmdResetQueryPool(void*, void*, uint32_t, uint32_t) {}
inline void vkCmdWriteTimestamp(void*, uint32_t, void*, uint32_t) {}
inline uint32_t vkGetQueryPoolResults(void*, void*, uint32_t, uint32_t, uint64_t, void*, uint64_t, uint32_t) { return 0; }
inline void vkCmdCopyBuffer(void*, void*, void*, uint32_t, void*) {}
inline void vkCmdDispatch(void*, uint32_t, uint32_t, uint32_t) {}
struct VkBufferMemoryBarrier { uint32_t sType; void* pNext; uint32_t srcAccessMask; uint32_t dstAccessMask; uint32_t srcQueueFamilyIndex; uint32_t dstQueueFamilyIndex; VkBuffer buffer; uint64_t offset; uint64_t size; };
inline void vkCmdPipelineBarrier(void*, uint32_t, uint32_t, uint32_t, uint32_t, const void*, uint32_t, const VkBufferMemoryBarrier*, uint32_t, const void*) {}
struct VkApplicationInfo { uint32_t sType; void* pNext; const char* pApplicationName; uint32_t applicationVersion; const char* pEngineName; uint32_t engineVersion; uint32_t apiVersion; };
struct VkInstanceCreateInfo { uint32_t sType; void* pNext; uint32_t flags; void* pApplicationInfo; uint32_t enabledLayerCount; void* ppEnabledLayerNames; uint32_t enabledExtensionCount; void* ppEnabledExtensionNames; };
struct VkDeviceQueueCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint32_t queueFamilyIndex; uint32_t queueCount; const float* pQueuePriorities; };
struct VkDeviceCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint32_t queueCreateInfoCount; void* pQueueCreateInfos; uint32_t enabledLayerCount; void* ppEnabledLayerNames; uint32_t enabledExtensionCount; void* ppEnabledExtensionNames; void* pEnabledFeatures; };
struct VkCommandPoolCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint32_t queueFamilyIndex; };
struct VkCommandBufferAllocateInfo { uint32_t sType; void* pNext; void* commandPool; uint32_t level; uint32_t commandBufferCount; };
struct VkCommandBufferBeginInfo { uint32_t sType; void* pNext; uint32_t flags; void* pInheritanceInfo; };
struct VkBufferCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint64_t size; uint32_t usage; uint32_t sharingMode; uint32_t queueFamilyIndexCount; void* pQueueFamilyIndices; };
struct VkMemoryAllocateInfo { uint32_t sType; void* pNext; uint64_t allocationSize; uint32_t memoryTypeIndex; };
struct VkFenceCreateInfo { uint32_t sType; void* pNext; uint32_t flags; };
struct VkSubmitInfo { uint32_t sType; void* pNext; uint32_t waitSemaphoreCount; void* pWaitSemaphores; void* pWaitDstStageMask; uint32_t commandBufferCount; void* pCommandBuffers; uint32_t signalSemaphoreCount; void* pSignalSemaphores; };
struct VkBufferCopy { uint64_t srcOffset; uint64_t dstOffset; uint64_t size; };
struct VkMemoryRequirements { uint64_t size; uint64_t alignment; uint32_t memoryTypeBits; };
struct VkPhysicalDeviceMemoryProperties { uint32_t memoryTypeCount; struct { uint32_t propertyFlags; uint32_t heapIndex; } memoryTypes[32]; uint32_t memoryHeapCount; struct { uint64_t size; uint64_t flags; } memoryHeaps[16]; };
struct VkPhysicalDeviceLimits { float timestampPeriod; uint32_t maxComputeWorkGroupCount[3]; uint32_t maxComputeWorkGroupInvocations; uint32_t maxComputeWorkGroupSize[3]; };
struct VkPhysicalDeviceProperties { VkPhysicalDeviceLimits limits; };
struct VkQueueFamilyProperties { uint32_t queueFlags; uint32_t queueCount; uint32_t timestampValidBits; void* minImageTransferGranularity; };
struct VkShaderModuleCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint64_t codeSize; const uint32_t* pCode; };
struct VkDescriptorSetLayoutBinding { uint32_t binding; uint32_t descriptorType; uint32_t descriptorCount; uint32_t stageFlags; void* pImmutableSamplers; };
struct VkDescriptorSetLayoutCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint32_t bindingCount; const VkDescriptorSetLayoutBinding* pBindings; };
struct VkPushConstantRange { uint32_t stageFlags; uint32_t offset; uint32_t size; };
struct VkPipelineLayoutCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint32_t setLayoutCount; const VkDescriptorSetLayout* pSetLayouts; uint32_t pushConstantRangeCount; const VkPushConstantRange* pPushConstantRanges; };
struct VkPipelineShaderStageCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint32_t stage; VkShaderModule module; const char* pName; void* pSpecializationInfo; };
struct VkComputePipelineCreateInfo { uint32_t sType; void* pNext; uint32_t flags; VkPipelineShaderStageCreateInfo stage; VkPipelineLayout layout; VkPipeline basePipelineHandle; int32_t basePipelineIndex; };
struct VkDescriptorPoolSize { uint32_t type; uint32_t descriptorCount; };
struct VkDescriptorPoolCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint32_t maxSets; uint32_t poolSizeCount; const VkDescriptorPoolSize* pPoolSizes; };
struct VkDescriptorSetAllocateInfo { uint32_t sType; void* pNext; VkDescriptorPool descriptorPool; uint32_t descriptorSetCount; const VkDescriptorSetLayout* pSetLayouts; };
struct VkDescriptorBufferInfo { VkBuffer buffer; uint64_t offset; uint64_t range; };
struct VkWriteDescriptorSet { uint32_t sType; void* pNext; VkDescriptorSet dstSet; uint32_t dstBinding; uint32_t dstArrayElement; uint32_t descriptorCount; uint32_t descriptorType; const VkDescriptorBufferInfo* pBufferInfo; void* pImageInfo; void* pTexelBufferView; };
struct VkQueryPoolCreateInfo { uint32_t sType; void* pNext; uint32_t flags; uint32_t queryType; uint32_t queryCount; uint32_t pipelineStatistics; };
// Timeline Semaphore stubs
constexpr uint32_t VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO = 20;
constexpr uint32_t VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO = 1000245002;
constexpr uint32_t VK_SEMAPHORE_TYPE_TIMELINE = 1;
constexpr uint32_t VK_STRUCTURE_TYPE_SEMAPHORE_TYPE_CREATE_INFO = 1000245000;
struct VkSemaphoreCreateInfo { uint32_t sType; void* pNext; uint32_t flags; };
struct VkSemaphoreTypeCreateInfo { uint32_t sType; void* pNext; uint32_t semaphoreType; uint64_t initialValue; };
struct VkTimelineSemaphoreSubmitInfo { uint32_t sType; void* pNext; uint32_t waitSemaphoreValueCount; const uint64_t* pWaitSemaphoreValues; uint32_t signalSemaphoreValueCount; const uint64_t* pSignalSemaphoreValues; };
inline uint32_t vkCreateSemaphore(void*, void*, void*, void**) { return 0; }
inline void vkDestroySemaphore(void*, void*, void*) {}
inline uint32_t vkGetSemaphoreCounterValue(void*, void*, uint64_t*) { return 0; }
#endif

// ============================================================================
// ASM function pointers — populated by Initialize(), consumed by shim
// ============================================================================
// These are the external symbols the MASM shim dereferences via [p_vkCmdDispatch]
// etc. The C++ side resolves them with vkGetDeviceProcAddr and writes here.
// ============================================================================

extern "C" {
    // Function pointer table written by VulkanAccelerator::Initialize()
    void* p_vkCmdDispatch      = nullptr;
    void* p_vkQueueSubmit      = nullptr;
    void* p_vkWaitForFences    = nullptr;
    void* p_vkCmdBindPipeline  = nullptr;
    void* p_vkCmdBindDescriptorSets = nullptr;
    void* p_vkCmdPushConstants = nullptr;
    void* p_vkCmdDispatchIndirect = nullptr;
    void* p_vkQueueWaitIdle    = nullptr;
    void* p_vkResetFences      = nullptr;
    void* p_vkGetSemaphoreCounterValue = nullptr;

    // MASM shim entry points (implemented in RawrXD_Vulkan_Shim.asm)
    int RawrXD_DispatchMatMul_Asm(void* instance, const void* desc);
    int RawrXD_KVAppend_Asm(void* instance, const void* desc);
    int RawrXD_Wait_Asm(void* instance, uint64_t timeout_ns);
    int RawrXD_SubmitGraph_Asm(void* instance, const void* submit_info);
    int RawrXD_QueueWaitIdle_Asm(void* instance);
    int RawrXD_DispatchRMSNorm_Asm(void* instance, const void* args);
    int RawrXD_TimelinePoll_Asm(void* instance, uint64_t target_value, uint64_t* out_current);

    // MASM async DMA ring orchestrator (host-side transfer lane scheduler)
    void     RawrXD_DMA_Init_Asm(uint64_t capacity);
    uint64_t RawrXD_DMA_AcquireFill_Asm();
    void     RawrXD_DMA_Commit_Asm();
    void     RawrXD_DMA_Release_Asm();
    uint64_t RawrXD_DMA_Head_Asm();
    uint64_t RawrXD_DMA_Tail_Asm();
    uint64_t RawrXD_DMA_Depth_Asm();
    uint64_t RawrXD_DMA_IsNearlyFull_Asm(uint64_t margin);
    uint64_t RawrXD_DMA_GetFullCount_Asm();

    // MASM integrity validator (SSE4.2 CRC32C)
    uint32_t RawrXD_ValidateBufferCRC32_Asm(const void* buffer_ptr, uint64_t size_bytes, uint32_t seed);
}

namespace rawrxd {

static uint64_t NowSteadyNs() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

// ============================================================================
// PIMPL — Vulkan state hidden from header
// ============================================================================

struct VulkanAccelerator::Impl {
    // Vulkan handles
    VkInstance       instance_       = VK_NULL_HANDLE;
    VkDevice         device_         = VK_NULL_HANDLE;
    VkPhysicalDevice physical_device_ = VK_NULL_HANDLE;
    VkQueue          queue_          = VK_NULL_HANDLE;
    uint32_t         queue_family_   = 0;
    VkCommandPool    cmd_pool_       = VK_NULL_HANDLE;
    VkCommandBuffer  cmd_buffer_     = VK_NULL_HANDLE;
    VkFence          fence_          = VK_NULL_HANDLE;

    // Memory
    VkDeviceMemory   staging_memory_  = VK_NULL_HANDLE;
    VkBuffer         staging_buffer_  = VK_NULL_HANDLE;
    void*            staging_mapped_  = nullptr;
    size_t           staging_size_    = 0;
    ComputeLimits    compute_limits_{};

    // Async upload ring (submit-and-forget staging lanes)
    static constexpr uint32_t kUploadRingSize = 16;
    static constexpr uint32_t kUploadRingDefaultCapacity = 8;
    struct UploadSlot {
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence         fence = VK_NULL_HANDLE;
        VkDeviceMemory  staging_memory = VK_NULL_HANDLE;
        VkBuffer        staging_buffer = VK_NULL_HANDLE;
        void*           staging_mapped = nullptr;
        size_t          staging_size = 0;
        bool            in_flight = false;
        uint64_t        submit_seq = 0;
    };
    UploadSlot upload_ring_[kUploadRingSize];
    bool       upload_ring_ready_ = false;
    uint32_t   upload_ring_capacity_ = kUploadRingDefaultCapacity;
    uint64_t   upload_submit_seq_ = 0;
    uint64_t   upload_full_last_count_ = 0;
    uint32_t   upload_inject_us_ = 0;
    uint32_t   upload_wait_inject_us_ = 0;
    bool       upload_force_burst_ = false;
    uint32_t   upload_nearly_full_margin_ = 2;

    // Tensor pool (simple fixed array for scaffolding)
    static constexpr uint32_t kMaxTensors = 4096;
    struct TensorSlot {
        VkBuffer       buffer = VK_NULL_HANDLE;
        VkDeviceMemory memory = VK_NULL_HANDLE;
        size_t         size_bytes = 0;
        bool           occupied = false;
        bool           upload_pending = false;
        uint32_t       upload_slot_idx = UINT32_MAX;
        uint64_t       upload_seq = 0;
    };
    TensorSlot tensor_pool_[kMaxTensors];
    uint32_t   next_tensor_id_ = 1;   // 0 = invalid

    // Kernel pipeline cache (data-driven, indexed by kernel ID)
    static constexpr uint32_t kMaxKernels = 64;
    struct KernelSlot {
        VkPipeline       pipeline = VK_NULL_HANDLE;
        VkPipelineLayout layout   = VK_NULL_HANDLE;
        VkDescriptorSetLayout ds_layout = VK_NULL_HANDLE;
        VkDescriptorSet  descriptor_set = VK_NULL_HANDLE;
        VkShaderModule   shader_module = VK_NULL_HANDLE;
        uint32_t         binding_count = 0;
        bool             occupied = false;
        bool             descriptors_bound = false; // TRUE if descriptor set has been updated with tensor bindings
        char             name[32] = {};
    };
    KernelSlot kernel_pool_[kMaxKernels];
    uint32_t   next_kernel_id_ = 1;   // 0 = invalid

    // Descriptor pool for compute kernels (one pool, many sets)
    VkDescriptorPool descriptor_pool_ = VK_NULL_HANDLE;

    // ------------------------------------------------------------------------
    // Sovereign Hot-Path: Persistent Command Buffer Ring + Timeline Semaphore
    // ------------------------------------------------------------------------
    // Design: Pre-recorded command buffers eliminate vkReset/Begin/End overhead.
    // Timeline semaphores replace fence stalls with non-blocking CPU polling.
    // ------------------------------------------------------------------------
    static constexpr uint32_t kCmdBufRingSize = 4;   // N-way buffering
    struct CmdBufSlot {
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence         fence = VK_NULL_HANDLE;      // Legacy fallback
        bool            ready = true;
    };
    CmdBufSlot cmd_ring_[kCmdBufRingSize];
    uint32_t   cmd_ring_head_ = 0;   // Next slot to use

    VkSemaphore timeline_semaphore_ = VK_NULL_HANDLE;
    uint64_t    timeline_value_ = 0; // Monotonically incremented per dispatch
    float       timestamp_period_ns_ = 1.0f;

    // ------------------------------------------------------------------------
    // Sovereign Static Pipeline: UBO Ring + Pre-recorded Command Buffers
    // ------------------------------------------------------------------------
    // Design: 16 UBO slots (256 bytes each) in host-visible memory.
    // Each slot has a pre-recorded command buffer containing:
    //   bindPipeline -> bindDescriptorSets(UBO+SSBOs) -> dispatch
    // Hot path: memcpy(params into mapped UBO) -> vkQueueSubmit(pre-recorded CB)
    // Zero vkResetCommandBuffer, vkBeginCommandBuffer, vkEndCommandBuffer overhead.
    // ------------------------------------------------------------------------
    static constexpr uint32_t kStaticRingSize = 16;   // Must be power of 2
    static constexpr uint32_t kUBOSlotSize   = 256;   // Bytes per slot (std140 aligned)
    struct StaticSlot {
        VkCommandBuffer cmd = VK_NULL_HANDLE;   // Pre-recorded, NEVER reset
        VkFence         fence = VK_NULL_HANDLE; // Per-slot completion fence
        bool            ready = true;
        uint32_t        kernel_id = 0;          // Which kernel this CB was recorded for
    };
    StaticSlot static_ring_[kStaticRingSize];
    uint32_t   static_ring_head_ = 0;
    uint32_t   static_kernel_id_ = 0;  // Which kernel ID the static CBs were recorded for
    uint64_t   static_layer_signature_ = 0; // Cached topology hash for chained layer CBs
    std::vector<VkDescriptorSet> static_layer_descriptor_sets_;

    // UBO: persistently mapped host-visible buffer for per-dispatch parameters
    VkBuffer       ubo_buffer_  = VK_NULL_HANDLE;
    VkDeviceMemory ubo_memory_  = VK_NULL_HANDLE;
    void*          ubo_mapped_  = nullptr;   // CPU-writable, GPU-readable
    uint32_t       ubo_mem_type_ = UINT32_MAX;

    // Timestamp queries (2 per static slot: begin/end)
    VkQueryPool    timestamp_query_pool_ = VK_NULL_HANDLE;
    uint32_t       last_submitted_static_indices_[kStaticRingSize] = {};
    uint32_t       last_submitted_static_count_ = 0;
    uint64_t       last_gpu_dispatch_ns_ = 0;
    uint64_t       last_submit_cpu_ns_ = 0;

    // Stats
    Stats stats_;

    // Helpers
    bool FindComputeQueue();
    bool CreateCommandBuffer();
    bool CreateStagingBuffer(size_t size);
    bool CreateUploadRing();
    bool EnsureUploadSlotStaging(uint32_t slot_idx, size_t size);
    bool FlushUploadRing(bool block);
    bool WaitForTensorUpload(GpuTensorHandle handle);
    bool WaitForTensorUploads(const GpuTensorHandle* handles, size_t handle_count);
    void ResolveProcAddresses();
    bool CreateDescriptorPool();
    bool CreateKernelPipeline(uint32_t slot_idx, const void* spv_data, size_t spv_size, uint32_t binding_count);
    void DestroyKernelSlot(uint32_t slot_idx);

    // Sovereign hot-path helpers
    bool CreateTimelineSemaphore();
    bool CreatePersistentCommandBuffer();
    bool PrepareRMSNormDispatch(uint32_t kernel_id, const RMSNormDesc& desc);
    bool SubmitPersistentDispatch(uint32_t groups_x, uint32_t groups_y, uint32_t groups_z);
    bool PollTimeline(uint64_t target_value, uint64_t* out_current);

    // Static Pipeline helpers (UBO-based zero-recording path)
    bool CreateUBOBuffer();
    void DestroyUBOBuffer();
    bool RecordStaticCBs(uint32_t kernel_id, uint32_t groups_x, uint32_t groups_y);
    bool RecordStaticLayerCBs(const StaticLayerDesc& desc);
    void CaptureLastStaticGpuDispatchNs();
};

// ============================================================================
// Helpers
// ============================================================================

bool VulkanAccelerator::Impl::FindComputeQueue() {
    uint32_t queue_family_count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device_, &queue_family_count, nullptr);
    if (queue_family_count == 0) return false;

    auto* families = static_cast<VkQueueFamilyProperties*>(
        std::malloc(queue_family_count * sizeof(VkQueueFamilyProperties)));
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device_, &queue_family_count, families);

    for (uint32_t i = 0; i < queue_family_count; ++i) {
        if (families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            queue_family_ = i;
            std::free(families);
            return true;
        }
    }
    std::free(families);
    return false;
}

bool VulkanAccelerator::Impl::CreateCommandBuffer() {
    VkCommandPoolCreateInfo pool_info{};
    pool_info.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_info.queueFamilyIndex = queue_family_;
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    if (vkCreateCommandPool(device_, &pool_info, nullptr, &cmd_pool_) != VK_SUCCESS)
        return false;

    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = cmd_pool_;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = 1;
    if (vkAllocateCommandBuffers(device_, &alloc_info, &cmd_buffer_) != VK_SUCCESS)
        return false;

    VkFenceCreateInfo fence_info{};
    fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    if (vkCreateFence(device_, &fence_info, nullptr, &fence_) != VK_SUCCESS)
        return false;

    return true;
}

bool VulkanAccelerator::Impl::CreateStagingBuffer(size_t size) {
    if (staging_buffer_ != VK_NULL_HANDLE && staging_size_ >= size)
        return true;

    // Cleanup old
    if (staging_buffer_ != VK_NULL_HANDLE) {
        vkDestroyBuffer(device_, staging_buffer_, nullptr);
        vkFreeMemory(device_, staging_memory_, nullptr);
    }

    VkBufferCreateInfo buf_info{};
    buf_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buf_info.size = size;
    buf_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    buf_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device_, &buf_info, nullptr, &staging_buffer_) != VK_SUCCESS)
        return false;

    VkMemoryRequirements mem_req{};
    vkGetBufferMemoryRequirements(device_, staging_buffer_, &mem_req);

    VkPhysicalDeviceMemoryProperties mem_props{};
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &mem_props);

    uint32_t mem_type_idx = UINT32_MAX;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((mem_req.memoryTypeBits & (1u << i)) &&
            (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
            mem_type_idx = i;
            break;
        }
    }
    if (mem_type_idx == UINT32_MAX) return false;

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_req.size;
    alloc_info.memoryTypeIndex = mem_type_idx;
    if (vkAllocateMemory(device_, &alloc_info, nullptr, &staging_memory_) != VK_SUCCESS)
        return false;

    vkBindBufferMemory(device_, staging_buffer_, staging_memory_, 0);
    vkMapMemory(device_, staging_memory_, 0, size, 0, &staging_mapped_);
    staging_size_ = size;
    return true;
}

bool VulkanAccelerator::Impl::CreateUploadRing() {
    if (upload_ring_ready_) {
        return true;
    }

    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = cmd_pool_;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = 1;

    for (uint32_t i = 0; i < upload_ring_capacity_; ++i) {
        if (vkAllocateCommandBuffers(device_, &alloc_info, &upload_ring_[i].cmd) != VK_SUCCESS) {
            return false;
        }

        VkFenceCreateInfo fence_info{};
        fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        if (vkCreateFence(device_, &fence_info, nullptr, &upload_ring_[i].fence) != VK_SUCCESS) {
            return false;
        }
        upload_ring_[i].in_flight = false;
    }

    RawrXD_DMA_Init_Asm(static_cast<uint64_t>(upload_ring_capacity_));
    upload_full_last_count_ = RawrXD_DMA_GetFullCount_Asm();
    upload_ring_ready_ = true;
    return true;
}

bool VulkanAccelerator::Impl::EnsureUploadSlotStaging(uint32_t slot_idx, size_t size) {
    if (slot_idx >= upload_ring_capacity_) {
        return false;
    }

    auto& slot = upload_ring_[slot_idx];
    if (slot.staging_buffer != VK_NULL_HANDLE && slot.staging_size >= size) {
        return true;
    }

    if (slot.staging_buffer != VK_NULL_HANDLE) {
        vkDestroyBuffer(device_, slot.staging_buffer, nullptr);
        slot.staging_buffer = VK_NULL_HANDLE;
    }
    if (slot.staging_memory != VK_NULL_HANDLE) {
        vkFreeMemory(device_, slot.staging_memory, nullptr);
        slot.staging_memory = VK_NULL_HANDLE;
    }
    slot.staging_mapped = nullptr;
    slot.staging_size = 0;

    VkBufferCreateInfo buf_info{};
    buf_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buf_info.size = size;
    buf_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    buf_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device_, &buf_info, nullptr, &slot.staging_buffer) != VK_SUCCESS) {
        return false;
    }

    VkMemoryRequirements mem_req{};
    vkGetBufferMemoryRequirements(device_, slot.staging_buffer, &mem_req);

    VkPhysicalDeviceMemoryProperties mem_props{};
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &mem_props);

    uint32_t mem_type_idx = UINT32_MAX;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((mem_req.memoryTypeBits & (1u << i)) &&
            (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
            mem_type_idx = i;
            break;
        }
    }
    if (mem_type_idx == UINT32_MAX) {
        return false;
    }

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_req.size;
    alloc_info.memoryTypeIndex = mem_type_idx;
    if (vkAllocateMemory(device_, &alloc_info, nullptr, &slot.staging_memory) != VK_SUCCESS) {
        return false;
    }

    vkBindBufferMemory(device_, slot.staging_buffer, slot.staging_memory, 0);
    vkMapMemory(device_, slot.staging_memory, 0, size, 0, &slot.staging_mapped);
    slot.staging_size = size;
    return true;
}

bool VulkanAccelerator::Impl::FlushUploadRing(bool block) {
    if (!upload_ring_ready_) {
        return true;
    }

    while (RawrXD_DMA_Tail_Asm() != RawrXD_DMA_Head_Asm()) {
        const uint32_t tail = static_cast<uint32_t>(RawrXD_DMA_Tail_Asm() % upload_ring_capacity_);
        auto& slot = upload_ring_[tail];
        if (!slot.in_flight) {
            RawrXD_DMA_Release_Asm();
            continue;
        }

        VkResult r = vkWaitForFences(device_, 1, &slot.fence, VK_TRUE, block ? UINT64_MAX : 0);
        if (!block && r != VK_SUCCESS) {
            break;
        }
        if (r == VK_SUCCESS) {
            vkResetFences(device_, 1, &slot.fence);
            vkResetCommandBuffer(slot.cmd, 0);
            slot.in_flight = false;
            RawrXD_DMA_Release_Asm();
            continue;
        }
        return false;
    }

    return true;
}

bool VulkanAccelerator::Impl::WaitForTensorUpload(GpuTensorHandle handle) {
    if (!handle.IsValid()) {
        return false;
    }

    const uint32_t tensor_idx = handle.id - 1;
    if (tensor_idx >= kMaxTensors) {
        return false;
    }

    auto& tensor = tensor_pool_[tensor_idx];
    if (!tensor.occupied || !tensor.upload_pending) {
        return true;
    }

    if (tensor.upload_slot_idx >= upload_ring_capacity_) {
        tensor.upload_pending = false;
        tensor.upload_slot_idx = UINT32_MAX;
        tensor.upload_seq = 0;
        return true;
    }

    auto& slot = upload_ring_[tensor.upload_slot_idx];
    if (slot.in_flight && slot.submit_seq == tensor.upload_seq) {
        const uint64_t wait_start = NowSteadyNs();
        if (upload_wait_inject_us_ > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(upload_wait_inject_us_));
        }
        VkResult r = vkWaitForFences(device_, 1, &slot.fence, VK_TRUE, UINT64_MAX);
        const uint64_t wait_ns = NowSteadyNs() - wait_start;
        stats_.upload_wait_count++;
        stats_.upload_wait_ns += wait_ns;
        if (r != VK_SUCCESS) {
            return false;
        }
    }

    if (!FlushUploadRing(false)) {
        return false;
    }

    tensor.upload_pending = false;
    tensor.upload_slot_idx = UINT32_MAX;
    tensor.upload_seq = 0;
    return true;
}

bool VulkanAccelerator::Impl::WaitForTensorUploads(const GpuTensorHandle* handles, size_t handle_count) {
    for (size_t i = 0; i < handle_count; ++i) {
        if (!WaitForTensorUpload(handles[i])) {
            return false;
        }
    }
    return true;
}

void VulkanAccelerator::Impl::ResolveProcAddresses() {
    // Resolve device-level entry points and write to the extern "C" table
    // so the MASM shim can call them without going through the loader.
    auto get = [&](const char* name) -> void* {
        return reinterpret_cast<void*>(vkGetDeviceProcAddr(device_, name));
    };

    p_vkCmdDispatch      = get("vkCmdDispatch");
    p_vkQueueSubmit      = get("vkQueueSubmit");
    p_vkWaitForFences    = get("vkWaitForFences");
    p_vkCmdBindPipeline  = get("vkCmdBindPipeline");
    p_vkCmdBindDescriptorSets = get("vkCmdBindDescriptorSets");
    p_vkCmdPushConstants = get("vkCmdPushConstants");
    p_vkCmdDispatchIndirect = get("vkCmdDispatchIndirect");
    p_vkQueueWaitIdle    = get("vkQueueWaitIdle");
    p_vkResetFences      = get("vkResetFences");
    p_vkGetSemaphoreCounterValue = get("vkGetSemaphoreCounterValue");
}

bool VulkanAccelerator::Impl::CreateDescriptorPool() {
    if (descriptor_pool_ != VK_NULL_HANDLE) return true;

    VkDescriptorPoolSize pool_sizes[2] = {};
    pool_sizes[0].type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    pool_sizes[0].descriptorCount = kMaxKernels * 8; // 8 SSBO bindings per kernel max
    pool_sizes[1].type = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
    pool_sizes[1].descriptorCount = kMaxKernels;     // 1 UBO per kernel

    VkDescriptorPoolCreateInfo pool_info{};
    pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pool_info.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    pool_info.maxSets = kMaxKernels;
    pool_info.poolSizeCount = 2;
    pool_info.pPoolSizes = pool_sizes;

    return vkCreateDescriptorPool(device_, &pool_info, nullptr, &descriptor_pool_) == VK_SUCCESS;
}

bool VulkanAccelerator::Impl::CreateKernelPipeline(uint32_t slot_idx, const void* spv_data,
                                                     size_t spv_size, uint32_t binding_count) {
    if (slot_idx >= kMaxKernels) return false;
    auto& slot = kernel_pool_[slot_idx];

    // 1. Create shader module from SPIR-V blob
    VkShaderModuleCreateInfo sm_info{};
    sm_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm_info.codeSize = spv_size;
    sm_info.pCode = static_cast<const uint32_t*>(spv_data);
    if (vkCreateShaderModule(device_, &sm_info, nullptr, &slot.shader_module) != VK_SUCCESS)
        return false;

    // 2. Create descriptor set layout (storage buffers + UBO at binding 3)
    uint32_t total_bindings = binding_count + 1; // +1 for UBO at binding 3
    VkDescriptorSetLayoutBinding* bindings = static_cast<VkDescriptorSetLayoutBinding*>(
        std::malloc(total_bindings * sizeof(VkDescriptorSetLayoutBinding)));
    for (uint32_t i = 0; i < binding_count; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        bindings[i].pImmutableSamplers = nullptr;
    }
    // UBO binding at binding 3
    bindings[binding_count].binding = binding_count;
    bindings[binding_count].descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
    bindings[binding_count].descriptorCount = 1;
    bindings[binding_count].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    bindings[binding_count].pImmutableSamplers = nullptr;

    VkDescriptorSetLayoutCreateInfo dsl_info{};
    dsl_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dsl_info.bindingCount = total_bindings;
    dsl_info.pBindings = bindings;
    VkResult dsl_res = vkCreateDescriptorSetLayout(device_, &dsl_info, nullptr, &slot.ds_layout);
    std::free(bindings);
    if (dsl_res != VK_SUCCESS) return false;

    // 3. Create pipeline layout (NO push constants — all params via UBO)
    VkPipelineLayoutCreateInfo pl_info{};
    pl_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pl_info.setLayoutCount = 1;
    pl_info.pSetLayouts = &slot.ds_layout;
    pl_info.pushConstantRangeCount = 0; // UBO replaces push constants
    pl_info.pPushConstantRanges = nullptr;
    if (vkCreatePipelineLayout(device_, &pl_info, nullptr, &slot.layout) != VK_SUCCESS)
        return false;

    // 4. Create compute pipeline
    VkComputePipelineCreateInfo cp_info{};
    cp_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cp_info.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cp_info.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    cp_info.stage.module = slot.shader_module;
    cp_info.stage.pName = "main";
    cp_info.layout = slot.layout;
    if (vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &cp_info, nullptr, &slot.pipeline) != VK_SUCCESS)
        return false;

    // 5. Allocate descriptor set from pool
    if (!CreateDescriptorPool()) return false;
    VkDescriptorSetAllocateInfo ds_alloc{};
    ds_alloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ds_alloc.descriptorPool = descriptor_pool_;
    ds_alloc.descriptorSetCount = 1;
    ds_alloc.pSetLayouts = &slot.ds_layout;
    if (vkAllocateDescriptorSets(device_, &ds_alloc, &slot.descriptor_set) != VK_SUCCESS)
        return false;

    slot.binding_count = binding_count;
    slot.occupied = true;
    return true;
}

void VulkanAccelerator::Impl::DestroyKernelSlot(uint32_t slot_idx) {
    if (slot_idx >= kMaxKernels) return;
    auto& slot = kernel_pool_[slot_idx];
    if (!slot.occupied) return;

    if (slot.pipeline != VK_NULL_HANDLE)
        vkDestroyPipeline(device_, slot.pipeline, nullptr);
    if (slot.layout != VK_NULL_HANDLE)
        vkDestroyPipelineLayout(device_, slot.layout, nullptr);
    if (slot.ds_layout != VK_NULL_HANDLE)
        vkDestroyDescriptorSetLayout(device_, slot.ds_layout, nullptr);
    if (slot.shader_module != VK_NULL_HANDLE)
        vkDestroyShaderModule(device_, slot.shader_module, nullptr);

    slot = {};
}

// ============================================================================
// Sovereign Hot-Path Helpers — Persistent CB + Timeline Semaphore
// ============================================================================

bool VulkanAccelerator::Impl::CreateTimelineSemaphore() {
    VkSemaphoreTypeCreateInfo type_info{};
    type_info.sType = VK_STRUCTURE_TYPE_SEMAPHORE_TYPE_CREATE_INFO;
    type_info.semaphoreType = VK_SEMAPHORE_TYPE_TIMELINE;
    type_info.initialValue = 0;

    VkSemaphoreCreateInfo sem_info{};
    sem_info.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    sem_info.pNext = &type_info;

    return vkCreateSemaphore(device_, &sem_info, nullptr, &timeline_semaphore_) == VK_SUCCESS;
}

bool VulkanAccelerator::Impl::CreatePersistentCommandBuffer() {
    // Create the legacy command buffer ring for multi-buffering
    // (used for upload/download, not for hot-path dispatches)
    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = cmd_pool_;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = 1;
    for (uint32_t i = 0; i < kCmdBufRingSize; ++i) {
        if (vkAllocateCommandBuffers(device_, &alloc_info, &cmd_ring_[i].cmd) != VK_SUCCESS)
            return false;

        VkFenceCreateInfo fence_info{};
        fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        if (vkCreateFence(device_, &fence_info, nullptr, &cmd_ring_[i].fence) != VK_SUCCESS)
            return false;
        cmd_ring_[i].ready = true;
    }

    return true;
}

bool VulkanAccelerator::Impl::CreateUBOBuffer() {
    // Create a host-visible, device-local (if possible) buffer for per-dispatch params.
    // 16 slots × 256 bytes = 4096 bytes total.
    VkBufferCreateInfo buf_info{};
    buf_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buf_info.size = kStaticRingSize * kUBOSlotSize;
    buf_info.usage = VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT;
    buf_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device_, &buf_info, nullptr, &ubo_buffer_) != VK_SUCCESS)
        return false;

    VkMemoryRequirements mem_req{};
    vkGetBufferMemoryRequirements(device_, ubo_buffer_, &mem_req);

    VkPhysicalDeviceMemoryProperties mem_props{};
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &mem_props);

    // Prefer HOST_VISIBLE | DEVICE_LOCAL (AMD ReBAR), fallback to HOST_VISIBLE | HOST_COHERENT
    ubo_mem_type_ = UINT32_MAX;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((mem_req.memoryTypeBits & (1u << i)) &&
            (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
            ubo_mem_type_ = i;
            break;
        }
    }
    if (ubo_mem_type_ == UINT32_MAX) {
        for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
            if ((mem_req.memoryTypeBits & (1u << i)) &&
                (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
                (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
                ubo_mem_type_ = i;
                break;
            }
        }
    }
    if (ubo_mem_type_ == UINT32_MAX) return false;

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_req.size;
    alloc_info.memoryTypeIndex = ubo_mem_type_;
    if (vkAllocateMemory(device_, &alloc_info, nullptr, &ubo_memory_) != VK_SUCCESS)
        return false;

    vkBindBufferMemory(device_, ubo_buffer_, ubo_memory_, 0);
    vkMapMemory(device_, ubo_memory_, 0, mem_req.size, 0, &ubo_mapped_);

    // Zero-initialize all slots
    std::memset(ubo_mapped_, 0, kStaticRingSize * kUBOSlotSize);
    return true;
}

void VulkanAccelerator::Impl::DestroyUBOBuffer() {
    if (ubo_mapped_) {
        vkUnmapMemory(device_, ubo_memory_);
        ubo_mapped_ = nullptr;
    }
    if (ubo_buffer_ != VK_NULL_HANDLE) {
        vkDestroyBuffer(device_, ubo_buffer_, nullptr);
        ubo_buffer_ = VK_NULL_HANDLE;
    }
    if (ubo_memory_ != VK_NULL_HANDLE) {
        vkFreeMemory(device_, ubo_memory_, nullptr);
        ubo_memory_ = VK_NULL_HANDLE;
    }
}

bool VulkanAccelerator::Impl::RecordStaticCBs(uint32_t kernel_id, uint32_t groups_x, uint32_t groups_y) {
    uint32_t kslot = kernel_id - 1;
    if (kslot >= kMaxKernels || !kernel_pool_[kslot].occupied) return false;
    auto& k = kernel_pool_[kslot];

    // Pre-record 16 static command buffers — one per UBO slot
    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = cmd_pool_;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = 1;

    for (uint32_t i = 0; i < kStaticRingSize; ++i) {
        if (vkAllocateCommandBuffers(device_, &alloc_info, &static_ring_[i].cmd) != VK_SUCCESS)
            return false;

        VkFenceCreateInfo fence_info{};
        fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        if (vkCreateFence(device_, &fence_info, nullptr, &static_ring_[i].fence) != VK_SUCCESS)
            return false;
        static_ring_[i].ready = true;
        static_ring_[i].kernel_id = kernel_id;

        // Record the IMMUTABLE command buffer for this slot
        VkCommandBufferBeginInfo begin_info{};
        begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin_info.flags = VK_COMMAND_BUFFER_USAGE_SIMULTANEOUS_USE_BIT;
        VkResult r = vkBeginCommandBuffer(static_ring_[i].cmd, &begin_info);
        if (r != VK_SUCCESS) return false;

        // Bind pipeline (static)
        vkCmdBindPipeline(static_ring_[i].cmd, VK_PIPELINE_BIND_POINT_COMPUTE, k.pipeline);

        // Bind descriptors with DYNAMIC offset for UBO slot
        uint32_t dynamic_offset = i * kUBOSlotSize;
        vkCmdBindDescriptorSets(static_ring_[i].cmd, VK_PIPELINE_BIND_POINT_COMPUTE, k.layout,
                                0, 1, &k.descriptor_set, 1, &dynamic_offset);

        // Timestamp region for pure GPU kernel duration (if query pool is available)
        if (timestamp_query_pool_ != VK_NULL_HANDLE) {
            const uint32_t q0 = i * 2;
            vkCmdResetQueryPool(static_ring_[i].cmd, timestamp_query_pool_, q0, 2);
            vkCmdWriteTimestamp(static_ring_[i].cmd, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, timestamp_query_pool_, q0);
        }

        // Dispatch
        uint32_t groups_z = 1;
        vkCmdDispatch(static_ring_[i].cmd, groups_x, groups_y, groups_z);

        if (timestamp_query_pool_ != VK_NULL_HANDLE) {
            const uint32_t q1 = i * 2 + 1;
            vkCmdWriteTimestamp(static_ring_[i].cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, timestamp_query_pool_, q1);
        }

        r = vkEndCommandBuffer(static_ring_[i].cmd);
        if (r != VK_SUCCESS) return false;
    }

    return true;
}

static uint64_t MixStaticLayerHash(uint64_t hash, uint64_t value) {
    hash ^= value + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2);
    return hash;
}

static uint64_t ComputeStaticLayerSignature(const StaticLayerDesc& desc) {
    uint64_t hash = 0xcbf29ce484222325ull;
    hash = MixStaticLayerHash(hash, desc.steps.size());
    hash = MixStaticLayerHash(hash, desc.barriers.size());
    for (const auto& step : desc.steps) {
        hash = MixStaticLayerHash(hash, step.kernel_id);
        hash = MixStaticLayerHash(hash, step.groups_x);
        hash = MixStaticLayerHash(hash, step.groups_y);
        hash = MixStaticLayerHash(hash, step.groups_z);
        hash = MixStaticLayerHash(hash, step.ubo_offset);
        hash = MixStaticLayerHash(hash, static_cast<uint64_t>(step.params_size));
    }
    for (const auto& barrier : desc.barriers) {
        hash = MixStaticLayerHash(hash, reinterpret_cast<uintptr_t>(barrier.buffer));
        hash = MixStaticLayerHash(hash, static_cast<uint64_t>(barrier.offset));
        hash = MixStaticLayerHash(hash, static_cast<uint64_t>(barrier.size));
        hash = MixStaticLayerHash(hash, barrier.src_stage_mask);
        hash = MixStaticLayerHash(hash, barrier.dst_stage_mask);
        hash = MixStaticLayerHash(hash, barrier.src_access_mask);
        hash = MixStaticLayerHash(hash, barrier.dst_access_mask);
    }
    return hash;
}

bool VulkanAccelerator::Impl::RecordStaticLayerCBs(const StaticLayerDesc& desc) {
    if (desc.steps.empty()) return false;
    if (desc.steps.size() > 1 && desc.barriers.size() != desc.steps.size() - 1) return false;

    const uint64_t signature = ComputeStaticLayerSignature(desc);

    if (static_layer_signature_ != 0 && static_layer_signature_ != signature) {
        vkDeviceWaitIdle(device_);
        if (!static_layer_descriptor_sets_.empty()) {
            vkFreeDescriptorSets(device_, descriptor_pool_, static_cast<uint32_t>(static_layer_descriptor_sets_.size()),
                                 static_layer_descriptor_sets_.data());
            static_layer_descriptor_sets_.clear();
        }
    }

    if (static_layer_descriptor_sets_.size() != desc.steps.size() || static_layer_signature_ != signature) {
        if (!static_layer_descriptor_sets_.empty()) {
            vkFreeDescriptorSets(device_, descriptor_pool_, static_cast<uint32_t>(static_layer_descriptor_sets_.size()),
                                 static_layer_descriptor_sets_.data());
            static_layer_descriptor_sets_.clear();
        }

        static_layer_descriptor_sets_.resize(desc.steps.size(), VK_NULL_HANDLE);
        for (size_t step_idx = 0; step_idx < desc.steps.size(); ++step_idx) {
            const auto& step = desc.steps[step_idx];
            uint32_t kslot = step.kernel_id - 1;
            if (step.kernel_id == 0 || kslot >= kMaxKernels || !kernel_pool_[kslot].occupied) return false;

            VkDescriptorSetAllocateInfo ds_alloc{};
            ds_alloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
            ds_alloc.descriptorPool = descriptor_pool_;
            ds_alloc.descriptorSetCount = 1;
            ds_alloc.pSetLayouts = &kernel_pool_[kslot].ds_layout;
            if (vkAllocateDescriptorSets(device_, &ds_alloc, &static_layer_descriptor_sets_[step_idx]) != VK_SUCCESS) {
                return false;
            }

            auto& k = kernel_pool_[kslot];
            if (!step.bindings.empty()) {
                std::vector<VkWriteDescriptorSet> writes;
                std::vector<VkDescriptorBufferInfo> infos;
                writes.reserve(step.bindings.size() + 1);
                infos.reserve(step.bindings.size() + 1);

                for (const auto& binding : step.bindings) {
                    if (!binding.tensor.IsValid()) return false;
                    uint32_t tensor_slot = binding.tensor.id - 1;
                    if (tensor_slot >= kMaxTensors) return false;
                    VkBuffer buffer = tensor_pool_[tensor_slot].buffer;
                    if (buffer == VK_NULL_HANDLE) return false;

                    infos.push_back({});
                    infos.back().buffer = buffer;
                    infos.back().offset = 0;
                    infos.back().range = VK_WHOLE_SIZE;

                    VkWriteDescriptorSet write{};
                    write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
                    write.dstSet = static_layer_descriptor_sets_[step_idx];
                    write.dstBinding = binding.binding;
                    write.descriptorCount = 1;
                    write.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
                    write.pBufferInfo = &infos.back();
                    writes.push_back(write);
                }

                VkDescriptorBufferInfo ubo_info{};
                ubo_info.buffer = ubo_buffer_;
                ubo_info.offset = 0;
                ubo_info.range = kUBOSlotSize;
                VkWriteDescriptorSet ubo_write{};
                ubo_write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
                ubo_write.dstSet = static_layer_descriptor_sets_[step_idx];
                ubo_write.dstBinding = k.binding_count;
                ubo_write.descriptorCount = 1;
                ubo_write.descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
                ubo_write.pBufferInfo = &ubo_info;
                writes.push_back(ubo_write);

                vkUpdateDescriptorSets(device_, static_cast<uint32_t>(writes.size()), writes.data(), 0, nullptr);
            }
        }
    }

    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = cmd_pool_;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = 1;

    for (uint32_t i = 0; i < kStaticRingSize; ++i) {
        if (static_ring_[i].cmd == VK_NULL_HANDLE) {
            if (vkAllocateCommandBuffers(device_, &alloc_info, &static_ring_[i].cmd) != VK_SUCCESS) {
                return false;
            }
        } else {
            vkResetCommandBuffer(static_ring_[i].cmd, 0);
        }

        if (static_ring_[i].fence == VK_NULL_HANDLE) {
            VkFenceCreateInfo fence_info{};
            fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
            if (vkCreateFence(device_, &fence_info, nullptr, &static_ring_[i].fence) != VK_SUCCESS) {
                return false;
            }
        }

        static_ring_[i].ready = true;
        static_ring_[i].kernel_id = desc.steps.front().kernel_id;

        VkCommandBufferBeginInfo begin_info{};
        begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin_info.flags = VK_COMMAND_BUFFER_USAGE_SIMULTANEOUS_USE_BIT;
        VkResult r = vkBeginCommandBuffer(static_ring_[i].cmd, &begin_info);
        if (r != VK_SUCCESS) return false;

        if (timestamp_query_pool_ != VK_NULL_HANDLE) {
            const uint32_t q0 = i * 2;
            vkCmdResetQueryPool(static_ring_[i].cmd, timestamp_query_pool_, q0, 2);
            vkCmdWriteTimestamp(static_ring_[i].cmd, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, timestamp_query_pool_, q0);
        }

        for (size_t step_idx = 0; step_idx < desc.steps.size(); ++step_idx) {
            const auto& step = desc.steps[step_idx];
            uint32_t kslot = step.kernel_id - 1;
            if (step.kernel_id == 0 || kslot >= kMaxKernels || !kernel_pool_[kslot].occupied) {
                return false;
            }
            auto& k = kernel_pool_[kslot];

            if (step.groups_x == 0 || step.groups_y == 0 || step.groups_z == 0) {
                return false;
            }

            if (step.params != nullptr && step.params_size > 0) {
                uint32_t base_offset = (i * kUBOSlotSize) + step.ubo_offset;
                if (step.ubo_offset >= kUBOSlotSize || step.params_size > kUBOSlotSize ||
                    (static_cast<uint64_t>(step.ubo_offset) + static_cast<uint64_t>(step.params_size)) > kUBOSlotSize) {
                    return false;
                }
                std::memcpy(static_cast<uint8_t*>(ubo_mapped_) + base_offset, step.params, step.params_size);
            }

            vkCmdBindPipeline(static_ring_[i].cmd, VK_PIPELINE_BIND_POINT_COMPUTE, k.pipeline);
            uint32_t dynamic_offset = i * kUBOSlotSize + step.ubo_offset;
            VkDescriptorSet step_set = static_layer_descriptor_sets_[step_idx];
            vkCmdBindDescriptorSets(static_ring_[i].cmd, VK_PIPELINE_BIND_POINT_COMPUTE, k.layout,
                                    0, 1, &step_set, 1, &dynamic_offset);
            vkCmdDispatch(static_ring_[i].cmd, step.groups_x, step.groups_y, step.groups_z);

            if (step_idx < desc.barriers.size()) {
                const auto& barrier_desc = desc.barriers[step_idx];
                if (barrier_desc.buffer != VK_NULL_HANDLE) {
                    VkBufferMemoryBarrier barrier{};
                    barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
                    barrier.srcAccessMask = barrier_desc.src_access_mask;
                    barrier.dstAccessMask = barrier_desc.dst_access_mask;
                    barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
                    barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
                    barrier.buffer = barrier_desc.buffer;
                    barrier.offset = barrier_desc.offset;
                    barrier.size = barrier_desc.size == 0 ? VK_WHOLE_SIZE : barrier_desc.size;
                    vkCmdPipelineBarrier(static_ring_[i].cmd,
                                         barrier_desc.src_stage_mask,
                                         barrier_desc.dst_stage_mask,
                                         0,
                                         0, nullptr,
                                         1, &barrier,
                                         0, nullptr);
                }
            }
        }

        if (timestamp_query_pool_ != VK_NULL_HANDLE) {
            const uint32_t q1 = i * 2 + 1;
            vkCmdWriteTimestamp(static_ring_[i].cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, timestamp_query_pool_, q1);
        }

        r = vkEndCommandBuffer(static_ring_[i].cmd);
        if (r != VK_SUCCESS) return false;
    }

    static_layer_signature_ = signature;
    static_kernel_id_ = 0;
    return true;
}

void VulkanAccelerator::Impl::CaptureLastStaticGpuDispatchNs() {
    if (timestamp_query_pool_ == VK_NULL_HANDLE || last_submitted_static_count_ == 0) {
        return;
    }

    uint64_t total_ticks = 0;
    for (uint32_t i = 0; i < last_submitted_static_count_; ++i) {
        const uint32_t slot = last_submitted_static_indices_[i] % kStaticRingSize;
        const uint32_t first_query = slot * 2;
        uint64_t ts[2] = {0, 0};
        VkResult qr = vkGetQueryPoolResults(
            device_,
            timestamp_query_pool_,
            first_query,
            2,
            sizeof(ts),
            ts,
            sizeof(uint64_t),
            VK_QUERY_RESULT_64_BIT | VK_QUERY_RESULT_WAIT_BIT);
        if (qr != VK_SUCCESS || ts[1] < ts[0]) {
            continue;
        }
        total_ticks += (ts[1] - ts[0]);
    }

    if (total_ticks == 0) {
        return;
    }

    last_gpu_dispatch_ns_ = static_cast<uint64_t>(static_cast<double>(total_ticks) * static_cast<double>(timestamp_period_ns_));
    stats_.last_dispatch_ns = last_gpu_dispatch_ns_;
    stats_.gpu_busy_ns += last_gpu_dispatch_ns_;
    last_submitted_static_count_ = 0;
}

bool VulkanAccelerator::Impl::PollTimeline(uint64_t target_value, uint64_t* out_current) {
    if (timeline_semaphore_ == VK_NULL_HANDLE) return false;
    uint64_t current = 0;
    VkResult r = vkGetSemaphoreCounterValue(device_, timeline_semaphore_, &current);
    if (r != VK_SUCCESS) return false;
    if (out_current) *out_current = current;
    return current >= target_value;
}

// ============================================================================
// VulkanAccelerator — Public API
// ============================================================================

VulkanAccelerator::VulkanAccelerator()
    : pImpl_(std::make_unique<Impl>()) {}

VulkanAccelerator::~VulkanAccelerator() {
    Shutdown();
}

bool VulkanAccelerator::Initialize() {
    // 1. Create Vulkan instance (minimal, no validation layers in production)
    VkApplicationInfo app_info{};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "RawrXD";
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "RawrXD-Sovereign";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo inst_info{};
    inst_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    inst_info.pApplicationInfo = &app_info;

    if (vkCreateInstance(&inst_info, nullptr, &pImpl_->instance_) != VK_SUCCESS)
        return false;

    // 2. Enumerate physical devices and pick first with compute
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(pImpl_->instance_, &device_count, nullptr);
    if (device_count == 0) return false;

    auto* devices = static_cast<VkPhysicalDevice*>(std::malloc(device_count * sizeof(VkPhysicalDevice)));
    vkEnumeratePhysicalDevices(pImpl_->instance_, &device_count, devices);
    pImpl_->physical_device_ = devices[0];   // TODO: score and select best
    std::free(devices);

    // Print largest device-local heap size for debugging
    VkPhysicalDeviceMemoryProperties mem_props{};
    vkGetPhysicalDeviceMemoryProperties(pImpl_->physical_device_, &mem_props);
    VkDeviceSize largest_heap = 0;
    for (uint32_t i = 0; i < mem_props.memoryHeapCount; ++i) {
        if (mem_props.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
            if (mem_props.memoryHeaps[i].size > largest_heap) {
                largest_heap = mem_props.memoryHeaps[i].size;
            }
        }
    }
    fprintf(stderr, "  [DEBUG] Largest device-local heap: %.2f GB\n", 
           static_cast<double>(largest_heap) / (1024.0*1024.0*1024.0));
    fflush(stderr);

    // Read timestamp period for GPU query-based duration metrics.
    VkPhysicalDeviceProperties props{};
    vkGetPhysicalDeviceProperties(pImpl_->physical_device_, &props);
    pImpl_->timestamp_period_ns_ = props.limits.timestampPeriod;
    pImpl_->compute_limits_.max_compute_work_group_count[0] = props.limits.maxComputeWorkGroupCount[0];
    pImpl_->compute_limits_.max_compute_work_group_count[1] = props.limits.maxComputeWorkGroupCount[1];
    pImpl_->compute_limits_.max_compute_work_group_count[2] = props.limits.maxComputeWorkGroupCount[2];
    pImpl_->compute_limits_.max_compute_work_group_invocations = props.limits.maxComputeWorkGroupInvocations;
    pImpl_->compute_limits_.max_compute_work_group_size[0] = props.limits.maxComputeWorkGroupSize[0];
    pImpl_->compute_limits_.max_compute_work_group_size[1] = props.limits.maxComputeWorkGroupSize[1];
    pImpl_->compute_limits_.max_compute_work_group_size[2] = props.limits.maxComputeWorkGroupSize[2];

    // 3. Create logical device with compute queue
    if (!pImpl_->FindComputeQueue()) return false;

    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info{};
    queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_info.queueFamilyIndex = pImpl_->queue_family_;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &queue_priority;

    VkDeviceCreateInfo dev_info{};
    dev_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dev_info.queueCreateInfoCount = 1;
    dev_info.pQueueCreateInfos = &queue_info;

    if (vkCreateDevice(pImpl_->physical_device_, &dev_info, nullptr, &pImpl_->device_) != VK_SUCCESS)
        return false;

    vkGetDeviceQueue(pImpl_->device_, pImpl_->queue_family_, 0, &pImpl_->queue_);

    // 4. Create command buffer and fence
    if (!pImpl_->CreateCommandBuffer()) return false;

    // 4b. Create sovereign hot-path infrastructure
    if (!pImpl_->CreateTimelineSemaphore()) {
        fprintf(stderr, "[WARN] Initialize: Timeline Semaphore creation failed. Falling back to fence sync.\n");
        // Non-fatal: we can still operate with fence fallback
    }
    if (!pImpl_->CreatePersistentCommandBuffer()) {
        fprintf(stderr, "[WARN] Initialize: Persistent CB ring creation failed.\n");
        return false;
    }

    // 4c. Optional timestamp query pool for pure GPU dispatch duration metrics
    VkQueryPoolCreateInfo qp_info{};
    qp_info.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
    qp_info.queryType = VK_QUERY_TYPE_TIMESTAMP;
    qp_info.queryCount = Impl::kStaticRingSize * 2;
    if (vkCreateQueryPool(pImpl_->device_, &qp_info, nullptr, &pImpl_->timestamp_query_pool_) != VK_SUCCESS) {
        pImpl_->timestamp_query_pool_ = VK_NULL_HANDLE;
        fprintf(stderr, "[WARN] Initialize: Timestamp query pool unavailable; GPU-duration metrics disabled.\n");
    }

    // 5. Resolve proc addresses for MASM shim
    pImpl_->ResolveProcAddresses();

    // Optional debug-only latency injector to validate upload wait telemetry.
    if (const char* inject_us_env = std::getenv("RAWRXD_UPLOAD_INJECT_US")) {
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(inject_us_env, &end, 10);
        if (end != inject_us_env && parsed > 0ULL) {
            const unsigned long long clamped = (parsed > 5000000ULL) ? 5000000ULL : parsed;
            pImpl_->upload_inject_us_ = static_cast<uint32_t>(clamped);
            fprintf(stderr, "[DEBUG] Upload injector enabled: %u us\n", pImpl_->upload_inject_us_);
            fflush(stderr);
        }
    }
    if (const char* ring_cap_env = std::getenv("RAWRXD_UPLOAD_RING_CAP")) {
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(ring_cap_env, &end, 10);
        if (end != ring_cap_env && parsed >= 2ULL) {
            const unsigned long long clamped = (parsed > static_cast<unsigned long long>(Impl::kUploadRingSize))
                ? static_cast<unsigned long long>(Impl::kUploadRingSize)
                : parsed;
            pImpl_->upload_ring_capacity_ = static_cast<uint32_t>(clamped);
            fprintf(stderr, "[DEBUG] Upload ring capacity override: %u\n", pImpl_->upload_ring_capacity_);
            fflush(stderr);
        }
    }
    if (const char* wait_inject_us_env = std::getenv("RAWRXD_UPLOAD_WAIT_INJECT_US")) {
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(wait_inject_us_env, &end, 10);
        if (end != wait_inject_us_env && parsed > 0ULL) {
            const unsigned long long clamped = (parsed > 5000000ULL) ? 5000000ULL : parsed;
            pImpl_->upload_wait_inject_us_ = static_cast<uint32_t>(clamped);
            fprintf(stderr, "[DEBUG] Upload wait injector enabled: %u us\n", pImpl_->upload_wait_inject_us_);
            fflush(stderr);
        }
    }
    if (const char* force_burst_env = std::getenv("RAWRXD_UPLOAD_FORCE_BURST")) {
        if (std::strcmp(force_burst_env, "0") != 0) {
            pImpl_->upload_force_burst_ = true;
            fprintf(stderr, "[DEBUG] Upload force-burst mode enabled\n");
            fflush(stderr);
        }
    }
    if (const char* burst_margin_env = std::getenv("RAWRXD_UPLOAD_BURST_MARGIN")) {
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(burst_margin_env, &end, 10);
        if (end != burst_margin_env && parsed > 0ULL) {
            const unsigned long long max_margin =
                (pImpl_->upload_ring_capacity_ > 1U) ? static_cast<unsigned long long>(pImpl_->upload_ring_capacity_ - 1U) : 1ULL;
            const unsigned long long clamped = (parsed > max_margin) ? max_margin : parsed;
            pImpl_->upload_nearly_full_margin_ = static_cast<uint32_t>(clamped);
            fprintf(stderr, "[DEBUG] Upload burst near-full margin: %u\n", pImpl_->upload_nearly_full_margin_);
            fflush(stderr);
        }
    }

    return true;
}

bool VulkanAccelerator::IsReady() const {
    return pImpl_->device_ != VK_NULL_HANDLE;
}

ComputeLimits VulkanAccelerator::GetComputeLimits() const {
    if (!pImpl_) {
        return {};
    }
    return pImpl_->compute_limits_;
}

GpuTensorHandle VulkanAccelerator::UploadTensor(const TensorDesc& desc, bool /*keep_host_copy*/) {
    const bool trace_upload = (std::getenv("RAWRXD_UPLOAD_TRACE") != nullptr);
    if (trace_upload) {
        fprintf(stderr, "  [DEBUG] UploadTensor called: size=%zu, name=%s\n", desc.size_bytes, desc.name.c_str());
    }
    GpuTensorHandle h{};
    if (!IsReady() || desc.size_bytes == 0) {
        if (trace_upload) {
            fprintf(stderr, "  [WARN] UploadTensor early return: not ready or zero size\n");
        }
        return h;
    }

    // Find free slot
    uint32_t id = 0;
    for (uint32_t i = 0; i < Impl::kMaxTensors; ++i) {
        if (!pImpl_->tensor_pool_[i].occupied) {
            id = pImpl_->next_tensor_id_++;
            if (id == 0) id = pImpl_->next_tensor_id_++; // skip invalid 0
            pImpl_->tensor_pool_[i].occupied = true;
            break;
        }
    }
    if (id == 0) return h; // pool full

    // Create device-local buffer
    VkBufferCreateInfo buf_info{};
    buf_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buf_info.size = desc.size_bytes;
    buf_info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    buf_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer buffer = VK_NULL_HANDLE;
    if (vkCreateBuffer(pImpl_->device_, &buf_info, nullptr, &buffer) != VK_SUCCESS) {
        fprintf(stderr, "  [WARN] vkCreateBuffer failed for size %zu\n", desc.size_bytes);
        return h;
    }

    VkMemoryRequirements mem_req{};
    vkGetBufferMemoryRequirements(pImpl_->device_, buffer, &mem_req);

    VkPhysicalDeviceMemoryProperties mem_props{};
    vkGetPhysicalDeviceMemoryProperties(pImpl_->physical_device_, &mem_props);

    uint32_t mem_type_idx = UINT32_MAX;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((mem_req.memoryTypeBits & (1u << i)) &&
            (mem_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
            mem_type_idx = i;
            break;
        }
    }
    if (mem_type_idx == UINT32_MAX) {
        fprintf(stderr, "  [WARN] Failed to find memory type for buffer size %zu, memoryTypeBits=0x%lx\n",
                desc.size_bytes, mem_req.memoryTypeBits);
        for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
            fprintf(stderr, "    memType[%u]: propertyFlags=0x%lx, heapIndex=%u\n",
                    i, mem_props.memoryTypes[i].propertyFlags, mem_props.memoryTypes[i].heapIndex);
        }
        vkDestroyBuffer(pImpl_->device_, buffer, nullptr);
        return h;
    }

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_req.size;
    alloc_info.memoryTypeIndex = mem_type_idx;

    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkResult alloc_result = vkAllocateMemory(pImpl_->device_, &alloc_info, nullptr, &memory);
    if (alloc_result != VK_SUCCESS) {
        fprintf(stderr, "  [WARN] vkAllocateMemory failed for size %zu, memoryTypeIndex=%u, error=%d\n",
                desc.size_bytes, alloc_info.memoryTypeIndex, alloc_result);
        vkDestroyBuffer(pImpl_->device_, buffer, nullptr);
        return h;
    }

    vkBindBufferMemory(pImpl_->device_, buffer, memory, 0);

    uint32_t submitted_upload_slot = UINT32_MAX;
    uint64_t submitted_upload_seq = 0;
    bool submitted_upload = false;

    // Upload via staging buffer
    if (desc.host_ptr) {
        if (!pImpl_->CreateUploadRing()) {
            vkFreeMemory(pImpl_->device_, memory, nullptr);
            vkDestroyBuffer(pImpl_->device_, buffer, nullptr);
            return h;
        }

        // Try to free completed slots first; if ring is still full, block until one finishes.
        pImpl_->FlushUploadRing(false);
        uint64_t slot_idx_u64 = RawrXD_DMA_AcquireFill_Asm();
        while (slot_idx_u64 == static_cast<uint64_t>(-1)) {
            if (pImpl_->upload_force_burst_) {
                uint64_t margin = pImpl_->upload_nearly_full_margin_;
                if (margin == 0 || margin >= pImpl_->upload_ring_capacity_) {
                    margin = (pImpl_->upload_ring_capacity_ > 1U) ? (pImpl_->upload_ring_capacity_ - 1U) : 1U;
                }
                if (RawrXD_DMA_IsNearlyFull_Asm(margin) != 0) {
                    // Force-burst mode intentionally avoids blocking to flood producer pressure.
                    const uint64_t full_now = RawrXD_DMA_GetFullCount_Asm();
                    if (full_now >= pImpl_->upload_full_last_count_) {
                        pImpl_->stats_.upload_ring_full_count += (full_now - pImpl_->upload_full_last_count_);
                    }
                    pImpl_->upload_full_last_count_ = full_now;
                    vkFreeMemory(pImpl_->device_, memory, nullptr);
                    vkDestroyBuffer(pImpl_->device_, buffer, nullptr);
                    return h;
                }
            }
            if (pImpl_->upload_inject_us_ > 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(pImpl_->upload_inject_us_));
            }
            if (!pImpl_->FlushUploadRing(true)) {
                vkFreeMemory(pImpl_->device_, memory, nullptr);
                vkDestroyBuffer(pImpl_->device_, buffer, nullptr);
                return h;
            }
            slot_idx_u64 = RawrXD_DMA_AcquireFill_Asm();
        }

        const uint64_t full_now = RawrXD_DMA_GetFullCount_Asm();
        if (full_now >= pImpl_->upload_full_last_count_) {
            pImpl_->stats_.upload_ring_full_count += (full_now - pImpl_->upload_full_last_count_);
        }
        pImpl_->upload_full_last_count_ = full_now;

        const uint32_t slot_idx = static_cast<uint32_t>(slot_idx_u64 % pImpl_->upload_ring_capacity_);
        auto& up_slot = pImpl_->upload_ring_[slot_idx];

        if (!pImpl_->EnsureUploadSlotStaging(slot_idx, desc.size_bytes)) {
            vkFreeMemory(pImpl_->device_, memory, nullptr);
            vkDestroyBuffer(pImpl_->device_, buffer, nullptr);
            return h;
        }

        std::memcpy(up_slot.staging_mapped, desc.host_ptr, desc.size_bytes);

        if (desc.expected_crc32 != 0) {
            const uint32_t crc = RawrXD_ValidateBufferCRC32_Asm(up_slot.staging_mapped,
                                                                static_cast<uint64_t>(desc.size_bytes),
                                                                0u);
            if (crc != desc.expected_crc32) {
                fprintf(stderr,
                        "[WARN] UploadTensor CRC mismatch for '%s': got=0x%08X expected=0x%08X\n",
                        desc.name.c_str(),
                        crc,
                        desc.expected_crc32);
                vkFreeMemory(pImpl_->device_, memory, nullptr);
                vkDestroyBuffer(pImpl_->device_, buffer, nullptr);
                return h;
            }
        }

        // Record copy command
        VkCommandBufferBeginInfo begin_info{};
        begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(up_slot.cmd, &begin_info);

        VkBufferCopy copy_region{};
        copy_region.size = desc.size_bytes;
        vkCmdCopyBuffer(up_slot.cmd, up_slot.staging_buffer, buffer, 1, &copy_region);

        vkEndCommandBuffer(up_slot.cmd);

        VkSubmitInfo submit_info{};
        submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit_info.commandBufferCount = 1;
        submit_info.pCommandBuffers = &up_slot.cmd;
        vkQueueSubmit(pImpl_->queue_, 1, &submit_info, up_slot.fence);
        up_slot.in_flight = true;
        up_slot.submit_seq = ++pImpl_->upload_submit_seq_;
        submitted_upload_slot = slot_idx;
        submitted_upload_seq = up_slot.submit_seq;
        submitted_upload = true;
        pImpl_->stats_.upload_submit_count++;
        std::atomic_thread_fence(std::memory_order_release);
        RawrXD_DMA_Commit_Asm();
    }

    // Store in pool
    uint32_t slot_idx = id - 1; // simple mapping
    if (slot_idx < Impl::kMaxTensors) {
        pImpl_->tensor_pool_[slot_idx].buffer = buffer;
        pImpl_->tensor_pool_[slot_idx].memory = memory;
        pImpl_->tensor_pool_[slot_idx].size_bytes = desc.size_bytes;
        pImpl_->tensor_pool_[slot_idx].occupied = true;
        pImpl_->tensor_pool_[slot_idx].upload_pending = submitted_upload;
        pImpl_->tensor_pool_[slot_idx].upload_slot_idx = submitted_upload ? submitted_upload_slot : UINT32_MAX;
        pImpl_->tensor_pool_[slot_idx].upload_seq = submitted_upload ? submitted_upload_seq : 0;
    }

    h.id = id;
    h.buffer = reinterpret_cast<VkBuffer_T*>(buffer);
    h.memory = reinterpret_cast<VkDeviceMemory_T*>(memory);
    h.size_bytes = desc.size_bytes;

    pImpl_->stats_.tensors_uploaded++;
    pImpl_->stats_.bytes_uploaded += desc.size_bytes;
    return h;
}

void VulkanAccelerator::ReleaseTensor(GpuTensorHandle handle) {
    if (!handle.IsValid()) return;
    uint32_t slot = handle.id - 1;
    if (slot >= Impl::kMaxTensors) return;

    auto& s = pImpl_->tensor_pool_[slot];
    if (s.buffer != VK_NULL_HANDLE)
        vkDestroyBuffer(pImpl_->device_, s.buffer, nullptr);
    if (s.memory != VK_NULL_HANDLE)
        vkFreeMemory(pImpl_->device_, s.memory, nullptr);
    s = {};
}

void VulkanAccelerator::ReleaseAllTensors() {
    for (uint32_t i = 0; i < Impl::kMaxTensors; ++i) {
        if (pImpl_->tensor_pool_[i].occupied) {
            GpuTensorHandle h;
            h.id = i + 1;
            ReleaseTensor(h);
        }
    }
}

bool VulkanAccelerator::GetMemoryStats(size_t& total_bytes, size_t& free_bytes) const {
    if (!IsReady()) return false;
    VkPhysicalDeviceMemoryProperties mem_props{};
    vkGetPhysicalDeviceMemoryProperties(pImpl_->physical_device_, &mem_props);

    // Sum device-local heaps for total memory
    total_bytes = 0;
    for (uint32_t i = 0; i < mem_props.memoryHeapCount; ++i) {
        if (mem_props.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
            total_bytes += mem_props.memoryHeaps[i].size;
        }
    }

    // Calculate used memory from tensor pool
    size_t used_bytes = 0;
    for (uint32_t i = 0; i < Impl::kMaxTensors; ++i) {
        if (pImpl_->tensor_pool_[i].occupied) {
            used_bytes += pImpl_->tensor_pool_[i].size_bytes;
        }
    }

    // Free memory is total minus used
    if (used_bytes > total_bytes) {
        // This should not happen, but clamp to avoid underflow
        free_bytes = 0;
    } else {
        free_bytes = total_bytes - used_bytes;
    }
    return true;
}

bool VulkanAccelerator::DispatchMatMul(const MatMulDesc& desc,
                                         VkSemaphore /*signal_semaphore*/,
                                         uint64_t /*signal_value*/) {
    if (!IsReady() || !desc.A.IsValid() || !desc.B.IsValid() || !desc.Out.IsValid())
        return false;

    const GpuTensorHandle dependencies[] = {desc.A, desc.B, desc.Out};
    if (!pImpl_->WaitForTensorUploads(dependencies, sizeof(dependencies) / sizeof(dependencies[0]))) {
        return false;
    }

    // Call the MASM hot-path shim
    int result = RawrXD_DispatchMatMul_Asm(this, static_cast<const void*>(&desc));
    pImpl_->stats_.matmul_dispatched++;
    return result == 0;
}

bool VulkanAccelerator::DispatchMatMulBatch(const std::vector<MatMulDesc>& descs) {
    if (!IsReady() || descs.empty()) return false;

    // For scaffolding: submit each individually. Future: record into single cmd buffer.
    for (const auto& d : descs) {
        if (!DispatchMatMul(d)) return false;
    }
    return true;
}

bool VulkanAccelerator::DispatchKVAppend(const KVAppendDesc& desc) {
    if (!IsReady()) return false;

    const GpuTensorHandle dependencies[] = {desc.K_cache, desc.V_cache, desc.K_new, desc.V_new};
    if (!pImpl_->WaitForTensorUploads(dependencies, sizeof(dependencies) / sizeof(dependencies[0]))) {
        return false;
    }

    int result = RawrXD_KVAppend_Asm(this, static_cast<const void*>(&desc));
    pImpl_->stats_.kv_appends_dispatched++;
    return result == 0;
}

bool VulkanAccelerator::DispatchKVAppendPrefill(const std::vector<KVAppendDesc>& descs) {
    if (!IsReady() || descs.empty()) return false;
    for (const auto& d : descs) {
        if (!DispatchKVAppend(d)) return false;
    }
    return true;
}

uint32_t VulkanAccelerator::LoadKernel(const char* name, const char* spv_path, uint32_t binding_count) {
    if (!IsReady() || name == nullptr || spv_path == nullptr || binding_count == 0) return 0;

    // Read SPIR-V file
    FILE* f = nullptr;
    if (fopen_s(&f, spv_path, "rb") != 0 || f == nullptr) {
        fprintf(stderr, "[WARN] LoadKernel: failed to open %s\n", spv_path);
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long spv_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (spv_size <= 0) {
        fclose(f);
        return 0;
    }
    void* spv_data = std::malloc(spv_size);
    if (!spv_data || fread(spv_data, 1, spv_size, f) != static_cast<size_t>(spv_size)) {
        std::free(spv_data);
        fclose(f);
        return 0;
    }
    fclose(f);

    // Find free kernel slot
    uint32_t id = 0;
    for (uint32_t i = 0; i < Impl::kMaxKernels; ++i) {
        if (!pImpl_->kernel_pool_[i].occupied) {
            id = pImpl_->next_kernel_id_++;
            if (id == 0) id = pImpl_->next_kernel_id_++;
            break;
        }
    }
    if (id == 0) {
        std::free(spv_data);
        return 0; // pool full
    }

    uint32_t slot = id - 1;
    bool ok = pImpl_->CreateKernelPipeline(slot, spv_data, spv_size, binding_count);

    if (ok) {
        auto& slot_ref = pImpl_->kernel_pool_[slot];
        strncpy_s(slot_ref.name, sizeof(slot_ref.name), name, _TRUNCATE);
        fprintf(stderr, "[DEBUG] LoadKernel: loaded '%s' id=%u bindings=%u\n", name, id, binding_count);
        return id;
    }
    return 0;
}

uint32_t VulkanAccelerator::LoadKernelFromMemory(const char* name, const void* spv_data, size_t spv_size, uint32_t binding_count) {
    if (!IsReady() || name == nullptr || spv_data == nullptr || spv_size == 0 || binding_count == 0) return 0;

    // Find free kernel slot
    uint32_t id = 0;
    for (uint32_t i = 0; i < Impl::kMaxKernels; ++i) {
        if (!pImpl_->kernel_pool_[i].occupied) {
            id = pImpl_->next_kernel_id_++;
            if (id == 0) id = pImpl_->next_kernel_id_++;
            break;
        }
    }
    if (id == 0) return 0; // pool full

    uint32_t slot = id - 1;
    bool ok = pImpl_->CreateKernelPipeline(slot, spv_data, spv_size, binding_count);

    if (ok) {
        auto& slot_ref = pImpl_->kernel_pool_[slot];
        strncpy_s(slot_ref.name, sizeof(slot_ref.name), name, _TRUNCATE);
        return id;
    }
    return 0;
}

bool VulkanAccelerator::DispatchRMSNorm(const RMSNormDesc& desc, uint32_t kernel_id) {
    if (!IsReady() || kernel_id == 0) return false;
    const GpuTensorHandle dependencies[] = {desc.input, desc.output, desc.weight};
    if (!pImpl_->WaitForTensorUploads(dependencies, sizeof(dependencies) / sizeof(dependencies[0]))) {
        return false;
    }
    uint32_t kslot = kernel_id - 1;
    if (kslot >= Impl::kMaxKernels || !pImpl_->kernel_pool_[kslot].occupied) return false;
    auto& k = pImpl_->kernel_pool_[kslot];

    // Resolve tensor buffers
    uint32_t in_slot  = desc.input.id - 1;
    uint32_t out_slot = desc.output.id - 1;
    uint32_t w_slot   = desc.weight.id - 1;
    if (in_slot >= Impl::kMaxTensors || out_slot >= Impl::kMaxTensors || w_slot >= Impl::kMaxTensors)
        return false;

    VkBuffer in_buf  = pImpl_->tensor_pool_[in_slot].buffer;
    VkBuffer out_buf = pImpl_->tensor_pool_[out_slot].buffer;
    VkBuffer w_buf   = pImpl_->tensor_pool_[w_slot].buffer;
    if (in_buf == VK_NULL_HANDLE || out_buf == VK_NULL_HANDLE || w_buf == VK_NULL_HANDLE)
        return false;

    // ------------------------------------------------------------------------
    // SOVEREIGN STATIC PIPELINE: One-time init, zero-recording hot path
    // ------------------------------------------------------------------------
    // On first dispatch: create UBO buffer + pre-record 16 static CBs
    // On every dispatch: memcpy(params) -> submit pre-recorded CB
    // Zero vkResetCommandBuffer, vkBeginCommandBuffer, vkEndCommandBuffer
    // ------------------------------------------------------------------------
    if (pImpl_->ubo_buffer_ == VK_NULL_HANDLE || pImpl_->static_kernel_id_ != kernel_id) {
        // If switching kernels, destroy old static ring first
        if (pImpl_->ubo_buffer_ != VK_NULL_HANDLE && pImpl_->static_kernel_id_ != kernel_id) {
            for (uint32_t i = 0; i < Impl::kStaticRingSize; ++i) {
                if (pImpl_->static_ring_[i].fence != VK_NULL_HANDLE) {
                    vkDestroyFence(pImpl_->device_, pImpl_->static_ring_[i].fence, nullptr);
                    pImpl_->static_ring_[i].fence = VK_NULL_HANDLE;
                }
                // CBs are freed when cmd_pool_ is destroyed; we just zero the handles
                pImpl_->static_ring_[i].cmd = VK_NULL_HANDLE;
                pImpl_->static_ring_[i].ready = true;
            }
            pImpl_->static_ring_head_ = 0;
        }
        if (pImpl_->ubo_buffer_ == VK_NULL_HANDLE) {
            if (!pImpl_->CreateUBOBuffer()) {
                fprintf(stderr, "[WARN] DispatchRMSNorm: UBO buffer creation failed\n");
                return false;
            }
        }
        if (!pImpl_->RecordStaticCBs(kernel_id, desc.num_rows, 1)) {
            fprintf(stderr, "[WARN] DispatchRMSNorm: Static CB recording failed\n");
            return false;
        }
        pImpl_->static_kernel_id_ = kernel_id;
        pImpl_->static_layer_signature_ = 0;
        fprintf(stderr, "[DEBUG] Static Pipeline: UBO + 16 pre-recorded CBs ready for kernel %u\n", kernel_id);
    }

    // Bind descriptors on first dispatch for this kernel
    if (!k.descriptors_bound) {
        VkWriteDescriptorSet writes[4] = {};
        VkDescriptorBufferInfo buf_infos[4] = {};

        buf_infos[0].buffer = in_buf;  buf_infos[0].offset = 0;  buf_infos[0].range = VK_WHOLE_SIZE;
        writes[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[0].dstSet = k.descriptor_set;
        writes[0].dstBinding = 0;
        writes[0].descriptorCount = 1;
        writes[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[0].pBufferInfo = &buf_infos[0];

        buf_infos[1].buffer = out_buf; buf_infos[1].offset = 0;  buf_infos[1].range = VK_WHOLE_SIZE;
        writes[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[1].dstSet = k.descriptor_set;
        writes[1].dstBinding = 1;
        writes[1].descriptorCount = 1;
        writes[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[1].pBufferInfo = &buf_infos[1];

        buf_infos[2].buffer = w_buf;   buf_infos[2].offset = 0;  buf_infos[2].range = VK_WHOLE_SIZE;
        writes[2].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[2].dstSet = k.descriptor_set;
        writes[2].dstBinding = 2;
        writes[2].descriptorCount = 1;
        writes[2].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[2].pBufferInfo = &buf_infos[2];

        buf_infos[3].buffer = pImpl_->ubo_buffer_;
        buf_infos[3].offset = 0;
        buf_infos[3].range = Impl::kUBOSlotSize;
        writes[3].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[3].dstSet = k.descriptor_set;
        writes[3].dstBinding = 3;
        writes[3].descriptorCount = 1;
        writes[3].descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
        writes[3].pBufferInfo = &buf_infos[3];

        vkUpdateDescriptorSets(pImpl_->device_, 4, writes, 0, nullptr);
        k.descriptors_bound = true;
    }

    // Rotate to next static ring slot
    uint32_t ring_idx = pImpl_->static_ring_head_;
    pImpl_->static_ring_head_ = (pImpl_->static_ring_head_ + 1) % Impl::kStaticRingSize;
    auto& slot = pImpl_->static_ring_[ring_idx];

    // Wait for slot availability (non-blocking poll first)
    if (!slot.ready) {
        VkResult r = vkWaitForFences(pImpl_->device_, 1, &slot.fence, VK_TRUE, 0);
        if (r != VK_SUCCESS) {
            vkWaitForFences(pImpl_->device_, 1, &slot.fence, VK_TRUE, UINT64_MAX);
        }
        vkResetFences(pImpl_->device_, 1, &slot.fence);
        slot.ready = true;
    }

    // ------------------------------------------------------------------------
    // HOT PATH: Write params into mapped UBO (zero driver calls)
    // ------------------------------------------------------------------------
    // Params layout (std140, 256 bytes per slot):
    //   offset 0x00: uint32_t hidden_size
    //   offset 0x04: float eps
    //   offset 0x08: uint32_t layer_idx
    //   offset 0x0C: uint32_t seq_pos
    //   offset 0x10-0xFC: reserved (zero)
    // ------------------------------------------------------------------------
    uint8_t* ubo_slot = static_cast<uint8_t*>(pImpl_->ubo_mapped_) + (ring_idx * Impl::kUBOSlotSize);
    std::memset(ubo_slot, 0, Impl::kUBOSlotSize);
    *reinterpret_cast<uint32_t*>(ubo_slot + 0x00) = desc.hidden_size;
    *reinterpret_cast<float*>(ubo_slot + 0x04) = desc.eps;
    *reinterpret_cast<uint32_t*>(ubo_slot + 0x08) = 0; // layer_idx
    *reinterpret_cast<uint32_t*>(ubo_slot + 0x0C) = 0; // seq_pos

    // ------------------------------------------------------------------------
    // HOT PATH: Submit pre-recorded command buffer (ONE Vulkan call)
    // ------------------------------------------------------------------------
    pImpl_->timeline_value_++;
    uint64_t signal_value = pImpl_->timeline_value_;

    VkTimelineSemaphoreSubmitInfo timeline_info{};
    timeline_info.sType = VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO;
    timeline_info.signalSemaphoreValueCount = 1;
    timeline_info.pSignalSemaphoreValues = &signal_value;

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.pNext = &timeline_info;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &slot.cmd;
    submit_info.signalSemaphoreCount = 1;
    submit_info.pSignalSemaphores = &pImpl_->timeline_semaphore_;

    VkResult r = vkQueueSubmit(pImpl_->queue_, 1, &submit_info, slot.fence);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "[WARN] DispatchRMSNorm: vkQueueSubmit failed: %d\n", r);
        return false;
    }
    pImpl_->last_submit_cpu_ns_ = NowSteadyNs();
    slot.ready = false;
    pImpl_->last_submitted_static_indices_[0] = ring_idx;
    pImpl_->last_submitted_static_count_ = 1;

    pImpl_->stats_.matmul_dispatched++;
    return true;
}

bool VulkanAccelerator::DispatchRMSNormBurst(const RMSNormDesc& desc, uint32_t kernel_id, uint32_t dispatch_count) {
    pImpl_->FlushUploadRing(true);
    if (dispatch_count == 0) return true;
    if (dispatch_count == 1) return DispatchRMSNorm(desc, kernel_id);

    if (!IsReady() || kernel_id == 0) return false;
    if (dispatch_count > Impl::kStaticRingSize) {
        dispatch_count = Impl::kStaticRingSize;
    }

    uint32_t kslot = kernel_id - 1;
    if (kslot >= Impl::kMaxKernels || !pImpl_->kernel_pool_[kslot].occupied) return false;
    auto& k = pImpl_->kernel_pool_[kslot];

    uint32_t in_slot  = desc.input.id - 1;
    uint32_t out_slot = desc.output.id - 1;
    uint32_t w_slot   = desc.weight.id - 1;
    if (in_slot >= Impl::kMaxTensors || out_slot >= Impl::kMaxTensors || w_slot >= Impl::kMaxTensors)
        return false;

    VkBuffer in_buf  = pImpl_->tensor_pool_[in_slot].buffer;
    VkBuffer out_buf = pImpl_->tensor_pool_[out_slot].buffer;
    VkBuffer w_buf   = pImpl_->tensor_pool_[w_slot].buffer;
    if (in_buf == VK_NULL_HANDLE || out_buf == VK_NULL_HANDLE || w_buf == VK_NULL_HANDLE)
        return false;

    if (pImpl_->ubo_buffer_ == VK_NULL_HANDLE || pImpl_->static_kernel_id_ != kernel_id) {
        if (pImpl_->ubo_buffer_ != VK_NULL_HANDLE && pImpl_->static_kernel_id_ != kernel_id) {
            for (uint32_t i = 0; i < Impl::kStaticRingSize; ++i) {
                if (pImpl_->static_ring_[i].fence != VK_NULL_HANDLE) {
                    vkDestroyFence(pImpl_->device_, pImpl_->static_ring_[i].fence, nullptr);
                    pImpl_->static_ring_[i].fence = VK_NULL_HANDLE;
                }
                pImpl_->static_ring_[i].cmd = VK_NULL_HANDLE;
                pImpl_->static_ring_[i].ready = true;
            }
            pImpl_->static_ring_head_ = 0;
        }
        if (pImpl_->ubo_buffer_ == VK_NULL_HANDLE) {
            if (!pImpl_->CreateUBOBuffer()) {
                fprintf(stderr, "[WARN] DispatchRMSNormBurst: UBO buffer creation failed\n");
                return false;
            }
        }
        if (!pImpl_->RecordStaticCBs(kernel_id, desc.num_rows, 1)) {
            fprintf(stderr, "[WARN] DispatchRMSNormBurst: Static CB recording failed\n");
            return false;
        }
        pImpl_->static_kernel_id_ = kernel_id;
        pImpl_->static_layer_signature_ = 0;
        fprintf(stderr, "[DEBUG] Static Pipeline: UBO + 16 pre-recorded CBs ready for kernel %u\n", kernel_id);
    }

    if (!k.descriptors_bound) {
        VkWriteDescriptorSet writes[4] = {};
        VkDescriptorBufferInfo buf_infos[4] = {};

        buf_infos[0].buffer = in_buf;  buf_infos[0].offset = 0;  buf_infos[0].range = VK_WHOLE_SIZE;
        writes[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[0].dstSet = k.descriptor_set;
        writes[0].dstBinding = 0;
        writes[0].descriptorCount = 1;
        writes[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[0].pBufferInfo = &buf_infos[0];

        buf_infos[1].buffer = out_buf; buf_infos[1].offset = 0;  buf_infos[1].range = VK_WHOLE_SIZE;
        writes[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[1].dstSet = k.descriptor_set;
        writes[1].dstBinding = 1;
        writes[1].descriptorCount = 1;
        writes[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[1].pBufferInfo = &buf_infos[1];

        buf_infos[2].buffer = w_buf;   buf_infos[2].offset = 0;  buf_infos[2].range = VK_WHOLE_SIZE;
        writes[2].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[2].dstSet = k.descriptor_set;
        writes[2].dstBinding = 2;
        writes[2].descriptorCount = 1;
        writes[2].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[2].pBufferInfo = &buf_infos[2];

        buf_infos[3].buffer = pImpl_->ubo_buffer_;
        buf_infos[3].offset = 0;
        buf_infos[3].range = Impl::kUBOSlotSize;
        writes[3].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[3].dstSet = k.descriptor_set;
        writes[3].dstBinding = 3;
        writes[3].descriptorCount = 1;
        writes[3].descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
        writes[3].pBufferInfo = &buf_infos[3];

        vkUpdateDescriptorSets(pImpl_->device_, 4, writes, 0, nullptr);
        k.descriptors_bound = true;
    }

    VkCommandBuffer cmd_list[Impl::kStaticRingSize] = {};
    for (uint32_t i = 0; i < dispatch_count; ++i) {
        uint32_t ring_idx = pImpl_->static_ring_head_;
        pImpl_->static_ring_head_ = (pImpl_->static_ring_head_ + 1) % Impl::kStaticRingSize;
        auto& slot = pImpl_->static_ring_[ring_idx];

        if (!slot.ready) {
            VkResult r = vkWaitForFences(pImpl_->device_, 1, &slot.fence, VK_TRUE, 0);
            if (r != VK_SUCCESS) {
                vkWaitForFences(pImpl_->device_, 1, &slot.fence, VK_TRUE, UINT64_MAX);
            }
            vkResetFences(pImpl_->device_, 1, &slot.fence);
            slot.ready = true;
        }

        uint8_t* ubo_slot = static_cast<uint8_t*>(pImpl_->ubo_mapped_) + (ring_idx * Impl::kUBOSlotSize);
        std::memset(ubo_slot, 0, Impl::kUBOSlotSize);
        *reinterpret_cast<uint32_t*>(ubo_slot + 0x00) = desc.hidden_size;
        *reinterpret_cast<float*>(ubo_slot + 0x04) = desc.eps;
        *reinterpret_cast<uint32_t*>(ubo_slot + 0x08) = 0;
        *reinterpret_cast<uint32_t*>(ubo_slot + 0x0C) = 0;

        cmd_list[i] = slot.cmd;
        pImpl_->last_submitted_static_indices_[i] = ring_idx;
    }

    pImpl_->timeline_value_++;
    uint64_t signal_value = pImpl_->timeline_value_;

    VkTimelineSemaphoreSubmitInfo timeline_info{};
    timeline_info.sType = VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO;
    timeline_info.signalSemaphoreValueCount = 1;
    timeline_info.pSignalSemaphoreValues = &signal_value;

    uint32_t fence_slot = pImpl_->last_submitted_static_indices_[dispatch_count - 1] % Impl::kStaticRingSize;
    auto& submit_fence_slot = pImpl_->static_ring_[fence_slot];

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.pNext = &timeline_info;
    submit_info.commandBufferCount = dispatch_count;
    submit_info.pCommandBuffers = cmd_list;
    submit_info.signalSemaphoreCount = 1;
    submit_info.pSignalSemaphores = &pImpl_->timeline_semaphore_;

    VkResult r = vkQueueSubmit(pImpl_->queue_, 1, &submit_info, submit_fence_slot.fence);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "[WARN] DispatchRMSNormBurst: vkQueueSubmit failed: %d\n", r);
        return false;
    }
    pImpl_->last_submit_cpu_ns_ = NowSteadyNs();

    for (uint32_t i = 0; i < dispatch_count; ++i) {
        uint32_t slot_idx = pImpl_->last_submitted_static_indices_[i] % Impl::kStaticRingSize;
        pImpl_->static_ring_[slot_idx].ready = false;
    }
    pImpl_->last_submitted_static_count_ = dispatch_count;

    pImpl_->stats_.matmul_dispatched += dispatch_count;
    return true;
}

bool VulkanAccelerator::DispatchFusedRMSNormMatMul(const FusedRMSNormMatMulDesc& desc, uint32_t kernel_id) {
    if (!IsReady() || kernel_id == 0) return false;
    const GpuTensorHandle dependencies[] = {desc.input, desc.output, desc.rmsnorm_weight, desc.matmul_weight};
    if (!pImpl_->WaitForTensorUploads(dependencies, sizeof(dependencies) / sizeof(dependencies[0]))) {
        return false;
    }
    uint32_t kslot = kernel_id - 1;
    if (kslot >= Impl::kMaxKernels || !pImpl_->kernel_pool_[kslot].occupied) return false;
    auto& k = pImpl_->kernel_pool_[kslot];

    // Resolve tensor buffers
    uint32_t in_slot  = desc.input.id - 1;
    uint32_t out_slot = desc.output.id - 1;
    uint32_t gamma_slot = desc.rmsnorm_weight.id - 1;
    uint32_t w_slot   = desc.matmul_weight.id - 1;
    if (in_slot >= Impl::kMaxTensors || out_slot >= Impl::kMaxTensors ||
        gamma_slot >= Impl::kMaxTensors || w_slot >= Impl::kMaxTensors)
        return false;

    VkBuffer in_buf  = pImpl_->tensor_pool_[in_slot].buffer;
    VkBuffer out_buf = pImpl_->tensor_pool_[out_slot].buffer;
    VkBuffer gamma_buf = pImpl_->tensor_pool_[gamma_slot].buffer;
    VkBuffer w_buf   = pImpl_->tensor_pool_[w_slot].buffer;
    if (in_buf == VK_NULL_HANDLE || out_buf == VK_NULL_HANDLE ||
        gamma_buf == VK_NULL_HANDLE || w_buf == VK_NULL_HANDLE)
        return false;

    // ------------------------------------------------------------------------
    // SOVEREIGN STATIC PIPELINE: One-time init, zero-recording hot path
    // ------------------------------------------------------------------------
    const uint32_t fused_tile_m = desc.tile_m > 0 ? desc.tile_m : 16u;
    const uint32_t fused_tile_n = desc.tile_n > 0 ? desc.tile_n : 16u;
    const uint32_t fused_groups_x = (desc.num_rows + (fused_tile_m - 1u)) / fused_tile_m;
    const uint32_t fused_groups_y = (desc.output_size + (fused_tile_n - 1u)) / fused_tile_n;
    const uint64_t fused_signature = (static_cast<uint64_t>(kernel_id) << 48) |
                                     (static_cast<uint64_t>(fused_tile_m & 0xFFu) << 40) |
                                     (static_cast<uint64_t>(fused_tile_n & 0xFFu) << 32) |
                                     (static_cast<uint64_t>(fused_groups_x) << 16) |
                                     static_cast<uint64_t>(fused_groups_y);

    if (pImpl_->ubo_buffer_ == VK_NULL_HANDLE ||
        pImpl_->static_kernel_id_ != kernel_id ||
        pImpl_->static_layer_signature_ != fused_signature) {
        if (pImpl_->ubo_buffer_ != VK_NULL_HANDLE &&
            (pImpl_->static_kernel_id_ != kernel_id || pImpl_->static_layer_signature_ != fused_signature)) {
            for (uint32_t i = 0; i < Impl::kStaticRingSize; ++i) {
                if (pImpl_->static_ring_[i].fence != VK_NULL_HANDLE) {
                    vkDestroyFence(pImpl_->device_, pImpl_->static_ring_[i].fence, nullptr);
                    pImpl_->static_ring_[i].fence = VK_NULL_HANDLE;
                }
                pImpl_->static_ring_[i].cmd = VK_NULL_HANDLE;
                pImpl_->static_ring_[i].ready = true;
            }
            pImpl_->static_ring_head_ = 0;
        }
        if (pImpl_->ubo_buffer_ == VK_NULL_HANDLE) {
            if (!pImpl_->CreateUBOBuffer()) {
                fprintf(stderr, "[WARN] DispatchFusedRMSNormMatMul: UBO buffer creation failed\n");
                return false;
            }
        }
        if (!pImpl_->RecordStaticCBs(kernel_id, fused_groups_x, fused_groups_y)) {
            fprintf(stderr, "[WARN] DispatchFusedRMSNormMatMul: Static CB recording failed\n");
            return false;
        }
        pImpl_->static_kernel_id_ = kernel_id;
        pImpl_->static_layer_signature_ = fused_signature;
        fprintf(stderr, "[DEBUG] Static Pipeline: UBO + 16 pre-recorded CBs ready (fused)\n");
    }

    // Bind descriptors on first dispatch for this kernel
    if (!k.descriptors_bound) {
        VkWriteDescriptorSet writes[5] = {};
        VkDescriptorBufferInfo buf_infos[5] = {};

        buf_infos[0].buffer = in_buf;  buf_infos[0].offset = 0;  buf_infos[0].range = VK_WHOLE_SIZE;
        writes[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[0].dstSet = k.descriptor_set;
        writes[0].dstBinding = 0;
        writes[0].descriptorCount = 1;
        writes[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[0].pBufferInfo = &buf_infos[0];

        buf_infos[1].buffer = out_buf; buf_infos[1].offset = 0;  buf_infos[1].range = VK_WHOLE_SIZE;
        writes[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[1].dstSet = k.descriptor_set;
        writes[1].dstBinding = 1;
        writes[1].descriptorCount = 1;
        writes[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[1].pBufferInfo = &buf_infos[1];

        buf_infos[2].buffer = gamma_buf; buf_infos[2].offset = 0; buf_infos[2].range = VK_WHOLE_SIZE;
        writes[2].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[2].dstSet = k.descriptor_set;
        writes[2].dstBinding = 2;
        writes[2].descriptorCount = 1;
        writes[2].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[2].pBufferInfo = &buf_infos[2];

        buf_infos[3].buffer = w_buf;   buf_infos[3].offset = 0;  buf_infos[3].range = VK_WHOLE_SIZE;
        writes[3].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[3].dstSet = k.descriptor_set;
        writes[3].dstBinding = 3;
        writes[3].descriptorCount = 1;
        writes[3].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[3].pBufferInfo = &buf_infos[3];

        buf_infos[4].buffer = pImpl_->ubo_buffer_;
        buf_infos[4].offset = 0;
        buf_infos[4].range = Impl::kUBOSlotSize;
        writes[4].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[4].dstSet = k.descriptor_set;
        writes[4].dstBinding = 4;
        writes[4].descriptorCount = 1;
        writes[4].descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
        writes[4].pBufferInfo = &buf_infos[4];

        vkUpdateDescriptorSets(pImpl_->device_, 5, writes, 0, nullptr);
        k.descriptors_bound = true;
    }

    // Rotate to next static ring slot
    uint32_t ring_idx = pImpl_->static_ring_head_;
    pImpl_->static_ring_head_ = (pImpl_->static_ring_head_ + 1) % Impl::kStaticRingSize;
    auto& slot = pImpl_->static_ring_[ring_idx];

    // Wait for slot availability
    if (!slot.ready) {
        VkResult r = vkWaitForFences(pImpl_->device_, 1, &slot.fence, VK_TRUE, 0);
        if (r != VK_SUCCESS) {
            vkWaitForFences(pImpl_->device_, 1, &slot.fence, VK_TRUE, UINT64_MAX);
        }
        vkResetFences(pImpl_->device_, 1, &slot.fence);
        slot.ready = true;
    }

    // ------------------------------------------------------------------------
    // HOT PATH: Write fused params into mapped UBO
    // ------------------------------------------------------------------------
    uint8_t* ubo_slot = static_cast<uint8_t*>(pImpl_->ubo_mapped_) + (ring_idx * Impl::kUBOSlotSize);
    std::memset(ubo_slot, 0, Impl::kUBOSlotSize);
    *reinterpret_cast<uint32_t*>(ubo_slot + 0x00) = desc.hidden_size;
    *reinterpret_cast<uint32_t*>(ubo_slot + 0x04) = desc.output_size;
    *reinterpret_cast<float*>(ubo_slot + 0x08)    = desc.eps;
    *reinterpret_cast<uint32_t*>(ubo_slot + 0x0C) = 0; // layer_idx
    *reinterpret_cast<uint32_t*>(ubo_slot + 0x10) = desc.num_rows;

    // ------------------------------------------------------------------------
    // HOT PATH: Submit pre-recorded command buffer
    // ------------------------------------------------------------------------
    pImpl_->timeline_value_++;
    uint64_t signal_value = pImpl_->timeline_value_;

    VkTimelineSemaphoreSubmitInfo timeline_info{};
    timeline_info.sType = VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO;
    timeline_info.signalSemaphoreValueCount = 1;
    timeline_info.pSignalSemaphoreValues = &signal_value;

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.pNext = &timeline_info;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &slot.cmd;
    submit_info.signalSemaphoreCount = 1;
    submit_info.pSignalSemaphores = &pImpl_->timeline_semaphore_;

    VkResult r = vkQueueSubmit(pImpl_->queue_, 1, &submit_info, slot.fence);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "[WARN] DispatchFusedRMSNormMatMul: vkQueueSubmit failed: %d\n", r);
        return false;
    }
    pImpl_->last_submit_cpu_ns_ = NowSteadyNs();
    slot.ready = false;
    pImpl_->last_submitted_static_indices_[0] = ring_idx;
    pImpl_->last_submitted_static_count_ = 1;

    pImpl_->stats_.matmul_dispatched++;
    return true;
}

bool VulkanAccelerator::DispatchStaticLayerChain(const StaticLayerDesc& desc) {
    if (!IsReady() || desc.steps.empty()) return false;

    for (const auto& step : desc.steps) {
        if (step.bindings.empty()) {
            continue;
        }
        std::vector<GpuTensorHandle> deps;
        deps.reserve(step.bindings.size());
        for (const auto& b : step.bindings) {
            deps.push_back(b.tensor);
        }
        if (!pImpl_->WaitForTensorUploads(deps.data(), deps.size())) {
            return false;
        }
    }

    uint64_t signature = ComputeStaticLayerSignature(desc);
    if (pImpl_->ubo_buffer_ == VK_NULL_HANDLE || pImpl_->static_layer_signature_ != signature) {
        if (pImpl_->ubo_buffer_ == VK_NULL_HANDLE) {
            if (!pImpl_->CreateUBOBuffer()) {
                fprintf(stderr, "[WARN] DispatchStaticLayerChain: UBO buffer creation failed\n");
                return false;
            }
        }
        if (!pImpl_->RecordStaticLayerCBs(desc)) {
            fprintf(stderr, "[WARN] DispatchStaticLayerChain: Static layer CB recording failed\n");
            return false;
        }
        fprintf(stderr, "[DEBUG] Static Layer Pipeline: %zu steps, %zu barriers, 16 pre-recorded CBs ready\n",
                desc.steps.size(), desc.barriers.size());
    }

    uint32_t ring_idx = pImpl_->static_ring_head_;
    pImpl_->static_ring_head_ = (pImpl_->static_ring_head_ + 1) % Impl::kStaticRingSize;
    auto& slot = pImpl_->static_ring_[ring_idx];

    if (!slot.ready) {
        VkResult r = vkWaitForFences(pImpl_->device_, 1, &slot.fence, VK_TRUE, 0);
        if (r != VK_SUCCESS) {
            vkWaitForFences(pImpl_->device_, 1, &slot.fence, VK_TRUE, UINT64_MAX);
        }
        vkResetFences(pImpl_->device_, 1, &slot.fence);
        slot.ready = true;
    }

    uint8_t* slot_base = static_cast<uint8_t*>(pImpl_->ubo_mapped_) + (ring_idx * Impl::kUBOSlotSize);
    for (const auto& step : desc.steps) {
        if (step.params != nullptr && step.params_size > 0) {
            if (step.ubo_offset >= Impl::kUBOSlotSize ||
                (static_cast<uint64_t>(step.ubo_offset) + static_cast<uint64_t>(step.params_size)) > Impl::kUBOSlotSize) {
                fprintf(stderr, "[WARN] DispatchStaticLayerChain: param blob exceeds UBO slot\n");
                return false;
            }
            std::memcpy(slot_base + step.ubo_offset, step.params, step.params_size);
        }
    }

    pImpl_->timeline_value_++;
    uint64_t signal_value = pImpl_->timeline_value_;

    VkTimelineSemaphoreSubmitInfo timeline_info{};
    timeline_info.sType = VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO;
    timeline_info.signalSemaphoreValueCount = 1;
    timeline_info.pSignalSemaphoreValues = &signal_value;

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.pNext = &timeline_info;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &slot.cmd;
    submit_info.signalSemaphoreCount = 1;
    submit_info.pSignalSemaphores = &pImpl_->timeline_semaphore_;

    VkResult r = vkQueueSubmit(pImpl_->queue_, 1, &submit_info, slot.fence);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "[WARN] DispatchStaticLayerChain: vkQueueSubmit failed: %d\n", r);
        return false;
    }

    pImpl_->last_submit_cpu_ns_ = NowSteadyNs();
    slot.ready = false;
    pImpl_->last_submitted_static_indices_[0] = ring_idx;
    pImpl_->last_submitted_static_count_ = 1;
    pImpl_->stats_.layer_dispatches++;
    pImpl_->static_kernel_id_ = 0;
    pImpl_->static_layer_signature_ = signature;
    return true;
}

bool VulkanAccelerator::Wait(uint64_t timeout_ns) {
    pImpl_->FlushUploadRing(true);
    if (!IsReady()) return false;

    // SOVEREIGN PATH: Timeline semaphore non-blocking poll
    if (pImpl_->timeline_semaphore_ != VK_NULL_HANDLE) {
        uint64_t target = pImpl_->timeline_value_;
        uint64_t current = 0;
        uint64_t deadline = 0; // TODO: use QueryPerformanceCounter for wall-clock deadline
        (void)deadline;

        // Spin-poll loop (no kernel transitions, pure user-space)
        for (;;) {
            VkResult r = vkGetSemaphoreCounterValue(pImpl_->device_, pImpl_->timeline_semaphore_, &current);
            if (r != VK_SUCCESS) {
                fprintf(stderr, "[WARN] Wait: vkGetSemaphoreCounterValue failed: %d\n", r);
                break;
            }
            if (current >= target) {
                pImpl_->CaptureLastStaticGpuDispatchNs();
                if (pImpl_->last_submit_cpu_ns_ != 0) {
                    uint64_t submit_to_signal = NowSteadyNs() - pImpl_->last_submit_cpu_ns_;
                    pImpl_->stats_.last_submit_to_signal_ns = submit_to_signal;
                    pImpl_->stats_.last_host_residual_ns =
                        (submit_to_signal > pImpl_->stats_.last_dispatch_ns)
                            ? (submit_to_signal - pImpl_->stats_.last_dispatch_ns)
                            : 0;
                }
                return true; // GPU has caught up
            }
            // Yield briefly to avoid burning CPU on long waits
            // In production, use a hybrid: spin for ~1ms, then Sleep(0)
            // For now, we keep spinning for lowest latency
        }
    }

    // FALLBACK: Legacy fence wait (blocking)
    VkResult r = vkWaitForFences(pImpl_->device_, 1, &pImpl_->fence_, VK_TRUE, timeout_ns);
    if (r == VK_SUCCESS) {
        vkResetFences(pImpl_->device_, 1, &pImpl_->fence_);
        pImpl_->CaptureLastStaticGpuDispatchNs();
        if (pImpl_->last_submit_cpu_ns_ != 0) {
            uint64_t submit_to_signal = NowSteadyNs() - pImpl_->last_submit_cpu_ns_;
            pImpl_->stats_.last_submit_to_signal_ns = submit_to_signal;
            pImpl_->stats_.last_host_residual_ns =
                (submit_to_signal > pImpl_->stats_.last_dispatch_ns)
                    ? (submit_to_signal - pImpl_->stats_.last_dispatch_ns)
                    : 0;
        }
        return true;
    }
    fprintf(stderr, "[WARN] Wait: vkWaitForFences returned %d\n", r);
    return false;
}

bool VulkanAccelerator::ReadbackTensor(GpuTensorHandle handle, void* dst) {
    if (!IsReady() || !handle.IsValid() || dst == nullptr) return false;

    if (!pImpl_->WaitForTensorUpload(handle)) {
        return false;
    }

    uint32_t slot = handle.id - 1;
    if (slot >= Impl::kMaxTensors) return false;

    auto& s = pImpl_->tensor_pool_[slot];
    if (!s.occupied) return false;

    if (!pImpl_->CreateStagingBuffer(s.size_bytes)) return false;

    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(pImpl_->cmd_buffer_, &begin_info);

    VkBufferCopy copy_region{};
    copy_region.size = s.size_bytes;
    vkCmdCopyBuffer(pImpl_->cmd_buffer_, s.buffer, pImpl_->staging_buffer_, 1, &copy_region);

    vkEndCommandBuffer(pImpl_->cmd_buffer_);

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &pImpl_->cmd_buffer_;
    vkQueueSubmit(pImpl_->queue_, 1, &submit_info, pImpl_->fence_);
    vkWaitForFences(pImpl_->device_, 1, &pImpl_->fence_, VK_TRUE, UINT64_MAX);
    vkResetFences(pImpl_->device_, 1, &pImpl_->fence_);

    std::memcpy(dst, pImpl_->staging_mapped_, s.size_bytes);
    return true;
}

VulkanAccelerator::Stats VulkanAccelerator::GetStats() const {
    return pImpl_->stats_;
}

void VulkanAccelerator::Shutdown() {
    if (!pImpl_ || pImpl_->device_ == VK_NULL_HANDLE) return;

    // 1. Block the GPU — no work in flight before teardown
    vkDeviceWaitIdle(pImpl_->device_);

    // 2. Release all tensors (buffers/memory must die before device)
    ReleaseAllTensors();

    // 3. Destroy all kernel pipelines + descriptor infrastructure (LIFO)
    for (uint32_t i = 0; i < Impl::kMaxKernels; ++i) {
        pImpl_->DestroyKernelSlot(i);
    }
    if (pImpl_->descriptor_pool_ != VK_NULL_HANDLE) {
        vkDestroyDescriptorPool(pImpl_->device_, pImpl_->descriptor_pool_, nullptr);
        pImpl_->descriptor_pool_ = VK_NULL_HANDLE;
    }

    // 4. Destroy staging resources
    if (pImpl_->staging_buffer_ != VK_NULL_HANDLE)
        vkDestroyBuffer(pImpl_->device_, pImpl_->staging_buffer_, nullptr);
    if (pImpl_->staging_memory_ != VK_NULL_HANDLE)
        vkFreeMemory(pImpl_->device_, pImpl_->staging_memory_, nullptr);

    // 4b. Destroy async upload ring resources
    for (uint32_t i = 0; i < Impl::kUploadRingSize; ++i) {
        if (pImpl_->upload_ring_[i].staging_buffer != VK_NULL_HANDLE) {
            vkDestroyBuffer(pImpl_->device_, pImpl_->upload_ring_[i].staging_buffer, nullptr);
            pImpl_->upload_ring_[i].staging_buffer = VK_NULL_HANDLE;
        }
        if (pImpl_->upload_ring_[i].staging_memory != VK_NULL_HANDLE) {
            vkFreeMemory(pImpl_->device_, pImpl_->upload_ring_[i].staging_memory, nullptr);
            pImpl_->upload_ring_[i].staging_memory = VK_NULL_HANDLE;
        }
        if (pImpl_->upload_ring_[i].fence != VK_NULL_HANDLE) {
            vkDestroyFence(pImpl_->device_, pImpl_->upload_ring_[i].fence, nullptr);
            pImpl_->upload_ring_[i].fence = VK_NULL_HANDLE;
        }
        pImpl_->upload_ring_[i].cmd = VK_NULL_HANDLE;
        pImpl_->upload_ring_[i].staging_mapped = nullptr;
        pImpl_->upload_ring_[i].staging_size = 0;
        pImpl_->upload_ring_[i].in_flight = false;
        pImpl_->upload_ring_[i].submit_seq = 0;
    }
    pImpl_->upload_ring_ready_ = false;
    pImpl_->upload_submit_seq_ = 0;

    // 5. Destroy sovereign static pipeline resources (UBO + static CB ring)
    pImpl_->DestroyUBOBuffer();
    for (uint32_t i = 0; i < Impl::kStaticRingSize; ++i) {
        if (pImpl_->static_ring_[i].fence != VK_NULL_HANDLE)
            vkDestroyFence(pImpl_->device_, pImpl_->static_ring_[i].fence, nullptr);
        pImpl_->static_ring_[i].fence = VK_NULL_HANDLE;
        pImpl_->static_ring_[i].cmd = VK_NULL_HANDLE;
        pImpl_->static_ring_[i].ready = true;
        pImpl_->static_ring_[i].kernel_id = 0;
    }
    pImpl_->static_ring_head_ = 0;
    pImpl_->static_kernel_id_ = 0;
    pImpl_->static_layer_signature_ = 0;
    pImpl_->static_layer_descriptor_sets_.clear();
    pImpl_->last_submitted_static_count_ = 0;
    pImpl_->last_gpu_dispatch_ns_ = 0;
    pImpl_->last_submit_cpu_ns_ = 0;
    if (pImpl_->timestamp_query_pool_ != VK_NULL_HANDLE) {
        vkDestroyQueryPool(pImpl_->device_, pImpl_->timestamp_query_pool_, nullptr);
        pImpl_->timestamp_query_pool_ = VK_NULL_HANDLE;
    }

    // 6. Destroy command infrastructure (ring + legacy)
    for (uint32_t i = 0; i < Impl::kCmdBufRingSize; ++i) {
        if (pImpl_->cmd_ring_[i].fence != VK_NULL_HANDLE)
            vkDestroyFence(pImpl_->device_, pImpl_->cmd_ring_[i].fence, nullptr);
        pImpl_->cmd_ring_[i].fence = VK_NULL_HANDLE;
        pImpl_->cmd_ring_[i].cmd = VK_NULL_HANDLE;
        pImpl_->cmd_ring_[i].ready = true;
    }
    pImpl_->cmd_ring_head_ = 0;
    pImpl_->timeline_value_ = 0;
    if (pImpl_->timeline_semaphore_ != VK_NULL_HANDLE)
        vkDestroySemaphore(pImpl_->device_, pImpl_->timeline_semaphore_, nullptr);
    pImpl_->timeline_semaphore_ = VK_NULL_HANDLE;
    if (pImpl_->fence_ != VK_NULL_HANDLE)
        vkDestroyFence(pImpl_->device_, pImpl_->fence_, nullptr);
    pImpl_->fence_ = VK_NULL_HANDLE;
    pImpl_->cmd_buffer_ = VK_NULL_HANDLE;
    if (pImpl_->cmd_pool_ != VK_NULL_HANDLE)
        vkDestroyCommandPool(pImpl_->device_, pImpl_->cmd_pool_, nullptr);
    pImpl_->cmd_pool_ = VK_NULL_HANDLE;

    // 6. Finally destroy device and instance
    if (pImpl_->device_ != VK_NULL_HANDLE)
        vkDestroyDevice(pImpl_->device_, nullptr);
    if (pImpl_->instance_ != VK_NULL_HANDLE)
        vkDestroyInstance(pImpl_->instance_, nullptr);

    pImpl_->instance_ = VK_NULL_HANDLE;
    pImpl_->device_   = VK_NULL_HANDLE;
}

// ============================================================================
// Global singleton
// ============================================================================

VulkanAccelerator& GetVulkanAccelerator() {
    static VulkanAccelerator s_instance;
    return s_instance;
}

} // namespace rawrxd
