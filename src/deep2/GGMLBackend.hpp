// ============================================================================
// GGMLBackend.hpp — Vulkan Compute Backend for R9700 (RDNA4 gfx1201)
// Concrete ExecutionBackend implementation
// Productionized from Sovereign Engine architecture
// ============================================================================

#pragma once

#include "OutOfCoreRuntime.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <functional>

// Forward-declare Vulkan types to avoid header dependency bloat
struct VkInstance_T;
struct VkPhysicalDevice_T;
struct VkDevice_T;
struct VkQueue_T;
struct VkCommandPool_T;
struct VkCommandBuffer_T;
struct VkBuffer_T;
struct VkDeviceMemory_T;
struct VkDescriptorPool_T;
struct VkDescriptorSet_T;
struct VkDescriptorSetLayout_T;
struct VkPipeline_T;
struct VkPipelineLayout_T;
struct VkShaderModule_T;
struct VkFence_T;

using VkInstance = VkInstance_T*;
using VkPhysicalDevice = VkPhysicalDevice_T*;
using VkDevice = VkDevice_T*;
using VkQueue = VkQueue_T*;
using VkCommandPool = VkCommandPool_T*;
using VkCommandBuffer = VkCommandBuffer_T*;
using VkBuffer = VkBuffer_T*;
using VkDeviceMemory = VkDeviceMemory_T*;
using VkDescriptorPool = VkDescriptorPool_T*;
using VkDescriptorSet = VkDescriptorSet_T*;
using VkDescriptorSetLayout = VkDescriptorSetLayout_T*;
using VkPipeline = VkPipeline_T*;
using VkPipelineLayout = VkPipelineLayout_T*;
using VkShaderModule = VkShaderModule_T*;
using VkFence = VkFence_T*;
using VkResult = int;

namespace rawrxd {

// ============================================================================
// VulkanBuffer — RAII wrapper for VkBuffer + VkDeviceMemory
// ============================================================================
struct VulkanBuffer {
    VkBuffer buffer = nullptr;
    VkDeviceMemory memory = nullptr;
    size_t size = 0;
    bool device_local = false;  // true = VRAM, false = staging (CPU-visible)

    bool valid() const { return buffer != nullptr && memory != nullptr; }
    void reset();
};

// ============================================================================
// VulkanContext — Minimal compute-only Vulkan context
// No graphics, no swapchain, no presentation
// ============================================================================
struct VulkanContext {
    VkInstance instance = nullptr;
    VkPhysicalDevice physical_device = nullptr;
    VkDevice device = nullptr;
    VkQueue compute_queue = nullptr;
    uint32_t compute_queue_family = ~0u;
    VkCommandPool command_pool = nullptr;
    VkDescriptorPool descriptor_pool = nullptr;
    VkPipelineLayout pipeline_layout = nullptr;
    VkPipeline compute_pipeline = nullptr;
    VkDescriptorSetLayout descriptor_set_layout = nullptr;
    VkDescriptorSet descriptor_set = nullptr;
    VkFence fence = nullptr;

    // Device properties
    uint64_t vram_bytes = 0;
    uint32_t max_compute_work_group_size[3] = {0,0,0};
    uint32_t max_compute_work_group_count[3] = {0,0,0};
    uint32_t subgroup_size = 64;  // AMD RDNA typical

    bool valid() const { return device != nullptr; }
    void shutdown();
};

// ============================================================================
// GGMLBackend — Vulkan compute ExecutionBackend
// Wraps ggml-style Vulkan dispatch for quantized GEMV/GEMM
// ============================================================================
class GGMLBackend final : public ExecutionBackend {
public:
    GGMLBackend();
    ~GGMLBackend() override;

    // Disable copy/move
    GGMLBackend(const GGMLBackend&) = delete;
    GGMLBackend& operator=(const GGMLBackend&) = delete;

    // -------------------------------------------------------------------------
    // ExecutionBackend interface
    // -------------------------------------------------------------------------
    Backend type() const override { return Backend::GPU; }
    std::shared_ptr<ExecutionBuffer> upload(const uint8_t* data, size_t bytes) override;
    bool download(const std::shared_ptr<ExecutionBuffer>& buffer, uint8_t* destination, size_t bytes) override;
    void release(std::shared_ptr<ExecutionBuffer>& buffer) override;
    bool execute(const TensorDescriptor& tensor, const std::shared_ptr<ExecutionBuffer>& buffer) override;

    // ------------------------------------------------------------------------
    // GPU-specific API
    // ------------------------------------------------------------------------
    bool initialize();
    bool isInitialized() const { return initialized_; }
    void shutdown();

    // Device info
    std::string deviceName() const;
    uint64_t vramTotal() const;
    uint64_t vramUsed() const;
    uint32_t computeUnits() const;

    // Quantized kernel dispatch
    bool dispatchQ4KGEMV(const float* input, const uint8_t* weights,
                         size_t n, size_t k, float* output);
    bool dispatchQ6KGEMV(const float* input, const uint8_t* weights,
                         size_t n, size_t k, float* output);
    bool dispatchF16GEMV(const float* input, const uint8_t* weights,
                         size_t n, size_t k, float* output);

    // Synchronization
    void synchronize();

    // Performance queries
    float lastKernelTimeMs() const { return last_kernel_time_ms_; }

private:
    bool initialized_ = false;
    VulkanContext ctx_;
    uint64_t vram_used_ = 0;
    float last_kernel_time_ms_ = 0.0f;

    // Internal Vulkan helpers
    bool createInstance();
    bool selectPhysicalDevice();
    bool createLogicalDevice();
    bool createCommandPool();
    bool createDescriptorPool();
    bool createPipelineLayouts();
    bool createFence();

    VulkanBuffer allocateBuffer(size_t bytes, bool device_local);
    void freeBuffer(VulkanBuffer& buf);
    bool uploadToDevice(const void* src, VulkanBuffer& dst, size_t bytes);
    bool downloadFromDevice(const VulkanBuffer& src, void* dst, size_t bytes);

    // SPIR-V compute shader modules (compiled offline)
    VkShaderModule loadShaderModule(const uint32_t* spirv, size_t word_count);

    // Kernel registry
    struct KernelEntry {
        VkShaderModule shader = nullptr;
        VkPipeline pipeline = nullptr;
        std::string name;
    };
    std::vector<KernelEntry> kernels_;

    bool dispatchCompute(VkPipeline pipeline, uint32_t group_count_x,
                         uint32_t group_count_y, uint32_t group_count_z);
};

// ============================================================================
// Factory function — creates a GGMLBackend and initializes Vulkan
// ============================================================================
std::shared_ptr<ExecutionBackend> CreateGGMLBackend();

} // namespace rawrxd
