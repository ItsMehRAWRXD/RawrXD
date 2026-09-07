#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <queue>

// Phase 46: Vulkan support with graceful fallback for dual GPU testing
#if defined(RAWR_ENABLE_VULKAN) || defined(RAWR_HAS_VULKAN)
    #if __has_include(<vulkan/vulkan.h>)
        #include <vulkan/vulkan.h>
        #define RAWR_VULKAN_AVAILABLE 1
    #else
        #pragma message("Vulkan SDK headers not found — using CPU fallback for dual GPU testing")
        #define RAWR_VULKAN_AVAILABLE 0
    #endif
#else
    #define RAWR_VULKAN_AVAILABLE 0
#endif

#if !RAWR_VULKAN_AVAILABLE
// Dummy types to allow compilation without Vulkan SDK
// Only define if not already defined by real Vulkan headers
#ifndef VK_VERSION_1_0
typedef void* VkDevice;
typedef void* VkInstance;
typedef void* VkPhysicalDevice;
typedef void* VkQueue;
typedef void* VkCommandPool;
typedef void* VkDescriptorPool;
typedef void* VkDescriptorSet;
typedef void* VkDescriptorSetLayout;
typedef void* VkShaderModule;
typedef void* VkPipelineLayout;
typedef void* VkPipeline;
typedef void* VkPipelineCache;
typedef void* VkBuffer;
typedef void* VkDeviceMemory;
typedef void* VkCommandBuffer;
typedef void* VkFence;
typedef void* VkDescriptorSetLayoutBinding;
typedef uint32_t VkMemoryPropertyFlags;
typedef int VkResult;
typedef uint64_t VkDeviceSize;

// VkBufferCopy for buffer-to-buffer copy regions
typedef struct VkBufferCopy {
    VkDeviceSize srcOffset;
    VkDeviceSize dstOffset;
    VkDeviceSize size;
} VkBufferCopy;

typedef struct { 
    uint32_t vendorID; 
    uint32_t deviceID; 
    char deviceName[256];
} VkPhysicalDeviceProperties;

// Define VkMemoryType and VkMemoryHeap first (needed for VkPhysicalDeviceMemoryProperties)
typedef struct VkMemoryType {
    uint32_t propertyFlags;
    uint32_t heapIndex;
} VkMemoryType;

typedef struct VkMemoryHeap {
    uint64_t size;
    uint64_t flags;
} VkMemoryHeap;

// Now define VkPhysicalDeviceMemoryProperties using the proper types
typedef struct VkPhysicalDeviceMemoryProperties {
    uint32_t memoryTypeCount;
    VkMemoryType memoryTypes[32];
    uint32_t memoryHeapCount;
    VkMemoryHeap memoryHeaps[16];
} VkPhysicalDeviceMemoryProperties;

// VkQueueFamilyProperties for queue family queries
typedef struct VkQueueFamilyProperties {
    uint32_t queueFlags;
    uint32_t queueCount;
    uint32_t timestampValidBits;
    uint32_t minImageTransferGranularity[3];
} VkQueueFamilyProperties;

// Stub function declarations for CPU fallback
inline void vkGetPhysicalDeviceQueueFamilyProperties(VkPhysicalDevice, uint32_t* count, VkQueueFamilyProperties*) {
    if (count) *count = 0;
}
inline void vkGetPhysicalDeviceMemoryProperties(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties*) {}

// Additional Vulkan function stubs for CPU fallback compilation
inline VkResult vkCreateInstance(const void*, const void*, VkInstance*) { return 0; }
inline void vkDestroyInstance(VkInstance, const void*) {}
inline VkResult vkEnumeratePhysicalDevices(VkInstance, uint32_t* count, VkPhysicalDevice*) { if (count) *count = 0; return 0; }
inline void vkGetPhysicalDeviceProperties(VkPhysicalDevice, VkPhysicalDeviceProperties*) {}
inline VkResult vkCreateDevice(VkPhysicalDevice, const void*, const void*, VkDevice*) { return 0; }
inline void vkDestroyDevice(VkDevice, const void*) {}
inline void vkGetDeviceQueue(VkDevice, uint32_t, uint32_t, VkQueue*) {}
inline VkResult vkCreateCommandPool(VkDevice, const void*, const void*, VkCommandPool*) { return 0; }
inline void vkDestroyCommandPool(VkDevice, VkCommandPool, const void*) {}
inline VkResult vkCreateDescriptorSetLayout(VkDevice, const void*, const void*, VkDescriptorSetLayout*) { return 0; }
inline void vkDestroyDescriptorSetLayout(VkDevice, VkDescriptorSetLayout, const void*) {}
inline VkResult vkCreateDescriptorPool(VkDevice, const void*, const void*, VkDescriptorPool*) { return 0; }
inline void vkDestroyDescriptorPool(VkDevice, VkDescriptorPool, const void*) {}
inline VkResult vkCreatePipelineLayout(VkDevice, const void*, const void*, VkPipelineLayout*) { return 0; }
inline void vkDestroyPipelineLayout(VkDevice, VkPipelineLayout, const void*) {}
inline VkResult vkCreateShaderModule(VkDevice, const void*, const void*, VkShaderModule*) { return 0; }
inline void vkDestroyShaderModule(VkDevice, VkShaderModule, const void*) {}
inline VkResult vkCreateComputePipelines(VkDevice, VkPipelineCache, uint32_t, const void*, const void*, VkPipeline*) { return 0; }
inline void vkDestroyPipeline(VkDevice, VkPipeline, const void*) {}
inline VkResult vkCreateBuffer(VkDevice, const void*, const void*, VkBuffer*) { return 0; }
inline void vkDestroyBuffer(VkDevice, VkBuffer, const void*) {}
inline VkResult vkAllocateMemory(VkDevice, const void*, const void*, VkDeviceMemory*) { return 0; }
inline void vkFreeMemory(VkDevice, VkDeviceMemory, const void*) {}
inline void vkGetBufferMemoryRequirements(VkDevice, VkBuffer, void*) {}
inline VkResult vkBindBufferMemory(VkDevice, VkBuffer, VkDeviceMemory, uint64_t) { return 0; }
inline VkResult vkMapMemory(VkDevice, VkDeviceMemory, uint64_t, uint64_t, uint32_t, void**) { return 0; }
inline void vkUnmapMemory(VkDevice, VkDeviceMemory) {}
inline VkResult vkAllocateDescriptorSets(VkDevice, const void*, VkDescriptorSet*) { return 0; }
inline void vkUpdateDescriptorSets(VkDevice, uint32_t, const void*, uint32_t, const void*) {}
inline VkResult vkAllocateCommandBuffers(VkDevice, const void*, VkCommandBuffer*) { return 0; }
inline void vkFreeCommandBuffers(VkDevice, VkCommandPool, uint32_t, const VkCommandBuffer*) {}
inline VkResult vkBeginCommandBuffer(VkCommandBuffer, const void*) { return 0; }
inline VkResult vkResetCommandBuffer(VkCommandBuffer, uint32_t) { return 0; }
inline VkResult vkEndCommandBuffer(VkCommandBuffer) { return 0; }
inline void vkCmdBindPipeline(VkCommandBuffer, uint32_t, VkPipeline) {}
inline void vkCmdBindDescriptorSets(VkCommandBuffer, uint32_t, VkPipelineLayout, uint32_t, uint32_t, const VkDescriptorSet*, uint32_t, const uint32_t*) {}
inline void vkCmdDispatch(VkCommandBuffer, uint32_t, uint32_t, uint32_t) {}
inline void vkCmdPushConstants(VkCommandBuffer, VkPipelineLayout, uint32_t, uint32_t, uint32_t, const void*) {}
inline void vkCmdCopyBuffer(VkCommandBuffer, VkBuffer, VkBuffer, uint32_t, const void*) {}
inline VkResult vkCreateFence(VkDevice, const void*, const void*, VkFence*) { return 0; }
inline void vkDestroyFence(VkDevice, VkFence, const void*) {}
inline VkResult vkQueueSubmit(VkQueue, uint32_t, const void*, VkFence) { return 0; }
inline VkResult vkQueueWaitIdle(VkQueue) { return 0; }
inline VkResult vkDeviceWaitIdle(VkDevice) { return 0; }
inline VkResult vkWaitForFences(VkDevice, uint32_t, const VkFence*, uint32_t, uint64_t) { return 0; }

#endif // VK_VERSION_1_0
#endif // !RAWR_VULKAN_AVAILABLE

// Forward declaration for gguf_loader.h which uses VulkanTensor at global scope
struct VulkanTensor;

namespace CPUInference {

// GPU compute optional - CPU inference always works
// Vulkan is enabled if system supports it, otherwise CPU fallback

struct VulkanDeviceInfo {
    std::string device_name;
    VkPhysicalDeviceProperties properties{};
    VkPhysicalDeviceMemoryProperties memory_props{};
    uint32_t vendor_id;
    uint32_t device_id;
    bool supports_compute;
    uint32_t compute_queue_family;
};

struct ComputeShader {
    std::string name;
    std::vector<uint32_t> spirv_code;
    VkShaderModule module = nullptr;
    VkPipelineLayout layout = nullptr;
    VkPipeline pipeline = nullptr;
};

struct VulkanTensor {
    std::string name;
    size_t size_bytes{0};
    std::vector<float> host_data;  // Scalar data stored in CPU memory
    VkBuffer device_buffer = nullptr;
    VkDeviceMemory device_memory = nullptr;
};

// Async command buffer pool for high-performance batching
struct CommandBufferPool {
    VkCommandBuffer buffer = nullptr;
    VkFence fence = nullptr;
    bool is_available = true;
};

class VulkanCompute {
public:
    VulkanCompute();
    ~VulkanCompute();

    bool Initialize();
    bool InitializeSolo(const char* nameNeedle);
    bool LoadShader(const std::string& name, const std::string& spirv_path);
    bool CreateComputePipeline(const std::string& shader_name);
    VulkanTensor TransferGGUFTensor(const std::string& tensor_name,
                                    const void* data_ptr,
                                    size_t size_bytes,
                                    uint32_t usage = 0);
    void ReleaseTensors();
    bool EnsureMatMulPipeline(const std::string& spirv_path);
    bool DispatchMatMul(uint32_t input_a_idx,
                        uint32_t input_b_idx,
                        uint32_t output_idx,
                        uint32_t M,
                        uint32_t K,
                        uint32_t N);
    
    // High-performance async variant using command buffer pooling
    bool DispatchMatMulAsync(uint32_t input_a_idx,
                             uint32_t input_b_idx,
                             uint32_t output_idx,
                             uint32_t M,
                             uint32_t K,
                             uint32_t N);
    
    // GEMV dispatch — resident DEVICE_LOCAL weights; host-visible act I/O
    bool DispatchGEMV(const float* weights, const float* input, float* output,
                      uint32_t rows, uint32_t cols, uint64_t cacheKey = 0);

    // ---- STREAMER_GPU_FORWARD_OPS_001: device-resident layer path ----
    struct DeviceBuf {
        VkBuffer buffer = nullptr;
        VkDeviceMemory memory = nullptr;
        size_t bytes = 0;
    };
    bool EnsureForwardArena(uint32_t hidden, uint32_t inter, uint32_t nHeads,
                            uint32_t nKv, uint32_t headDim, uint32_t maxSeq,
                            uint32_t nLayers = 32);
    bool UploadHidden(const float* host, uint32_t n);
    bool DownloadHidden(float* host, uint32_t n);
    bool CopyArenaHiddenTo(VulkanCompute& dst, uint32_t n); // ownership handoff
    bool DispatchGemvDevice(const float* weights, uint64_t cacheKey,
                            DeviceBuf& in, DeviceBuf& out,
                            uint32_t rows, uint32_t cols);
    bool DispatchGemvPacked(const void* packed, size_t bytes,
                            DeviceBuf& in, DeviceBuf& out,
                            uint32_t rows, uint32_t cols);
    bool DispatchGemvQ6kPacked(const void* packed, size_t bytes,
                               DeviceBuf& in, DeviceBuf& out,
                               uint32_t rows, uint32_t cols);
    bool DispatchGEMVPacked(const void* packed, size_t bytes,
                            const float* input, float* output,
                            uint32_t rows, uint32_t cols, uint64_t pinKey = 0);
    // MLA_FUSED_Q4KT: packed resident weights → FMA (no F32 expand).
    bool DispatchGEMVFusedQ4KT(const void* packed, size_t bytes,
                               const float* input, float* output,
                               uint32_t rows, uint32_t cols, uint64_t pinKey = 0);
    // After a GEMV that uploaded `cols` activations, skip the next host→GPU
    // input copy when the next GEMV consumes the same device-side vector
    // (Q_A then KV_A both read hidden).
    void GemvReuseInputNext();
    uint64_t GemvInputReuseHits() const;
    uint64_t Q4kFusedOps() const { return q4k_fused_ops_; }
    bool DispatchGEMVQ6kPacked(const void* packed, size_t bytes,
                               const float* input, float* output,
                               uint32_t rows, uint32_t cols);
    bool DispatchGemvQuant(int ggmlType, const void* packed, size_t bytes,
                           DeviceBuf& in, DeviceBuf& out,
                           uint32_t rows, uint32_t cols);
    bool DispatchGEMVQuant(int ggmlType, const void* packed, size_t bytes,
                           const float* input, float* output,
                           uint32_t rows, uint32_t cols, uint64_t pinKey = 0);
    uint64_t Q4kPackedOps() const { return q4k_packed_ops_; }
    uint64_t Q6kPackedOps() const { return q6k_packed_ops_; }
    uint64_t Q5kPackedOps() const { return q5k_packed_ops_; }
    uint64_t Q3kPackedOps() const { return q3k_packed_ops_; }
    uint64_t Q2kPackedOps() const { return q2k_packed_ops_; }
    uint64_t Q8PackedOps() const { return q8_packed_ops_; }
    uint64_t QuantPackedOps() const {
        return q4k_packed_ops_ + q6k_packed_ops_ + q5k_packed_ops_ +
               q3k_packed_ops_ + q2k_packed_ops_ + q8_packed_ops_;
    }
    uint64_t FusedCbAllocs() const { return fused_cb_allocs_; }
    uint64_t FusedCbReuses() const { return fused_cb_reuses_; }
    uint64_t XferRecords() const { return xfer_records_; }
    uint64_t XferSubmits() const { return xfer_submits_; }
    uint32_t GemvLocalSize() const { return gemv_local_size_; }
    bool KernelTuneOk() const { return kernel_tune_ok_; }
    size_t WeightSlotBytes() const { return ww_slot_bytes_; }
    // Out-of-line: must share VulkanCompute layout with weight_window.cpp.
    size_t WeightBudgetBytes() const;
    size_t WeightPinBudgetFloor() const;
    void SetPinResidentBudget(size_t bytes);
    uint64_t WeightPinCacheCount() const;
    uint64_t WeightPinResidentBytes() const;
    bool HasPinnedGemvWeight(uint64_t pinKey, size_t bytes, uint32_t rows,
                             uint32_t cols) const;
    size_t WeightUsableBudget() const { return ww_usable_budget_; }
    size_t WeightArenaReserve() const { return ww_arena_reserve_; }
    size_t WeightDeviceHeap() const { return ww_device_heap_; }
    bool WeightSlotsAuto() const { return ww_slots_auto_; }
    static constexpr uint32_t kWeightMinSlots = 2;
    static constexpr uint32_t kWeightMaxSlots = 16;
    static size_t ForwardArenaReserveBytes(uint32_t hidden, uint32_t inter, uint32_t nHeads,
                                           uint32_t nKv, uint32_t headDim, uint32_t maxSeq,
                                           uint32_t nLayers);
    size_t DeviceLocalHeapBytes() const;
    static bool ChooseWeightWindow(size_t maxPacked, size_t envBudget, uint32_t envSlots,
                                   size_t arenaReserve, size_t deviceHeap,
                                   uint32_t& slotCount, size_t& usableOut);
    bool ApplyWeightWindowPolicy(size_t maxPacked, size_t envBudget, uint32_t envSlots,
                                 size_t arenaReserve);
    // STREAMER_GPU_WEIGHT_WINDOW_001 — bounded slot streamer (default)
    bool EnsureWeightWindow(size_t slotBytes, uint32_t slotCount, size_t budgetBytes);
    bool StreamWeightToSlot(const void* weights, size_t bytes, VkBuffer& outDev);
    static uintptr_t WeightContentFingerprint(const void* p, size_t bytes);
    static bool WantWeightPin();
    uint64_t WeightPinRejects() const { return ww_pin_rejects_; }
    uint64_t WeightContentHits() const { return ww_content_hits_; }
    // LRU victims from EnsurePinnedPackedWeight budget pressure (not stream slots).
    uint64_t WeightPinEvicts() const { return gemv_pin_evicts_; }
    void ReleaseWeightWindow();
    // Cold-start only. Stream-slot rebuild must never clear pin residents —
    // that destroys PROMOTE_GPU_MLA_REUSE (u→0 / h↑) after warmup.
    void ClearPinnedGemvWeights();
    void ResetWeightWindowLayerCursor();
    bool WeightStreamActive() const { return ww_active_; }
    uint32_t WeightSlotCount() const { return ww_slot_count_; }
    uint64_t WeightStreamBytesTotal() const { return ww_stream_bytes_total_; }
    uint64_t WeightStreamPeakBytes() const { return ww_peak_bytes_; }
    uint64_t WeightSlotAllocs() const { return ww_slot_allocs_; }
    uint64_t WeightSlotReuses() const { return ww_slot_reuses_; }
    uint64_t WeightHotpathWaitIdle() const { return ww_hotpath_wait_idle_; }
    uint64_t WeightHotpathCreateBuf() const { return ww_hotpath_create_buf_; }
    uint64_t WeightHotpathDestroyBuf() const { return ww_hotpath_destroy_buf_; }
    uint64_t WeightResidentGrowthAfterInit() const { return ww_growth_after_init_; }
    uint64_t WeightPrefetchDistance() const { return ww_prefetch_distance_; }
    uint64_t WeightOverlapEvents() const { return ww_overlap_events_; }
    bool WeightPrefetchActive() const { return ww_prefetch_; }
    bool PermanentF32WeightCache() const { return !ww_active_; }
    bool PrefetchWeight(const void* weights, size_t bytes, uint32_t& slotOut);
    bool WaitWeightUpload(uint32_t slot);
    bool SubmitGemvPrefetch(uint32_t slot, DeviceBuf& in, DeviceBuf& out,
                            uint32_t rows, uint32_t cols, size_t packedBytes = 0,
                            int packedKind = 0); // 0=f32, 4=Q4_K, 6=Q6_K
    bool WaitWeightCompute(uint32_t slot);
    bool FlushWeightComputes();
    bool DispatchRmsNorm(DeviceBuf& in, DeviceBuf& w, DeviceBuf& out,
                         uint32_t n, float eps);
    bool DispatchResidualAdd(DeviceBuf& a, DeviceBuf& b, DeviceBuf& out, uint32_t n);
    bool DispatchRope(DeviceBuf& q, DeviceBuf& k, uint32_t headDim, uint32_t nHeads,
                      uint32_t nKv, uint32_t pos, float theta);
    bool DispatchAttnDecode(DeviceBuf& q, DeviceBuf& kCache, DeviceBuf& vCache,
                            DeviceBuf& out, uint32_t headDim, uint32_t nHeads,
                            uint32_t nKv, uint32_t seq, float scale,
                            uint32_t layer);
    bool DispatchSwiGLU(DeviceBuf& gate, DeviceBuf& up, DeviceBuf& out, uint32_t n);
    bool AppendKV(DeviceBuf& kTok, DeviceBuf& vTok, uint32_t kvDim, uint32_t pos,
                  uint32_t layer);
    DeviceBuf& ArenaHidden();
    DeviceBuf& ArenaResidual();
    DeviceBuf& ArenaNormed();
    DeviceBuf& ArenaQ();
    DeviceBuf& ArenaK();
    DeviceBuf& ArenaV();
    DeviceBuf& ArenaAttn();
    DeviceBuf& ArenaGate();
    DeviceBuf& ArenaUp();
    DeviceBuf& ArenaDown();
    DeviceBuf& ArenaFFNAct();
    DeviceBuf& ArenaAttnW(); // RMSNorm attn weight
    DeviceBuf& ArenaFfnW();
    DeviceBuf& ArenaKCache();
    DeviceBuf& ArenaVCache();
    bool UploadNormWeight(DeviceBuf& dst, const float* w, uint32_t n);
    bool DownloadBuf(DeviceBuf& b, float* host, uint32_t n);
    bool UploadBuf(DeviceBuf& b, const float* host, uint32_t n);
    bool BeginFusedLayer();
    bool EndFusedLayer();
    uint32_t WeightOversize() const { return ww_oversize_ ? 1u : 0u; }
    uint64_t LayerSubmits() const { return layer_submits_; }
    uint64_t OpSubmits() const { return op_submits_; }

    VulkanDeviceInfo GetDeviceInfo() const { return device_info_; }
    bool IsAMDDevice() const { return device_info_.vendor_id == 0x1002; }
    bool IsNvidiaDevice() const { return device_info_.vendor_id == 0x10DE; }
    
    bool AllocateBuffer(size_t size, uint32_t& buffer_idx, size_t& memory_size);
    bool AllocateBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory);
    bool CopyBufferToHost(uint32_t buffer_idx, void* host_data, size_t size);
    bool CopyBufferToHost(VkBuffer device_buffer, void* host_data, size_t size);
    bool CopyHostToBuffer(void* host_data, uint32_t buffer_idx, size_t size);
    bool CopyHostToBuffer(void* host_data, VkBuffer device_buffer, size_t size);
    
    // Staging buffer creation for async upload (CPU pointer -> VkBuffer)
    VkBuffer CreateStagingBuffer(const void* host_data, size_t size);
    
    // KV Cache management for autoregressive inference
    bool AllocateKVCache(uint32_t num_layers, uint32_t max_seq_len, uint32_t head_dim);
    bool AppendToKVCache(uint32_t layer_idx, const float* k_new, const float* v_new, uint32_t token_pos);
    bool GetKVCacheSlice(uint32_t layer_idx, uint32_t start_pos, uint32_t end_pos, float* k_out, float* v_out);
    void ClearKVCache();
    bool IsKVCacheAllocated() const { return kv_cache_allocated_; }
    
    // Command buffer & synchronization utilities
    bool ExecuteSingleTimeCommands(std::function<void(VkCommandBuffer)> record_func);
    bool ExecuteCommandBuffer(VkCommandBuffer cmd_buffer);
    
    // High-performance async execution
    VkCommandBuffer AcquireAsyncCommandBuffer();
    bool SubmitAsyncCommandBuffer(VkCommandBuffer cmd_buffer);
    bool FlushAsyncCommands();  // Wait for all pending async operations
    bool CheckAsyncCompletion(VkCommandBuffer cmd_buffer);  // Non-blocking check
    
    // Descriptor set management
    bool CreateDescriptorSetLayout(uint32_t binding_count, VkDescriptorSetLayout& layout);
    bool AllocateDescriptorSet(VkDescriptorSetLayout layout, VkDescriptorSet& descriptor_set);
    bool UpdateDescriptorSet(VkDescriptorSet descriptor_set, uint32_t binding, VkBuffer buffer, size_t buffer_size);
    
    // Scalar CPU implementations (no GPU)
    bool ExecuteMatMul(const float* input_a, const float* input_b, 
                       float* output, uint32_t m, uint32_t k, uint32_t n);
    bool ExecuteAttention(const float* queries, const float* keys, const float* values,
                         float* output, uint32_t seq_len, uint32_t head_dim);
    bool ExecuteRoPE(float* embeddings, uint32_t dim, uint32_t seq_pos, uint32_t rotation_dim);
    bool ExecuteRMSNorm(float* data, uint32_t size, float epsilon = 1e-5f);
    bool ExecuteSiLU(float* data, uint32_t size);
    bool ExecuteSoftmax(float* data, uint32_t size);
    bool ExecuteDequantize(const uint8_t* quantized, float* output,
                           uint32_t elements, const std::string& quant_type);
    
    void Cleanup();

private:
    bool CreateInstance();
    bool SelectPhysicalDevice();
    bool CreateLogicalDevice();
    std::string solo_needle_;
    bool CreateCommandPool();
    bool LoadSPIRVCode(const std::string& path, std::vector<uint32_t>& code);
    uint32_t FindMemoryType(uint32_t type_filter, VkMemoryPropertyFlags properties);

    VkInstance instance_ = nullptr;
    VkPhysicalDevice physical_device_ = nullptr;
    VkDevice device_ = nullptr;
    VkQueue compute_queue_ = nullptr;
    VkQueue transfer_queue_ = nullptr; // same family index 1 when available
    bool dual_queue_ = false;
    VkCommandPool command_pool_ = nullptr;
    VkDescriptorPool descriptor_pool_ = nullptr;

    // Async command buffer pooling for high-performance batching
    std::vector<CommandBufferPool> command_buffer_pool_;
    std::queue<size_t> available_buffer_indices_;

    // Permanent descriptor system for MatMul (avoid per-dispatch allocation overhead)
    VkDescriptorSetLayout matmul_descriptor_set_layout_ = nullptr;
    VkDescriptorPool matmul_descriptor_pool_ = nullptr;

    // KV Cache for autoregressive inference
    std::vector<std::pair<VkBuffer, VkDeviceMemory>> kv_cache_buffers_; // 2 per layer (K, V)
    uint32_t kv_cache_num_layers_ = 0;
    uint32_t kv_cache_max_seq_len_ = 0;
    uint32_t kv_cache_head_dim_ = 0;
    bool kv_cache_allocated_ = false;
    
    // Persistent staging buffer for optimized host-to-device transfers
    VkBuffer staging_buffer_ = nullptr;
    VkDeviceMemory staging_memory_ = nullptr;
    size_t staging_buffer_size_ = 0;

    // GEMV pipeline cache
    VkPipeline gemv_pipeline_ = nullptr;
    VkPipelineLayout gemv_pipeline_layout_ = nullptr;
    VkDescriptorSetLayout gemv_ds_layout_ = nullptr;
    VkDescriptorPool gemv_desc_pool_ = nullptr;
    VkDescriptorSet gemv_ds_ = nullptr;
    VkDescriptorSet gemv_ds_arr_[8]{};
    uint32_t gemv_ds_n_ = 0;
    uint32_t gemv_ds_cursor_ = 0;
    VkCommandBuffer fused_cmd_ = nullptr;
    VkCommandBuffer fused_pool_[4]{};
    VkFence fused_fence_[4]{};
    uint32_t fused_pool_i_ = 0;
    uint32_t fused_cmd_idx_ = 0;
    bool fused_pool_ready_ = false;
    uint64_t fused_cb_allocs_ = 0;
    uint64_t fused_cb_reuses_ = 0;
    uint64_t xfer_records_ = 0;
    uint64_t xfer_submits_ = 0;
    uint32_t gemv_local_size_ = 64;
    bool kernel_tune_ok_ = false;
    bool EnsureFusedPool();
    bool SubmitFusedPool(VkCommandBuffer cmd, uint32_t idx);
    void ReleaseFusedPool();
    bool TuneFromDevice();
    uint64_t layer_submits_ = 0;
    uint64_t op_submits_ = 0;
    bool gemv_pipeline_created_ = false;
    VkPipeline q4k_pipe_ = nullptr;
    VkPipeline q4k_fused_pipe_ = nullptr;
    uint64_t q4k_fused_ops_ = 0;
    VkPipeline q6k_pipe_ = nullptr;
    VkPipeline q5k_pipe_ = nullptr;
    VkPipeline q3k_pipe_ = nullptr;
    VkPipeline q2k_pipe_ = nullptr;
    VkPipeline q8_pipe_ = nullptr;
    uint64_t q4k_packed_ops_ = 0;
    uint64_t q6k_packed_ops_ = 0;
    uint64_t q5k_packed_ops_ = 0;
    uint64_t q3k_packed_ops_ = 0;
    uint64_t q2k_packed_ops_ = 0;
    uint64_t q8_packed_ops_ = 0;
    bool EnsureQ4kPipeline();
    bool EnsureQ4kFusedPipeline();
    bool EnsureQ6kPipeline();
    bool EnsureQ5kPipeline();
    bool EnsureQ3kPipeline();
    bool EnsureQ2kPipeline();
    bool EnsureQ8Pipeline();
    bool CreateGemvPipe(const char* spvName, VkPipeline& pipe);
    bool SelectPackedPipe(int ggmlType, VkPipeline& pipe, uint64_t*& ops);
    bool BindGemvStorage(VkBuffer wbuf, size_t wbytes, VkBuffer inb, size_t inBytes,
                         VkBuffer outb, size_t outBytes, VkPipeline pipe,
                         uint32_t rows, uint32_t cols, uint32_t groups);
    uint64_t gemv_desc_allocs_ = 0;
    uint64_t gemv_desc_reuses_ = 0;
    uint64_t gemv_attempts_ = 0;
    uint64_t gemv_success_ = 0;
    uint64_t gemv_weight_uploads_ = 0;
    uint64_t gemv_weight_hits_ = 0;
    uint64_t gemv_pin_evicts_ = 0;
    uint64_t gemv_resident_bytes_ = 0;

    struct GemvResidentWeight {
        VkBuffer buffer = nullptr;
        VkDeviceMemory memory = nullptr;
        size_t bytes = 0;
        uint32_t rows = 0;
        uint32_t cols = 0;
        uint64_t lastUse = 0;
        uintptr_t contentFp = 0;
    };
    std::unordered_map<uint64_t, GemvResidentWeight> gemv_weight_cache_;
    uint64_t gemv_pin_clock_ = 0;
    bool EnsurePinnedPackedWeight(const void* packed, size_t bytes,
                                  uint32_t rows, uint32_t cols, VkBuffer& outDev,
                                  uint64_t pinKey = 0);

    // Bounded weight window (STREAMER_GPU_WEIGHT_WINDOW_001)
    static constexpr uint32_t kWwMaxSlots = 128;
    struct WeightSlot {
        DeviceBuf device{};
        VkBuffer staging = nullptr;
        VkDeviceMemory stagingMem = nullptr;
        void* stagingMap = nullptr;
        VkFence fence = nullptr;       // sync path / legacy
        VkFence uploadFence = nullptr;
        VkFence computeFence = nullptr;
        VkCommandBuffer uploadCmd = nullptr;
        VkCommandBuffer computeCmd = nullptr;
        bool busy = false;
        bool uploadPending = false;
        bool computePending = false;
        bool hasContent = false;
        bool overlapArmed = false;
        uintptr_t contentKey = 0;
        size_t contentBytes = 0;
        uint64_t overlapT0Us = 0;
    };
    WeightSlot ww_slots_[kWwMaxSlots]{};
    uint32_t ww_slot_count_ = 0;
    uint32_t ww_cursor_ = 0;
    uint32_t ww_layer_used_ = 0;
    size_t ww_slot_bytes_ = 0;
    size_t ww_budget_bytes_ = 0;
    // Sticky floor from SetPinResidentBudget — EnsureWeightWindow must not shrink below.
    size_t ww_pin_budget_floor_ = 0;
    bool ww_active_ = false;
    bool ww_init_done_ = false;
    bool ww_prefetch_ = false;
    bool ww_slots_auto_ = true;
    size_t ww_usable_budget_ = 0;
    size_t ww_arena_reserve_ = 0;
    size_t ww_device_heap_ = 0;
    uint64_t ww_stream_bytes_total_ = 0;
    uint64_t ww_peak_bytes_ = 0;
    uint64_t ww_slot_allocs_ = 0;
    uint64_t ww_slot_reuses_ = 0;
    uint64_t ww_hotpath_wait_idle_ = 0;
    uint64_t ww_hotpath_create_buf_ = 0;
    uint64_t ww_hotpath_destroy_buf_ = 0;
    uint64_t ww_growth_after_init_ = 0;
    uint64_t ww_prefetch_distance_ = 0;
    uint64_t ww_overlap_events_ = 0;
    uint64_t ww_pin_rejects_ = 0;
    uint64_t ww_content_hits_ = 0;
    uint32_t ww_oversize_ = 0;
    static bool WantWeightStream();
    static bool WantWeightPrefetch();
    bool SubmitFence(VkCommandBuffer cmd, VkFence fence);
    bool SubmitFenceOn(VkCommandBuffer cmd, VkFence fence, bool transfer);

    // Reusable host-visible activation buffers (grow-only)
    VkBuffer gemv_in_buf_ = nullptr;
    VkDeviceMemory gemv_in_mem_ = nullptr;
    size_t gemv_in_cap_ = 0;
    uint32_t gemv_in_live_cols_ = 0;
    bool gemv_reuse_in_next_ = false;
    uint64_t gemv_in_reuse_hits_ = 0;
    VkBuffer gemv_out_buf_ = nullptr;
    VkDeviceMemory gemv_out_mem_ = nullptr;
    size_t gemv_out_cap_ = 0;
    // Dedicated Q6 logits weight staging — must NOT touch ww slots / MLA pins.
    VkBuffer q6k_logits_w_buf_ = nullptr;
    VkDeviceMemory q6k_logits_w_mem_ = nullptr;
    size_t q6k_logits_w_cap_ = 0;

    bool EnsureGemvPipeline();
    bool CreateDeviceLocalBuffer(size_t size, VkBuffer& buf, VkDeviceMemory& mem);
    bool CreateHostVisibleBuffer(size_t size, VkBuffer& buf, VkDeviceMemory& mem);
    bool UploadToDeviceLocal(const void* src, size_t size, VkBuffer dst);
    bool EnsureHostIo(size_t inBytes, size_t outBytes);
    void ReleaseGemvResidents();
    void ReleaseForwardArena();
    bool LoadComputePipeline(const char* spvName, uint32_t nBind, uint32_t pcBytes,
                             VkPipeline& pipe, VkPipelineLayout& layout,
                             VkDescriptorSetLayout& dsLayout, VkDescriptorPool& pool,
                             VkDescriptorSet& ds);
    bool SubmitOne(VkCommandBuffer cmd);
    bool DownloadDeviceLocal(VkBuffer src, void* dst, size_t size);
    bool CopyDeviceToDevice(VkBuffer src, VkBuffer dst, size_t size);
    bool RecordCompute(VkPipeline pipe, VkPipelineLayout layout, VkDescriptorSet ds,
                       const void* pc, uint32_t pcBytes, uint32_t groupsX);
    bool FusedBarrier();
    bool FlushFusedRestart();
    VkDescriptorSet NextGemvDs();
    bool RecordCopy(VkBuffer src, VkBuffer dst, VkDeviceSize srcOff, VkDeviceSize dstOff,
                    VkDeviceSize bytes);

    // Forward-resident arena + pipelines
    DeviceBuf fwd_hidden_{}, fwd_residual_{}, fwd_normed_{};
    DeviceBuf fwd_q_{}, fwd_k_{}, fwd_v_{}, fwd_attn_{};
    DeviceBuf fwd_gate_{}, fwd_up_{}, fwd_down_{}, fwd_ffn_act_{};
    DeviceBuf fwd_attn_w_{}, fwd_ffn_w_{};
    DeviceBuf fwd_k_cache_{}, fwd_v_cache_{};
    uint32_t fwd_hidden_n_ = 0, fwd_inter_n_ = 0, fwd_kv_dim_ = 0, fwd_max_seq_ = 0;
    uint32_t fwd_n_layers_ = 0;
    bool fwd_arena_ready_ = false;

    VkPipeline rms_pipe_ = nullptr; VkPipelineLayout rms_layout_ = nullptr;
    VkDescriptorSetLayout rms_dsl_ = nullptr; VkDescriptorPool rms_pool_ = nullptr;
    VkDescriptorSet rms_ds_ = nullptr;
    VkDescriptorSet rms_ds2_ = nullptr;
    uint32_t rms_use_ = 0;
    VkPipeline add_pipe_ = nullptr; VkPipelineLayout add_layout_ = nullptr;
    VkDescriptorSetLayout add_dsl_ = nullptr; VkDescriptorPool add_pool_ = nullptr;
    VkDescriptorSet add_ds_ = nullptr;
    VkDescriptorSet add_ds2_ = nullptr;
    uint32_t add_use_ = 0;
    VkPipeline rope_pipe_ = nullptr; VkPipelineLayout rope_layout_ = nullptr;
    VkDescriptorSetLayout rope_dsl_ = nullptr; VkDescriptorPool rope_pool_ = nullptr;
    VkDescriptorSet rope_ds_ = nullptr;
    VkPipeline attn_pipe_ = nullptr; VkPipelineLayout attn_layout_ = nullptr;
    VkDescriptorSetLayout attn_dsl_ = nullptr; VkDescriptorPool attn_pool_ = nullptr;
    VkDescriptorSet attn_ds_ = nullptr;
    VkPipeline swiglu_pipe_ = nullptr; VkPipelineLayout swiglu_layout_ = nullptr;
    VkDescriptorSetLayout swiglu_dsl_ = nullptr; VkDescriptorPool swiglu_pool_ = nullptr;
    VkDescriptorSet swiglu_ds_ = nullptr;

public:
    uint64_t GemvDescriptorAllocations() const { return gemv_desc_allocs_; }
    uint64_t GemvDescriptorReuses() const { return gemv_desc_reuses_; }
    uint64_t GemvAttempts() const { return gemv_attempts_; }
    uint64_t GemvSuccess() const { return gemv_success_; }
    uint64_t GemvWeightUploads() const { return gemv_weight_uploads_; }
    uint64_t GemvWeightHits() const { return gemv_weight_hits_; }
    uint64_t GemvResidentBytes() const {
        return ww_active_ ? ww_peak_bytes_ : gemv_resident_bytes_;
    }

private:
    VulkanDeviceInfo device_info_;
    std::unordered_map<std::string, ComputeShader> shaders_;
    std::vector<VulkanTensor> uploaded_tensors_;
    std::vector<std::pair<VkBuffer, VkDeviceMemory>> allocated_buffers_;
    std::unordered_map<std::string, VkDescriptorSetLayout> descriptor_layouts_;
    
    // Helper methods for command buffer pool management
    void InitializeCommandBufferPool(uint32_t pool_size = 4);
    void CleanupCommandBufferPool();
    
    // Helper for offset-based buffer copies (KV cache updates)
    bool CopyHostToBufferOffset(const void* host_data, VkBuffer device_buffer, size_t offset, size_t size);
    bool CopyBufferToHostOffset(VkBuffer device_buffer, size_t offset, void* host_data, size_t size);
    
    // Helper for creating staging buffers (reduces code duplication)
    bool CreateStagingBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory);
};

} // namespace CPUInference
