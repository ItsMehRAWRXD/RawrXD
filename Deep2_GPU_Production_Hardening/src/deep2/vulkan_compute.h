// ============================================================================
// vulkan_compute.h — Deep2 GPU Production Hardening (P0-A, P0-B, P1)
// Adds GpuCounters with real GPU timestamp timing, batched submission support,
// and total device-local weight allocation tracking.
// ============================================================================

#pragma once
#include <vulkan/vulkan.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {

// ============================================================================
// GPU Counters — Real device timing + host breakdown (P0-A)
// ============================================================================
struct GpuCounters {
    // Device-local weight allocation (total, not just managed cache)
    uint64_t total_device_weight_bytes = 0;
    uint64_t total_device_weight_peak = 0;

    // Managed cache subsystem (existing)
    uint64_t weight_cache_hits = 0;
    uint64_t weight_cache_misses = 0;
    uint64_t weight_cache_evictions = 0;
    uint64_t weight_prefetches = 0;
    uint64_t weight_prefetch_hits = 0;
    uint64_t device_bytes_live = 0;
    uint64_t device_bytes_peak = 0;

    // Submission and timing
    uint64_t submits = 0;
    uint64_t waits = 0;

    // Real GPU execution time (device timestamps, nanoseconds)
    double gpu_ms = 0;            // Σ(gpuEndNs - gpuStartNs) / 1e6
    double host_wait_ms = 0;      // Σ(hostCompleteNs - hostSubmitNs) / 1e6
    double submit_cpu_ms = 0;     // CPU time in vkQueueSubmit

    // Legacy alias (DEPRECATED: equals host_wait_ms + submit_cpu_ms)
    double kernel_ms = 0;
    double wait_ms = 0;
    double submit_ms = 0;

    // Buffer/descriptor accounting
    uint64_t buffer_allocations = 0;
    uint64_t descriptor_allocations = 0;
    uint64_t descriptor_reuses = 0;
    uint64_t descriptor_alloc_attempts = 0;
    uint64_t descriptor_alloc_failures = 0;
    uint64_t descriptor_pool_creates = 0;
    uint64_t descriptor_pool_resets = 0;
    uint64_t descriptor_sets_in_flight = 0;
    uint64_t descriptor_sets_peak = 0;

    // Transfer queue
    uint64_t upload_bytes = 0;
    uint64_t download_bytes = 0;

    // Calibration
    bool calibrated_available = false;

    void reset() { *this = {}; }
};

// ============================================================================
// Batch submission support (P0-B)
// ============================================================================
struct BatchSubmitContext {
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    VkQueryPool query = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;
    uint64_t hostSubmitNs = 0;
    uint64_t epoch = 0;
    uint64_t bytes = 0;
    GpuWorkKind kind = GpuWorkKind::ModelCompute;
    bool active = false;
    uint32_t recordedDispatches = 0;
};

struct DescriptorKey { /* ... existing ... */ };
struct DescriptorKeyHash { /* ... existing ... */ };

enum class GpuWorkKind : uint32_t {
    Unknown = 0,
    ModelCompute = 1,
    ModelTransfer = 2,
    CapabilityProbe = 3,
};

struct GpuWorkInterval { /* ... existing ... */ };

struct VulkanPhysicalInfo { /* ... existing ... */ };

struct GpuWeightView { /* ... existing ... */ };

class VulkanCompute {
public:
    struct DeviceBuf { /* ... existing ... */ };
    struct MaterialTicket { /* ... existing ... */ };

    explicit VulkanCompute(uint32_t physicalOrdinal = 0);
    ~VulkanCompute();

    VulkanCompute(const VulkanCompute&) = delete;
    VulkanCompute& operator=(const VulkanCompute&) = delete;

    static std::vector<VulkanPhysicalInfo> EnumeratePhysicalDevices();

    // ... existing forward arena methods ...

    bool initialize();
    bool Initialize() { return initialize(); }
    void cleanup();

    bool initialized() const noexcept { return initialized_; }
    bool computeReady() const noexcept { return opsPipeline_ != VK_NULL_HANDLE; }
    bool quantComputeReady() const noexcept { return qPipeline_ != VK_NULL_HANDLE; }
    const VulkanPhysicalInfo& physicalInfo() const noexcept { return info_; }
    uint64_t deviceLocalBytes() const noexcept { return info_.deviceLocalBytes; }

    void SetWorkEpoch(uint64_t epoch) noexcept { workEpoch_ = epoch; }
    uint64_t WorkEpoch() const noexcept { return workEpoch_; }

    bool RunComputeProbe(size_t elements, float scale, float bias,
                         std::vector<float>* out = nullptr);

    // ============================================================================
    // Material upload (async + batch)
    // ============================================================================
    bool SubmitMaterialUploadAsync(const void* src, size_t bytes,
                                   uint64_t epoch, MaterialTicket& ticket);
    bool WaitMaterialUpload(MaterialTicket& ticket, GpuWorkInterval* interval = nullptr);

    bool SubmitWeightPrimeAsync(const void* src, size_t bytes, int type,
                                uint64_t cacheKey, uint64_t epoch,
                                MaterialTicket& ticket);
    bool CommitWeightPrime(MaterialTicket& ticket, int type,
                           uint64_t cacheKey,
                           GpuWorkInterval* interval = nullptr);

    // ============================================================================
    // Batch submission API (P0-B)
    // ============================================================================
    bool BeginBatch(GpuWorkKind kind = GpuWorkKind::ModelCompute,
                    uint64_t epoch = 0);
    bool EndBatch(GpuWorkInterval* interval = nullptr);
    bool BatchActive() const noexcept { return batchActive_; }
    uint32_t BatchDispatchCount() const noexcept { return batchDispatchCount_; }

    // Dispatch into active batch (records into batch command buffer)
    bool DispatchOpsBatched(DeviceBuf& a, DeviceBuf& b, DeviceBuf& c, DeviceBuf& d,
                            const OpsPush& push, uint32_t groupsX);
    bool DispatchQuantBatched(DeviceBuf& weights, DeviceBuf& input, DeviceBuf& output,
                              const QPush& push);

    // Legacy single-dispatch (still available, creates own batch internally)
    std::vector<GpuWorkInterval> RecentIntervals(uint64_t epoch) const;
    GpuWorkInterval LastInterval() const;
    bool calibratedTimestampsAvailable() const noexcept { return calibratedAvailable_; }

    // Flight recorder counter for GPU dispatches
    std::atomic<uint64_t> gpu_dispatch_count_{0};
    uint64_t get_dispatch_count() const noexcept { return gpu_dispatch_count_.load(std::memory_order_relaxed); }
    void reset_dispatch_count() noexcept { gpu_dispatch_count_.store(0, std::memory_order_relaxed); }
    void increment_dispatch_count(uint64_t n = 1) noexcept { gpu_dispatch_count_.fetch_add(n, std::memory_order_relaxed); }

    // ============================================================================
    // Counters accessor (P0-A, P1)
    // ============================================================================
    const GpuCounters& GetGpuCounters() const noexcept { return gpu_counters_; }
    GpuCounters& GetGpuCountersMutable() noexcept { return gpu_counters_; }

    // ============================================================================
    // Existing dispatch methods (unchanged public API)
    // ============================================================================
    bool ApplyWeightWindowPolicy(size_t maxWeightBytes, size_t budgetBytes,
                                 uint32_t slotOverride, size_t arenaBytes);
    bool ReserveDecodeScratch();

    bool UploadHidden(const float* src, uint32_t count);
    bool DownloadHidden(float* dst, uint32_t count);
    bool CopyArenaHiddenTo(VulkanCompute& dst, uint32_t count);
    bool LastCrossDeviceCopyUsedHost() const noexcept { return lastCrossDeviceCopyUsedHost_; }

    bool UploadNormWeight(DeviceBuf& dst, const float* src, size_t count);

    // Fused layer (existing, now uses batch internally)
    bool BeginFusedLayer();
    bool EndFusedLayer();
    bool FusedRecording() const noexcept { return fused_; }
    bool FlushWeightComputes();

    bool DispatchRmsNorm(DeviceBuf& input, DeviceBuf& weight, DeviceBuf& output,
                         uint32_t n, float eps);
    bool DispatchResidualAdd(DeviceBuf& a, DeviceBuf& b, DeviceBuf& out, uint32_t n);
    bool DispatchSwiGLU(DeviceBuf& gate, DeviceBuf& up, DeviceBuf& out, uint32_t n);
    bool DispatchRope(DeviceBuf& q, DeviceBuf& k,
                      uint32_t headDim, uint32_t heads, uint32_t kvHeads,
                      uint32_t pos, float theta);

    bool AppendKV(DeviceBuf& k, DeviceBuf& v, uint32_t kvDim,
                  uint32_t pos, uint32_t layer);

    bool DispatchGemvDevice(const float* weights, uint64_t key,
                            DeviceBuf& input, DeviceBuf& output,
                            uint32_t rows, uint32_t cols);
    bool DispatchGemvQuant(int type, const void* weights, size_t weightBytes,
                           DeviceBuf& input, DeviceBuf& output,
                           uint32_t rows, uint32_t cols);

    bool PrefetchWeight(const void* weights, size_t bytes, uint32_t& slot);
    bool SubmitGemvPrefetch(uint32_t slot, DeviceBuf& input, DeviceBuf& output,
                            uint32_t rows, uint32_t cols,
                            size_t packedBytes = 0, int quantType = 0);
    bool WaitWeightCompute(uint32_t slot);
    bool WeightStreamActive() const noexcept { return weightBudgetBytes_ != 0; }
    bool WeightPrefetchActive() const noexcept;

    // Batch 10 generic device math surface
    bool EnsureScratch(unsigned index, size_t floatCount);
    DeviceBuf& Scratch(unsigned index);
    bool UploadVector(DeviceBuf& dst, const float* src, size_t count);
    bool DownloadVector(const DeviceBuf& src, float* dst, size_t count);
    bool CopyVector(DeviceBuf& src, DeviceBuf& dst, size_t count,
                    size_t srcFloatOffset = 0, size_t dstFloatOffset = 0);
    bool DispatchWeight(const GpuWeightView& weight,
                        DeviceBuf& input, DeviceBuf& output);

    bool RunExpertFFN(const GpuWeightView& gate,
                      const GpuWeightView& up,
                      const GpuWeightView& down,
                      const float* input, float* output,
                      uint32_t hidden, uint32_t intermediate,
                      uint64_t epoch);

    // ... existing MLA, spec, batch methods ...

    // ============================================================================
    // Accessors
    // ============================================================================
    DeviceBuf& ArenaHidden()   { return arenaHidden_; }
    DeviceBuf& ArenaAttnW()    { return arenaAttnW_; }
    DeviceBuf& ArenaFfnW()     { return arenaFfnW_; }
    DeviceBuf& ArenaNormed()   { return arenaNormed_; }
    DeviceBuf& ArenaQ()        { return arenaQ_; }
    DeviceBuf& ArenaK()        { return arenaK_; }
    DeviceBuf& ArenaV()        { return arenaV_; }
    DeviceBuf& ArenaAttn()     { return arenaAttn_; }
    DeviceBuf& ArenaResidual() { return arenaResidual_; }
    DeviceBuf& ArenaGate()     { return arenaGate_; }
    DeviceBuf& ArenaUp()       { return arenaUp_; }
    DeviceBuf& ArenaFFNAct()   { return arenaFFNAct_; }
    DeviceBuf& ArenaDown()     { return arenaDown_; }
    DeviceBuf& ArenaKCache()   { return arenaKCache_; }
    DeviceBuf& ArenaVCache()   { return arenaVCache_; }

    uint64_t GemvSuccessCount() const noexcept { return gemvSuccess_; }
    uint64_t WeightUploadCount() const noexcept { return weightUploads_; }
    uint64_t WeightHitCount() const noexcept { return weightHits_; }

    // ... rest of existing public methods ...

    // ============================================================================
    // Private implementation
    // ============================================================================
private:
    struct WeightCacheEntry { /* ... existing ... */ };
    struct PrefetchEntry { /* ... existing ... */ };
    struct OpsPush { /* ... existing ... */ };
    struct QPush { /* ... existing ... */ };

    // Batch state (P0-B)
    bool batchActive_ = false;
    BatchSubmitContext batch_{};
    uint32_t batchDispatchCount_ = 0;

    // Counters (P0-A, P1)
    GpuCounters gpu_counters_;

    // Pipeline cache (P1)
    VkPipelineCache pipelineCache_ = VK_NULL_HANDLE;

    // ... existing private members and methods ...
    bool createInstance();
    bool selectPhysical();
    bool createDevice();
    bool createCommandPool();
    bool createDescriptorSystems();
    bool createPipelines();
    bool createPipelineFromFile(const std::string& file,
                                VkDescriptorSetLayout layout,
                                uint32_t pushBytes,
                                VkPipelineLayout& pipelineLayout,
                                VkPipeline& pipeline);

    bool createBuffer(VkDeviceSize bytes, VkBufferUsageFlags usage,
                      VkMemoryPropertyFlags required,
                      DeviceBuf& out);
    void destroyBuffer(DeviceBuf& b);
    bool uploadToBuffer(DeviceBuf& dst, const void* src, size_t bytes);
    bool downloadFromBuffer(const DeviceBuf& src, void* dst, size_t bytes);

    bool beginCommand(VkCommandBuffer& cmd, VkQueryPool& query, bool timestamped);
    bool endSubmitWait(VkCommandBuffer cmd, VkQueryPool query,
                       GpuWorkKind kind, uint64_t bytes, uint64_t epoch,
                       GpuWorkInterval* interval = nullptr);
    bool recordCopy(VkCommandBuffer cmd, const DeviceBuf& src, DeviceBuf& dst,
                    VkDeviceSize bytes, VkDeviceSize srcOffset = 0,
                    VkDeviceSize dstOffset = 0);
    void recordComputeBarrier(VkCommandBuffer cmd);

    bool dispatchOps(DeviceBuf& a, DeviceBuf& b, DeviceBuf& c, DeviceBuf& d,
                     const OpsPush& push, uint32_t groupsX,
                     GpuWorkKind kind = GpuWorkKind::ModelCompute);
    bool dispatchQuant(DeviceBuf& weights, DeviceBuf& input, DeviceBuf& output,
                       const QPush& push);

    bool ensureWeightF32(const float* weights, uint64_t key,
                         size_t bytes, DeviceBuf*& out);
    bool ensureWeightQuant(int type, const void* weights, size_t bytes,
                           DeviceBuf*& out);
    void clearWeightCache();

    // Pipeline cache
    bool createPipelineCache();
    void destroyPipelineCache();

    uint32_t findMemoryType(uint32_t bits, VkMemoryPropertyFlags required) const;
    static uint64_t nowNs();
    bool finalizeInterval(VkQueryPool query, uint64_t hostSubmitNs,
                          uint64_t hostCompleteNs, uint64_t epoch,
                          uint64_t bytes, GpuWorkKind kind,
                          GpuWorkInterval& out);
    bool calibrateTick(uint64_t deviceTick, uint64_t& hostNs) const;

    void recordInterval(const GpuWorkInterval& interval);
    std::string shaderPath(const char* file) const;

    // ... existing private members ...
    uint32_t requestedOrdinal_ = 0;
    VulkanPhysicalInfo info_{};
    bool initialized_ = false;
    uint64_t nextBufferId_ = 1;
    uint64_t workEpoch_ = 0;

    VkInstance instance_ = VK_NULL_HANDLE;
    VkPhysicalDevice physical_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue queue_ = VK_NULL_HANDLE;
    uint32_t queueFamily_ = UINT32_MAX;
    uint32_t transferQueueFamilyIndex_ = UINT32_MAX;
    uint32_t transferQueueIndex_ = 0;
    VkQueue transferQueue_ = VK_NULL_HANDLE;
    VkCommandPool transferCommandPool_ = VK_NULL_HANDLE;
    uint64_t transferQueueSubmits_ = 0;
    bool discoverTransferQueue(VkPhysicalDevice physical,
                               uint32_t computeFamily,
                               uint32_t& transferFamily,
                               uint32_t& transferQueueIndex) const;
    bool createTransferCommandPool();
    uint32_t timestampValidBits_ = 0;
    float timestampPeriodNs_ = 0.0f;

    VkCommandPool commandPool_ = VK_NULL_HANDLE;
    VkDescriptorPool descriptorPool_ = VK_NULL_HANDLE;
    VkDescriptorSetLayout opsSetLayout_ = VK_NULL_HANDLE;
    VkDescriptorSetLayout qSetLayout_ = VK_NULL_HANDLE;
    VkPipelineLayout opsPipelineLayout_ = VK_NULL_HANDLE;
    VkPipelineLayout qPipelineLayout_ = VK_NULL_HANDLE;
    VkPipeline opsPipeline_ = VK_NULL_HANDLE;
    VkPipeline qPipeline_ = VK_NULL_HANDLE;

    bool calibratedAvailable_ = false;
    VkTimeDomainEXT hostTimeDomain_ = VK_TIME_DOMAIN_DEVICE_EXT;
    PFN_vkGetCalibratedTimestampsEXT fpGetCalibrated_ = nullptr;

    bool fused_ = false;
    VkCommandBuffer fusedCmd_ = VK_NULL_HANDLE;
    VkQueryPool fusedQuery_ = VK_NULL_HANDLE;
    uint64_t fusedHostSubmitNs_ = 0;

    uint32_t hidden_ = 0, intermediate_ = 0, heads_ = 0;
    uint32_t kvHeads_ = 0, headDim_ = 0, maxSeq_ = 0, layers_ = 0;
    uint32_t kvDim_ = 0;
    uint32_t kvArenaLayers_ = 0;
    uint32_t kvLayerBase_ = 0;

    DeviceBuf arenaHidden_{}, arenaAttnW_{}, arenaFfnW_{}, arenaNormed_{};
    DeviceBuf arenaQ_{}, arenaK_{}, arenaV_{}, arenaAttn_{}, arenaResidual_{};
    DeviceBuf arenaGate_{}, arenaUp_{}, arenaFFNAct_{}, arenaDown_{};
    DeviceBuf arenaKCache_{}, arenaVCache_{};

    size_t weightBudgetBytes_ = 0;
    size_t weightCacheBytes_ = 0;
    size_t scratchReservedBytes_ = 0;
    bool memoryBudgetAvailable_ = false;
    size_t deviceLocalHeapHeadroom() const;
    bool checkLiveHeapAdmission(size_t bytes) const;
    std::unordered_map<uint64_t, WeightCacheEntry> weightCache_;
    std::vector<PrefetchEntry> prefetch_;

    // ... existing residency/RCU/async state ...

    mutable std::recursive_mutex apiMu_;
    mutable std::mutex intervalMu_;
    std::deque<GpuWorkInterval> intervals_;

    bool evictWeightCacheUntil(size_t incomingBytes);
    bool ensureMappedStaging(bool upload, size_t bytes,
                             DeviceBuf*& buffer, void*& mapped);
    VkDescriptorSet getOpsDescriptor(DeviceBuf& a, DeviceBuf& b,
                                     DeviceBuf& c, DeviceBuf& d);
    VkDescriptorSet getQuantDescriptor(DeviceBuf& weights,
                                       DeviceBuf& input, DeviceBuf& output);
    VkDescriptorSet getQuantDescriptorRange(
        DeviceBuf& w, VkDeviceSize wOffset, VkDeviceSize wRange,
        DeviceBuf& in, DeviceBuf& out);
    bool ensureReusableFusedSubmitObjects();
    bool uploadToBufferRange(DeviceBuf& dst, const void* src, size_t bytes,
                             VkDeviceSize dstOffset);

    uint64_t queueSubmitCount_ = 0;

    VkCommandBuffer reusableFusedCmd_ = VK_NULL_HANDLE;
    VkQueryPool reusableFusedQuery_ = VK_NULL_HANDLE;
    VkFence reusableFusedFence_ = VK_NULL_HANDLE;

    // ... existing Q4K parity state ...

    DeviceBuf uploadStaging_{};
    DeviceBuf downloadStaging_{};
    void* uploadMapped_ = nullptr;
    void* downloadMapped_ = nullptr;
    size_t uploadStagingBytes_ = 0;
    size_t downloadStagingBytes_ = 0;

    std::unordered_map<DescriptorKey, VkDescriptorSet, DescriptorKeyHash>
        opsDescriptorCache_;
    std::unordered_map<DescriptorKey, VkDescriptorSet, DescriptorKeyHash>
        quantDescriptorCache_;
};

} // namespace Deep2

Deep2::VulkanCompute& GetDeep2VulkanCompute();