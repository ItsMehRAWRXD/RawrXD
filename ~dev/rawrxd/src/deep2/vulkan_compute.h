#pragma once
// ============================================================================
// vulkan_compute.h — Batch 9 real Vulkan device/runtime surface
// No synthetic success returns. Unsupported operations fail closed.
// Requires only the Vulkan SDK already used by RawrXD.
// ============================================================================
#include <vulkan/vulkan.h>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {

enum class GpuWorkKind : uint32_t {
    Unknown = 0,
    ModelCompute = 1,
    ModelTransfer = 2,
    CapabilityProbe = 3,
};

struct GpuWorkInterval {
    uint64_t epoch = 0;
    uint64_t hostSubmitNs = 0;
    uint64_t hostCompleteNs = 0;
    uint64_t gpuStartNs = 0;
    uint64_t gpuEndNs = 0;
    uint64_t bytes = 0;
    uint32_t deviceOrdinal = 0;
    GpuWorkKind kind = GpuWorkKind::Unknown;
    bool calibrated = false;

    uint64_t calibratedDurationNs() const {
        return calibrated && gpuEndNs >= gpuStartNs ? gpuEndNs - gpuStartNs : 0;
    }
};

struct VulkanPhysicalInfo {
    uint32_t ordinal = 0;
    uint32_t vendorId = 0;
    uint32_t deviceId = 0;
    uint32_t apiVersion = 0;
    uint64_t deviceLocalBytes = 0;
    bool discrete = false;
    bool compute = false;
    std::string name;
};

struct GpuWeightView {
    const void* data = nullptr;
    size_t bytes = 0;
    int type = 0;
    uint32_t rows = 0;
    uint32_t cols = 0;
    uint64_t key = 0;

    bool valid() const noexcept {
        return data && bytes && rows && cols;
    }
};

class VulkanCompute {
public:
    struct DeviceBuf {
        VkBuffer buffer = VK_NULL_HANDLE;
        VkDeviceMemory memory = VK_NULL_HANDLE;
        VkDeviceSize size = 0;
        VkMemoryPropertyFlags memoryFlags = 0;
        uint64_t id = 0;
        explicit operator bool() const noexcept {
            return buffer != VK_NULL_HANDLE && memory != VK_NULL_HANDLE && size != 0;
        }
    };

    struct MaterialTicket {
        DeviceBuf staging{};
        DeviceBuf target{};
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
        VkQueryPool query = VK_NULL_HANDLE;
        uint64_t hostSubmitNs = 0;
        uint64_t epoch = 0;
        uint64_t bytes = 0;
        bool submitted = false;
    };

    explicit VulkanCompute(uint32_t physicalOrdinal = 0);
    ~VulkanCompute();

    VulkanCompute(const VulkanCompute&) = delete;
    VulkanCompute& operator=(const VulkanCompute&) = delete;

    static std::vector<VulkanPhysicalInfo> EnumeratePhysicalDevices();
    static size_t ForwardArenaReserveBytes(
        uint32_t hidden, uint32_t intermediate,
        uint32_t heads, uint32_t kvHeads, uint32_t headDim,
        uint32_t maxSeq, uint32_t layers);
    static size_t ForwardArenaReserveBytes(int deviceOrdinal);

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

    bool SubmitMaterialUploadAsync(const void* src, size_t bytes,
                                   uint64_t epoch, MaterialTicket& ticket);
    bool WaitMaterialUpload(MaterialTicket& ticket, GpuWorkInterval* interval = nullptr);

    // Useful cross-device overlap primitive: asynchronously upload a real model
    // weight, then adopt that exact device buffer into the normal GEMV cache.
    bool SubmitWeightPrimeAsync(const void* src, size_t bytes, int type,
                                uint64_t cacheKey, uint64_t epoch,
                                MaterialTicket& ticket);
    bool CommitWeightPrime(MaterialTicket& ticket, int type,
                           uint64_t cacheKey,
                           GpuWorkInterval* interval = nullptr);

    std::vector<GpuWorkInterval> RecentIntervals(uint64_t epoch) const;
    GpuWorkInterval LastInterval() const;
    bool calibratedTimestampsAvailable() const noexcept { return calibratedAvailable_; }

    bool EnsureForwardArena(
        uint32_t hidden, uint32_t intermediate,
        uint32_t heads, uint32_t kvHeads, uint32_t headDim,
        uint32_t maxSeq, uint32_t layers);
    bool ApplyWeightWindowPolicy(size_t maxWeightBytes, size_t budgetBytes,
                                 uint32_t slotOverride, size_t arenaBytes);

    bool UploadHidden(const float* src, uint32_t count);
    bool DownloadHidden(float* dst, uint32_t count);
    bool CopyArenaHiddenTo(VulkanCompute& dst, uint32_t count);
    bool LastCrossDeviceCopyUsedHost() const noexcept { return lastCrossDeviceCopyUsedHost_; }

    bool UploadNormWeight(DeviceBuf& dst, const float* src, size_t count);

    bool BeginFusedLayer();
    bool EndFusedLayer();
    bool FlushWeightComputes();
    void ResetWeightWindowLayerCursor() {}

    bool DispatchRmsNorm(DeviceBuf& input, DeviceBuf& weight, DeviceBuf& output,
                         uint32_t n, float eps);
    bool DispatchResidualAdd(DeviceBuf& a, DeviceBuf& b, DeviceBuf& out, uint32_t n);
    bool DispatchSwiGLU(DeviceBuf& gate, DeviceBuf& up, DeviceBuf& out, uint32_t n);
    bool DispatchRope(DeviceBuf& q, DeviceBuf& k,
                      uint32_t headDim, uint32_t heads, uint32_t kvHeads,
                      uint32_t pos, float theta);
    bool AppendKV(DeviceBuf& k, DeviceBuf& v, uint32_t kvDim,
                  uint32_t pos, uint32_t layer);
    bool DispatchAttnDecode(DeviceBuf& q, DeviceBuf& kCache, DeviceBuf& vCache,
                            DeviceBuf& out, uint32_t headDim,
                            uint32_t heads, uint32_t kvHeads,
                            uint32_t seqLen, float scale, uint32_t layer);

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

    // Batch 10 generic device math surface used by row-split, MoE and MLA.
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

    bool RunMLAAttentionHost(const float* q,
                             const float* k,
                             const float* v,
                             float* output,
                             uint32_t heads,
                             uint32_t keyLen,
                             uint32_t valueLen,
                             uint32_t layer,
                             uint32_t pos,
                             uint32_t layers,
                             uint32_t maxSeq,
                             float scale,
                             uint64_t epoch);
    void ResetMLACache();

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

private:
    struct WeightCacheEntry {
        DeviceBuf buffer{};
        size_t bytes = 0;
        int type = 0;
    };
    struct PrefetchEntry {
        DeviceBuf buffer{};
        size_t bytes = 0;
        int type = 0;
        bool valid = false;
    };

    struct OpsPush {
        uint32_t op = 0;
        uint32_t n = 0;
        uint32_t p0 = 0;
        uint32_t p1 = 0;
        uint32_t p2 = 0;
        uint32_t p3 = 0;
        uint32_t p4 = 0;
        uint32_t p5 = 0;
        float f0 = 0.0f;
        float f1 = 0.0f;
    };
    struct QPush {
        uint32_t type = 0;
        uint32_t rows = 0;
        uint32_t cols = 0;
        uint32_t weightBytes = 0;
    };

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

    uint32_t findMemoryType(uint32_t bits, VkMemoryPropertyFlags required) const;
    static uint64_t nowNs();
    bool finalizeInterval(VkQueryPool query, uint64_t hostSubmitNs,
                          uint64_t hostCompleteNs, uint64_t epoch,
                          uint64_t bytes, GpuWorkKind kind,
                          GpuWorkInterval& out);
    bool calibrateTick(uint64_t deviceTick, uint64_t& hostNs) const;
    void recordInterval(const GpuWorkInterval& interval);
    std::string shaderPath(const char* file) const;

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

    DeviceBuf arenaHidden_{}, arenaAttnW_{}, arenaFfnW_{}, arenaNormed_{};
    DeviceBuf arenaQ_{}, arenaK_{}, arenaV_{}, arenaAttn_{}, arenaResidual_{};
    DeviceBuf arenaGate_{}, arenaUp_{}, arenaFFNAct_{}, arenaDown_{};
    DeviceBuf arenaKCache_{}, arenaVCache_{};

    size_t weightBudgetBytes_ = 0;
    size_t weightCacheBytes_ = 0;
    std::unordered_map<uint64_t, WeightCacheEntry> weightCache_;
    std::vector<PrefetchEntry> prefetch_;

    std::vector<DeviceBuf> scratch_;

    DeviceBuf mlaKCache_{};
    DeviceBuf mlaVCache_{};
    uint32_t mlaCacheHeads_ = 0;
    uint32_t mlaCacheKeyLen_ = 0;
    uint32_t mlaCacheValueLen_ = 0;
    uint32_t mlaCacheLayers_ = 0;
    uint32_t mlaCacheCapacity_ = 0;
    uint32_t mlaCacheMaxSeq_ = 0;

    uint64_t gemvSuccess_ = 0;
    uint64_t weightUploads_ = 0;
    uint64_t weightHits_ = 0;
    bool lastCrossDeviceCopyUsedHost_ = false;

    mutable std::recursive_mutex apiMu_;
    mutable std::mutex intervalMu_;
    std::deque<GpuWorkInterval> intervals_;
};

} // namespace Deep2

namespace CPUInference {
using VulkanCompute = Deep2::VulkanCompute;
}
