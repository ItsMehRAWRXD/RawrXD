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

struct DescriptorKey {
    uint64_t a = 0, b = 0, c = 0, d = 0;
    bool operator==(const DescriptorKey& o) const noexcept {
        return a == o.a && b == o.b && c == o.c && d == o.d;
    }
};
struct DescriptorKeyHash {
    size_t operator()(const DescriptorKey& k) const noexcept {
        uint64_t x = k.a;
        x ^= k.b + 0x9E3779B97F4A7C15ull + (x << 6) + (x >> 2);
        x ^= k.c + 0x9E3779B97F4A7C15ull + (x << 6) + (x >> 2);
        x ^= k.d + 0x9E3779B97F4A7C15ull + (x << 6) + (x >> 2);
        return static_cast<size_t>(x);
    }
};

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
    uint8_t deviceUUID[VK_UUID_SIZE] = {};
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
    // ========== Forward arena (Batch9 resident decode) ==========
    // kvLayers=0 sizes K/V caches for ALL model layers (legacy behavior).
    // kvLayers=N sizes them for only the N layers this slot executes in a
    // multi-GPU layer-split plan, reclaiming dead KV VRAM on split slots.
    // SetKvLayerBase maps absolute layer indices onto the sized region:
    // cache slot 0 corresponds to absolute layer `base`.
    bool EnsureForwardArena(
        uint32_t hidden, uint32_t intermediate,
        uint32_t heads, uint32_t kvHeads, uint32_t headDim,
        uint32_t maxSeq, uint32_t layers, uint32_t kvLayers = 0);
    void SetKvLayerBase(uint32_t base) noexcept { kvLayerBase_ = base; }
    uint32_t KvLayerBase() const noexcept { return kvLayerBase_; }
    static size_t ForwardArenaReserveBytes(
        uint32_t hidden, uint32_t intermediate,
        uint32_t heads, uint32_t kvHeads, uint32_t headDim,
        uint32_t maxSeq, uint32_t layers, uint32_t kvLayers = 0);
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

    bool ApplyWeightWindowPolicy(size_t maxWeightBytes, size_t budgetBytes,
                                 uint32_t slotOverride, size_t arenaBytes);
    bool ReserveDecodeScratch();

    bool UploadHidden(const float* src, uint32_t count);
    bool DownloadHidden(float* dst, uint32_t count);
    bool CopyArenaHiddenTo(VulkanCompute& dst, uint32_t count);
    bool LastCrossDeviceCopyUsedHost() const noexcept { return lastCrossDeviceCopyUsedHost_; }

    bool UploadNormWeight(DeviceBuf& dst, const float* src, size_t count);

    bool BeginFusedLayer();
    bool EndFusedLayer();
    bool FusedRecording() const noexcept { return fused_; }
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

    // ========== Batch Q4K GEMV ==========
    bool DispatchGemvQ4KBatch(
        const void* weights, size_t weightBytes,
        DeviceBuf& inputBatch, DeviceBuf& outputBatch,
        uint32_t rows, uint32_t cols, uint32_t batch);
    struct QBatchPush {
        uint32_t type = 12;
        uint32_t rows = 0;
        uint32_t cols = 0;
        uint32_t weightBytes = 0;
        uint32_t batch = 1;
    };
    VkPipeline qBatchPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout qBatchPipelineLayout_ = VK_NULL_HANDLE;

    bool RunWeightHostBatchQ4K(
        const GpuWeightView& weight,
        const float* inputBatch, float* outputBatch,
        uint32_t batch, uint64_t epoch);
    bool RunWeightBatchQ4KTop1(
        const GpuWeightView& weight,
        const float* inputBatch, uint32_t batch,
        uint32_t rowBase, uint32_t* outIndex, float* outValue,
        uint64_t epoch);

    // ========== Argmax ==========
    VkPipeline argmaxPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout argmaxPipelineLayout_ = VK_NULL_HANDLE;
    struct ArgmaxPush { uint32_t rows = 0, batch = 0; };
    bool DispatchArgmaxBatch(
        DeviceBuf& logits, DeviceBuf& values, DeviceBuf& indices,
        uint32_t rows, uint32_t batch);

    // ========== Spec ops host batch ==========
    bool RunSpecRmsNormHostBatch(
        const float* input, const float* weight, float* output,
        uint32_t width, uint32_t batch, float eps, uint64_t epoch);
    bool RunSpecSwiGLUHostBatch(
        const float* gate, const float* up, float* output,
        uint32_t width, uint32_t batch, uint64_t epoch);

    // ========== Spec ops device ==========
    VkPipeline specOpsPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout specOpsPipelineLayout_ = VK_NULL_HANDLE;
    struct SpecOpsPush {
        uint32_t op = 0, width = 0, batch = 0, reserved = 0;
        float eps = 0.0f;
    };
    bool dispatchSpecOps(
        DeviceBuf& a, DeviceBuf& b, DeviceBuf& c, DeviceBuf& d,
        const SpecOpsPush& p);

    // ========== Spec attention ==========
    bool RunSpecAttentionHostBatch(
        const float* q, const float* k, const float* v, float* output,
        uint32_t heads, uint32_t kvHeads, uint32_t headDim,
        uint32_t seqLen, uint32_t basePos, uint32_t batch, uint64_t epoch);
    VkPipeline specAttnPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout specAttnPipelineLayout_ = VK_NULL_HANDLE;
    struct SpecAttnPush {
        uint32_t headDim = 0, heads = 0, kvHeads = 0, seqLen = 0;
        uint32_t capacity = 0, basePos = 0, batch = 0;
        float scale = 1.0f;
    };
    static_assert(offsetof(SpecAttnPush, headDim)  == 0);
    static_assert(offsetof(SpecAttnPush, heads)    == 4);
    static_assert(offsetof(SpecAttnPush, kvHeads)  == 8);
    static_assert(offsetof(SpecAttnPush, seqLen)   == 12);
    static_assert(offsetof(SpecAttnPush, capacity) == 16);
    static_assert(offsetof(SpecAttnPush, basePos)  == 20);
    static_assert(offsetof(SpecAttnPush, batch)    == 24);
    static_assert(offsetof(SpecAttnPush, scale)    == 28);
    static_assert(sizeof(SpecAttnPush) == 32);

    // ========== KV mirror ==========
    bool EnsureSpecKvMirror(uint32_t layers, uint32_t kvHeads,
                            uint32_t headDim, uint32_t maxSeq);
    bool UploadSpecKvRange(uint32_t layer, uint32_t start, uint32_t count,
                           const float* kTokenMajor, const float* vTokenMajor);
    bool RunSpecAttentionResident(
        uint32_t layer, const float* q, float* output,
        uint32_t heads, uint32_t kvHeads, uint32_t headDim,
        uint32_t seqLen, uint32_t basePos, uint32_t batch, uint64_t epoch);
    void ResetSpecKvMirror();
    std::vector<DeviceBuf> specKMirror_;
    std::vector<DeviceBuf> specVMirror_;
    uint32_t specKvLayers_ = 0, specKvHeads_ = 0, specKvHeadDim_ = 0;
    uint32_t specKvCapacity_ = 0;

    // ========== Weight group host batch ==========
    bool RunWeightGroupHostBatchQ4K(
        const GpuWeightView* weights, float* const* outputs, size_t weightCount,
        const float* inputBatch, uint32_t batch, uint64_t epoch);

    // ========== Spec batch arena ==========
    struct SpecBatchArena {
        DeviceBuf hidden{}, norm{}, q{}, k{}, v{}, attn{}, proj{};
        DeviceBuf gate{}, up{}, act{}, down{}, tmp{};
        uint32_t hiddenWidth = 0;
        uint32_t kvWidth = 0;
        uint32_t intermediate = 0;
        uint32_t batchCapacity = 0;
        bool valid() const noexcept {
            return hidden && norm && q && k && v && attn && proj && gate && up && act && down;
        }
    };
    bool EnsureSpecBatchArena(uint32_t hidden, uint32_t kvWidth,
                              uint32_t intermediate, uint32_t batch);
    SpecBatchArena& SpecArena() noexcept { return specArenas_[specArenaIndex_ & 1u]; }
    SpecBatchArena& InactiveSpecArena() noexcept { return specArenas_[(specArenaIndex_ ^ 1u) & 1u]; }
    void FlipSpecArena() noexcept { specArenaIndex_ ^= 1u; }
    uint64_t SpecArenaFlips() const noexcept { return specArenaFlips_; }
    void ResetSpecBatchArena();
    bool UploadSpecHidden(const float* src, uint32_t hidden, uint32_t batch);
    bool DownloadSpecHidden(float* dst, uint32_t hidden, uint32_t batch);
    SpecBatchArena specArenas_[2]{};
    uint32_t specArenaIndex_ = 0;
    uint64_t specArenaFlips_ = 0;

    bool SpecBatchRmsNorm(DeviceBuf& input, DeviceBuf& weight, DeviceBuf& output,
                          uint32_t width, uint32_t batch, float eps);
    bool SpecBatchSwiGLU(DeviceBuf& gate, DeviceBuf& up, DeviceBuf& output,
                         uint32_t width, uint32_t batch);
    bool SpecBatchResidual(DeviceBuf& a, DeviceBuf& b, DeviceBuf& output,
                            uint32_t width, uint32_t batch);

    // ========== Reduction / resident input ==========
    bool ReduceHostPartialInto(
        DeviceBuf& primary, const float* partial, uint32_t count);
    bool EnsureResidentBatchInput(uint32_t cols, uint32_t batch);
    bool UploadResidentBatchInput(const float* input, uint32_t cols,
                                  uint32_t batch, uint64_t epoch);
    DeviceBuf& ResidentBatchInput() noexcept { return residentBatchInput_; }
    void ResetResidentBatchInput();
    uint64_t ResidentBatchInputUploads() const noexcept {
        return residentBatchInputUploads_;
    }
    DeviceBuf residentBatchInput_{};
    uint32_t residentBatchCols_ = 0;
    uint32_t residentBatchCapacity_ = 0;
    uint64_t residentBatchInputUploads_ = 0;

    // ========== Weight pinning ==========
    bool PinWeightView(const GpuWeightView& view);
    void UnpinAllWeights();
    uint64_t PinnedWeightBytes() const noexcept { return pinnedWeightBytes_; }
    uint64_t PinnedWeightEntries() const noexcept { return pinnedWeightEntries_; }

    // ===== B5.2 PEER_HANDOFF capability probe ==============================
    // CAUTION: device-extension + handle-type support does NOT prove that
    // memory exported by GPU A can be imported by GPU B. Vulkan restricts
    // Win32 external-memory import to the SAME underlying physical device
    // as the exporter; two discrete AMD GPUs are different physical devices.
    // The only native cross-physical-device mechanism is a
    // VkPhysicalDeviceGroup logical device with peer memory features.
    // Fails closed: peerHandoffSupported=1 ONLY when sameDeviceGroup=1 AND
    // peer COPY features are present.
    struct PeerHandoffCaps {
        bool     externalMemoryExtension = false;
        bool     win32 = false;
        bool     omtHandle = false;
        bool     d3d12Handle = false;
        bool     externalSemaphore = false;
        bool     externalMemoryApiSupported = false;
        // Device-group authority (B5.2a):
        bool     deviceGroupSupported = false;
        bool     sameDeviceGroup = false;
        uint32_t groupCount = 0;
        bool     subsetAllocation = false;
        bool     peerCopySrc = false;
        bool     peerCopyDst = false;
        bool     peerHandoffSupported = false;   // the honest verdict
        std::string commonHandleName;
        // B5_HOST_IMPORT_PROBE_001: VK_EXT_external_memory_host
        bool     externalMemoryHostSupported = false;
        uint64_t minImportedHostPointerAlignment = 0;
        uint32_t hostImportableMemoryTypeBits = 0;
        bool     hostImportable = false;   // dummy pointer query succeeded
    };
    const PeerHandoffCaps& PeerHandoffCapability() const;
    bool PeerHandoffSupported() const {
        return PeerHandoffCapability().peerHandoffSupported;
    }

    // B5_SHARED_HOST_IMPORT_001: same host allocation imported into both devices
    struct SharedHostImportResult {
        int32_t  hostPointerQueryResult = INT32_MIN; // vkGetMemoryHostPointerPropertiesEXT
        uint32_t memoryTypeBits = 0;
        int32_t  importMemoryResult = INT32_MIN;    // vkAllocateMemory with VkImportMemoryHostPointerInfoEXT
        int32_t  bindResult = INT32_MIN;              // vkBindBufferMemory
    };
    SharedHostImportResult TestSharedHostImport(size_t testBytes = 4096) const;
    DeviceBuf* ResolveResidentF32(const float* src, uint64_t key, size_t count);
    uint64_t weightUseClock_ = 0;
    uint64_t pinnedWeightBytes_ = 0;
    uint64_t pinnedWeightEntries_ = 0;

    // ========== Resident group Q4K ==========
    bool RunWeightGroupResidentInputQ4K(
        const GpuWeightView* weights, float* const* outputs,
        size_t weightCount, uint32_t cols, uint32_t batch, uint64_t epoch);
    bool EnsureResidentGroupOutputs(const GpuWeightView* weights,
                                      size_t weightCount, uint32_t batch);
    DeviceBuf& ResidentGroupOutput(size_t index) noexcept {
        return residentGroupOutputs_[index];
    }
    void ResetResidentGroupOutputs();
    uint64_t ResidentGroupOutputReallocs() const noexcept {
        return residentGroupOutputReallocs_;
    }
    DeviceBuf residentGroupOutputs_[3]{};
    size_t residentGroupOutputFloats_[3]{};
    uint64_t residentGroupOutputReallocs_ = 0;
    bool RunWeightGroupResidentInputQ4KSingleReturn(
        const GpuWeightView* weights, float* contiguousOutput,
        size_t* outputOffsets, size_t weightCount,
        uint32_t cols, uint32_t batch, uint64_t epoch);

    // ========== Download ticket ==========
    struct DownloadTicket {
        DeviceBuf staging{};
        void* mapped = nullptr;
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
        VkQueryPool query = VK_NULL_HANDLE;
        size_t bytes = 0;
        bool active = false;
    };
    bool SubmitDownloadAsync(
        DeviceBuf& src, size_t bytes, DownloadTicket& ticket);
    bool WaitDownloadAsync(
        DownloadTicket& ticket, void* dst, size_t bytes);
    void CancelDownloadTicket(DownloadTicket& ticket);

    // ========== Spec KV append / full output ==========
    bool AppendSpecKvFromDevice(
        uint32_t layer, uint32_t start, uint32_t count,
        DeviceBuf& kTokenMajor, DeviceBuf& vTokenMajor);
    uint64_t DirectSpecKvAppends() const noexcept {
        return directSpecKvAppends_;
    }
    uint64_t directSpecKvAppends_ = 0;

    bool EnsureResidentFullOutput(uint32_t rows, uint32_t batch);
    DeviceBuf& ResidentFullOutput() noexcept { return residentFullOutput_; }
    bool CopyDeviceSliceIntoFullOutput(
        DeviceBuf& src, uint32_t srcRows, uint32_t rowBegin,
        uint32_t fullRows, uint32_t batch);
    uint64_t ResidentFullOutputCopies() const noexcept {
        return residentFullOutputCopies_;
    }
    DeviceBuf residentFullOutput_{};
    uint32_t residentFullOutputRows_ = 0;
    uint32_t residentFullOutputBatch_ = 0;
    uint64_t residentFullOutputCopies_ = 0;

    bool ImportHostRowsIntoFullOutput(
        const float* rows, uint32_t rowCount, uint32_t rowBegin,
        uint32_t fullRows, uint32_t batch);
    uint64_t SecondaryImportBytes() const noexcept {
        return secondaryImportBytes_;
    }
    uint64_t secondaryImportBytes_ = 0;

    bool DownloadResidentFullOutput(
        float* dst, uint32_t rows, uint32_t batch);
    uint64_t FullOutputBoundaryBytes() const noexcept {
        return fullOutputBoundaryBytes_;
    }
    void ResetResidentFullOutput();
    uint64_t fullOutputBoundaryBytes_ = 0;

    // ========== Spec layer graph ==========
    bool BeginSpecLayerGraph(uint64_t epoch);
    bool EndSpecLayerGraph();
    bool SpecLayerGraphActive() const noexcept { return specLayerGraphActive_; }
    uint64_t SpecLayerGraphSubmits() const noexcept {
        return specLayerGraphSubmits_;
    }
    bool specLayerGraphActive_ = false;
    uint64_t specLayerGraphSubmits_ = 0;

    // ========== Batch 4/8 row ==========
    bool DispatchGemvQ4KBatch4Row(
        const void* weights, size_t weightBytes,
        DeviceBuf& inputBatch, DeviceBuf& outputBatch,
        uint32_t rows, uint32_t cols, uint32_t batch);
    VkPipeline qBatch4RowPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout qBatch4RowPipelineLayout_ = VK_NULL_HANDLE;
    uint64_t Q4KBatchWeightBytes() const noexcept {
        return q4kBatchWeightBytes_;
    }
    uint64_t Q4KBatchGpuNs() const noexcept { return q4kBatchGpuNs_; }
    uint64_t Q4KBatch4RowOps() const noexcept { return q4kBatch4RowOps_; }
    uint64_t q4kBatchWeightBytes_ = 0;
    uint64_t q4kBatchGpuNs_ = 0;
    uint64_t q4kBatch4RowOps_ = 0;

    enum class Q4KBatchTile : uint8_t { Four = 4, Eight = 8 };
    struct Q4KTileKey {
        uint32_t rows = 0, cols = 0, batch = 0;
        bool operator==(const Q4KTileKey& o) const noexcept {
            return rows == o.rows && cols == o.cols && batch == o.batch;
        }
    };
    struct Q4KTileKeyHash {
        size_t operator()(const Q4KTileKey& k) const noexcept {
            return ((size_t)k.rows << 32) ^ ((size_t)k.cols << 5) ^ k.batch;
        }
    };
    struct Q4KTileChoice {
        Q4KBatchTile tile = Q4KBatchTile::Four;
        uint64_t fourNs = 0, eightNs = 0;
    };
    bool DispatchGemvQ4KBatch8Row(
        const void* weights, size_t weightBytes,
        DeviceBuf& inputBatch, DeviceBuf& outputBatch,
        uint32_t rows, uint32_t cols, uint32_t batch);
    Q4KBatchTile SelectQ4KBatchTile(
        const void* weights, size_t weightBytes,
        DeviceBuf& inputBatch, DeviceBuf& scratchOutput,
        uint32_t rows, uint32_t cols, uint32_t batch);
    VkPipeline qBatch8RowPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout qBatch8RowPipelineLayout_ = VK_NULL_HANDLE;
    std::unordered_map<Q4KTileKey, Q4KTileChoice, Q4KTileKeyHash>
        q4kTileChoices_;
    uint64_t Q4KBatch8RowOps() const noexcept { return q4kBatch8RowOps_; }
    uint64_t Q4KAutotuneRuns() const noexcept { return q4kAutotuneRuns_; }
    uint64_t q4kBatch8RowOps_ = 0;
    uint64_t q4kAutotuneRuns_ = 0;

    // ========== Recorded Q4K ==========
    struct RecordedQ4KKey {
        VkBuffer weight = VK_NULL_HANDLE;
        VkBuffer input = VK_NULL_HANDLE;
        VkBuffer output = VK_NULL_HANDLE;
        uint32_t rows = 0, cols = 0, batch = 0, tile = 4;
        bool operator==(const RecordedQ4KKey& o) const noexcept {
            return weight == o.weight && input == o.input && output == o.output &&
                   rows == o.rows && cols == o.cols && batch == o.batch && tile == o.tile;
        }
    };
    struct RecordedQ4KKeyHash {
        size_t operator()(const RecordedQ4KKey& k) const noexcept {
            size_t h = (size_t)(uintptr_t)k.weight;
            h ^= (size_t)(uintptr_t)k.input >> 4;
            h ^= (size_t)(uintptr_t)k.output << 3;
            h ^= ((size_t)k.rows << 32) ^ ((size_t)k.cols << 7) ^ k.batch ^ k.tile;
            return h;
        }
    };
    struct RecordedQ4K {
        VkDescriptorSet set = VK_NULL_HANDLE;
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
    };
    bool SubmitRecordedResidentQ4K(
        const GpuWeightView& weight, DeviceBuf& input, DeviceBuf& output,
        uint32_t batch, uint64_t epoch);
    uint64_t RecordedQ4KSubmits() const noexcept {
        return recordedQ4KSubmits_;
    }
    uint64_t RecordedQ4KBuilds() const noexcept {
        return recordedQ4KBuilds_;
    }
    std::unordered_map<
        RecordedQ4KKey, RecordedQ4K, RecordedQ4KKeyHash> recordedQ4K_;
    uint64_t recordedQ4KSubmits_ = 0;
    uint64_t recordedQ4KBuilds_ = 0;
    void clearRecordedQ4K();

    // ========== Q4K Async ==========
    struct Q4KAsyncTicket {
        uint64_t submitNs = 0;
        uint64_t completeNs = 0;
        uint64_t weightBytes = 0;
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
        VkQueryPool query = VK_NULL_HANDLE;
        bool active = false;
    };
    bool BeginQ4KResidentAsync(
        const GpuWeightView& weight, DeviceBuf& input, DeviceBuf& output,
        uint32_t batch, uint64_t epoch, Q4KAsyncTicket& ticket);
    bool WaitQ4KResidentAsync(Q4KAsyncTicket& ticket, uint64_t* gpuNs = nullptr);
    void CancelQ4KAsync(Q4KAsyncTicket& ticket);
    uint64_t Q4KAsyncSubmits() const noexcept { return q4kAsyncSubmits_; }
    uint64_t Q4KAsyncWaitNs() const noexcept { return q4kAsyncWaitNs_; }
    uint64_t q4kAsyncSubmits_ = 0;
    uint64_t q4kAsyncWaitNs_ = 0;

    // ========== Download ring ==========
    struct TransferRingSlot {
        DeviceBuf staging{};
        void* mapped = nullptr;
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
        size_t capacity = 0;
        size_t bytes = 0;
        bool inFlight = false;
    };
    bool EnsureDownloadRing(size_t bytes);
    bool SubmitDownloadRing(DeviceBuf& src, size_t bytes, uint32_t& slotOut);
    bool WaitDownloadRing(uint32_t slot, void* dst, size_t bytes);
    void ResetDownloadRing();
    uint64_t DownloadRingSubmits() const noexcept {
        return downloadRingSubmits_;
    }
    uint64_t DownloadRingWaitNs() const noexcept {
        return downloadRingWaitNs_;
    }
    TransferRingSlot downloadRing_[3]{};
    uint32_t downloadRingHead_ = 0;
    uint64_t downloadRingSubmits_ = 0;
    uint64_t downloadRingWaitNs_ = 0;

    // ========== Transfer queue ==========
    bool HasDedicatedTransferQueue() const noexcept {
        return transferQueue_ != VK_NULL_HANDLE &&
               (transferQueue_ != queue_ ||
                transferQueueFamilyIndex_ != queueFamily_);
    }
    uint32_t ComputeQueueFamily() const noexcept { return queueFamily_; }
    uint32_t TransferQueueFamily() const noexcept {
        return transferQueueFamilyIndex_;
    }
    uint64_t TransferQueueSubmits() const noexcept {
        return transferQueueSubmits_;
    }
    uint64_t TransferRingOverlapNs() const noexcept {
        return transferRingOverlapNs_;
    }
    uint64_t transferRingOverlapNs_ = 0;

    // ========== Device / timeline ==========
    VkDevice DeviceHandle() const noexcept { return device_; }
    bool TimelineSemaphoreEnabled() const noexcept {
        return timelineEnabled_ && timelineSemaphore_ != VK_NULL_HANDLE;
    }
    uint64_t NextTimelineValue() noexcept { return ++timelineNextValue_; }
    uint64_t TimelineSignals() const noexcept { return timelineSignals_; }
    uint64_t TimelineWaits() const noexcept { return timelineWaits_; }
    VkSemaphore TimelineSemaphore() const noexcept { return timelineSemaphore_; }
    bool WaitTimelineValue(uint64_t value, uint64_t timeoutNs = UINT64_MAX);
    bool timelineEnabled_ = false;
    VkSemaphore timelineSemaphore_ = VK_NULL_HANDLE;
    uint64_t timelineNextValue_ = 0;
    uint64_t timelineSignals_ = 0;
    uint64_t timelineWaits_ = 0;

    struct TimelineTicket {
        uint64_t computeDone = 0;
        uint64_t transferDone = 0;
        uint32_t ringSlot = UINT32_MAX;
        size_t bytes = 0;
        bool active = false;
    };
    bool SubmitQ4KThenDownloadTimeline(
        const GpuWeightView& weight, DeviceBuf& input, DeviceBuf& output,
        uint32_t batch, uint64_t epoch, TimelineTicket& ticket);
    bool WaitTimelineDownload(
        TimelineTicket& ticket, void* dst, size_t bytes);
    uint64_t TimelineComputeTransferChains() const noexcept {
        return timelineComputeTransferChains_;
    }
    uint64_t timelineComputeTransferChains_ = 0;

    // ========== Async command ring ==========
    struct AsyncCmdSlot {
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
        VkQueryPool query = VK_NULL_HANDLE;
        bool used = false;
        bool inFlight = false;
    };
    bool EnsureAsyncCmdRing();
    void ResetAsyncCmdRing();
    uint64_t AsyncCmdRingReuses() const noexcept { return asyncCmdRingReuses_; }
    AsyncCmdSlot asyncCmdRing_[4]{};
    uint32_t asyncCmdRingHead_ = 0;
    uint64_t asyncCmdRingReuses_ = 0;

    // ========== Recorded group Q4K ==========
    struct RecordedGroupKey {
        VkBuffer weight[3]{VK_NULL_HANDLE, VK_NULL_HANDLE, VK_NULL_HANDLE};
        VkBuffer output[3]{VK_NULL_HANDLE, VK_NULL_HANDLE, VK_NULL_HANDLE};
        uint32_t rows[3]{};
        uint32_t cols = 0, batch = 0, count = 0;
        VkBuffer input = VK_NULL_HANDLE;
        bool operator==(const RecordedGroupKey& o) const noexcept {
            if (input != o.input || cols != o.cols || batch != o.batch || count != o.count)
                return false;
            for (uint32_t i = 0; i < count; ++i)
                if (weight[i] != o.weight[i] || output[i] != o.output[i] ||
                    rows[i] != o.rows[i]) return false;
            return true;
        }
    };
    struct RecordedGroupKeyHash {
        size_t operator()(const RecordedGroupKey& k) const noexcept {
            size_t h = (size_t)(uintptr_t)k.input;
            h ^= ((size_t)k.cols << 17) ^ ((size_t)k.batch << 3) ^ k.count;
            for (uint32_t i = 0; i < k.count; ++i) {
                h ^= (size_t)(uintptr_t)k.weight[i] >> 4;
                h ^= (size_t)(uintptr_t)k.output[i] << 5;
                h ^= (size_t)k.rows[i] << (i + 7);
            }
            return h;
        }
    };
    struct RecordedGroup {
        VkDescriptorSet set[3]{VK_NULL_HANDLE, VK_NULL_HANDLE, VK_NULL_HANDLE};
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
    };
    bool SubmitRecordedResidentGroupQ4K(
        const GpuWeightView* weights, size_t weightCount,
        uint32_t cols, uint32_t batch, uint64_t epoch);
    uint64_t RecordedGroupBuilds() const noexcept {
        return recordedGroupBuilds_;
    }
    uint64_t RecordedGroupSubmits() const noexcept {
        return recordedGroupSubmits_;
    }
    uint64_t RecordedGroupAsyncSubmits() const noexcept {
        return recordedGroupAsyncSubmits_;
    }
    uint64_t RecordedGroupSyncWaits() const noexcept {
        return recordedGroupSyncWaits_;
    }
    uint64_t RecordedGroupLastSignal() const noexcept {
        return recordedGroupLastSignal_;
    }
    std::unordered_map<
        RecordedGroupKey, RecordedGroup, RecordedGroupKeyHash> recordedGroups_;
    uint64_t recordedGroupBuilds_ = 0;
    uint64_t recordedGroupSubmits_ = 0;
    uint64_t recordedGroupAsyncSubmits_ = 0;
    uint64_t recordedGroupSyncWaits_ = 0;
    uint64_t recordedGroupLastSignal_ = 0;
    void clearRecordedGroups();

    // ========== Dense-row GPU timing authority (DEEP2_DENSE_ROW_GPU_TIMING_AUTHORITY_001)
    // Timestamp-derived GPU compute ns for the dual-row dense lane
    // (RunWeightHostRoundTrip / RunWeightGroupHostRoundTrip). Accumulated
    // from the already-finalized EndFusedLayer interval AFTER the existing
    // fence — no new synchronization point. Separate authority from the
    // Q4K-batch counters: never overloaded.
    uint64_t DenseRowGpuNs() const noexcept { return denseRowGpuNs_; }
    uint64_t DenseRowTimedOps() const noexcept { return denseRowTimedOps_; }
    uint64_t DenseRowSingleGpuNs() const noexcept { return denseRowSingleGpuNs_; }
    uint64_t DenseRowGroupGpuNs() const noexcept { return denseRowGroupGpuNs_; }
    void RecordDenseRowGpuInterval(const GpuWorkInterval& wi, bool isGroup) noexcept {
        const uint64_t gpuNs = wi.calibratedDurationNs();
        denseRowGpuNs_ += gpuNs;
        ++denseRowTimedOps_;
        if (isGroup) denseRowGroupGpuNs_ += gpuNs;
        else         denseRowSingleGpuNs_ += gpuNs;
    }
    // Read the interval EndFusedLayer finalized on this thread. Valid only
    // immediately after a successful EndFusedLayer under the same apiMu_
    // guard; BeginFusedLayer invalidates it.
    const GpuWorkInterval& LastFusedInterval() const noexcept {
        return lastFusedInterval_;
    }
    bool LastFusedIntervalValid() const noexcept {
        return lastFusedIntervalValid_;
    }
    // Last interval finalized by EndFusedLayer, for callers that need the
    // GPU-side duration of the fused submission they just waited on.
    // Valid only immediately after a successful EndFusedLayer on the same
    // thread (guarded by apiMu_).
    GpuWorkInterval lastFusedInterval_{};
    bool lastFusedIntervalValid_ = false;
    uint64_t denseRowGpuNs_ = 0;
    uint64_t denseRowTimedOps_ = 0;
    uint64_t denseRowSingleGpuNs_ = 0;
    uint64_t denseRowGroupGpuNs_ = 0;

    // ========== Q4K execution-path parity harness ==========
    // DEEP2_RESIDENT_Q4K_KERNEL_PARITY_001: both the dual-row lane and
    // the resident lane execute Q4_K GEMVs through dispatchQuant() on the
    // SAME qPipeline_ (deep2_qgemv.comp, one 256-lane workgroup per row).
    // This harness lane-tags every quant dispatch and samples GPU
    // timestamp pairs around dispatches (mid-command-buffer), collected
    // post-fence — no new synchronization. Emits per-lane ns/row so the
    // receipt can compute RESIDENT_Q4K_SLOWDOWN = resident/dual ns/row.
    //   lane: 0=untagged, 1=dual-row, 2=resident-range
    static constexpr uint32_t kQ4kLaneDual = 1;
    static constexpr uint32_t kQ4kLaneResident = 2;
    void SetQ4kLaneTag(uint32_t lane) noexcept { q4kLane_ = lane; }
    // Reset all parity/ops sampled statistics. The gate calls this between
    // warmup and measurement so warmup-phase samples (taken while ~18GB of
    // weight admission transfers contend with compute) cannot contaminate
    // the measured receipt.
    void ResetQ4kParityStats() noexcept {
        for (uint32_t l = 0; l < 3; ++l) {
            q4kDispatchCount_[l] = 0;
            q4kRows_[l] = 0;
            q4kSampledNs_[l] = 0;
            q4kSampledCount_[l] = 0;
            q4kSampledRows_[l] = 0;
            q4kPipelineSeen_[l] = VK_NULL_HANDLE;
            for (uint32_t op = 0; op < 8; ++op) {
                opsSampledNs_[l][op] = 0;
                opsSampledCount_[l][op] = 0;
                opsSampledUnits_[l][op] = 0;
            }
        }
    }
    uint64_t Q4kParityDispatchCount(uint32_t lane) const noexcept {
        return lane < 3 ? q4kDispatchCount_[lane] : 0;
    }
    uint64_t Q4kParityRows(uint32_t lane) const noexcept {
        return lane < 3 ? q4kRows_[lane] : 0;
    }
    uint64_t Q4kParitySampledNs(uint32_t lane) const noexcept {
        return lane < 3 ? q4kSampledNs_[lane] : 0;
    }
    uint64_t Q4kParitySampledCount(uint32_t lane) const noexcept {
        return lane < 3 ? q4kSampledCount_[lane] : 0;
    }
    uint64_t Q4kParitySampledRows(uint32_t lane) const noexcept {
        return lane < 3 ? q4kSampledRows_[lane] : 0;
    }
    // Pipeline-handle identity per lane: proves both lanes bind the same
    // compute pipeline (Q4K_SHADER_MATCH / Q4K_LAYOUT_MATCH authority).
    VkPipeline Q4kParityPipeline(uint32_t lane) const noexcept {
        return lane < 3 ? q4kPipelineSeen_[lane] : VK_NULL_HANDLE;
    }
    // DEEP2_RESIDENT_OPS_BREAKDOWN_001: sampled ops-pipeline GPU ns by
    // op kind (0=probe,1=gemv_f32,2=rmsnorm,3=residual,4=swiglu,5=rope,
    // 6=attn,7=mla_attn) and lane (0=untagged,1=dual-row,2=resident).
    uint64_t OpsSampledNs(uint32_t lane, uint32_t opKind) const noexcept {
        return (lane<3 && opKind<8) ? opsSampledNs_[lane][opKind] : 0;
    }
    uint64_t OpsSampledCount(uint32_t lane, uint32_t opKind) const noexcept {
        return (lane<3 && opKind<8) ? opsSampledCount_[lane][opKind] : 0;
    }
    uint64_t OpsSampledUnits(uint32_t lane, uint32_t opKind) const noexcept {
        return (lane<3 && opKind<8) ? opsSampledUnits_[lane][opKind] : 0;
    }

    // ========== Spec accept ==========
    struct SpecAcceptResult {
        uint32_t accepted = 0;
        uint32_t replacement = UINT32_MAX;
        uint32_t bonus = UINT32_MAX;
    };
    bool RunSpecAcceptPrefix(
        const uint32_t* target, const uint32_t* proposal,
        uint32_t count, SpecAcceptResult& result);
    bool RunSpecAcceptPrefixResident(
        DeviceBuf& targetIds, DeviceBuf& proposalIds,
        uint32_t count, SpecAcceptResult& result);
    uint64_t SpecAcceptGpuOps() const noexcept { return specAcceptGpuOps_; }
    uint64_t SpecAcceptResidentOps() const noexcept { return specAcceptResidentOps_; }
    uint64_t SpecAcceptInputUploadBytes() const noexcept {
        return specAcceptInputUploadBytes_;
    }
    VkPipeline specAcceptPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout specAcceptPipelineLayout_ = VK_NULL_HANDLE;
    uint64_t specAcceptGpuOps_ = 0;
    uint64_t specAcceptResidentOps_ = 0;
    uint64_t specAcceptInputUploadBytes_ = 0;

    // ========== Verified hidden ==========
    bool CaptureVerifiedHidden(
        DeviceBuf& hiddenBatch, uint32_t tokenIndex,
        uint32_t hiddenWidth, uint32_t batch);
    bool RestoreVerifiedHiddenToArena(uint32_t hiddenWidth);
    bool DownloadVerifiedHidden(float* dst, uint32_t hiddenWidth);
    uint64_t VerifiedHiddenHandoffs() const noexcept {
        return verifiedHiddenHandoffs_;
    }
    DeviceBuf verifiedHidden_{};
    uint32_t verifiedHiddenWidth_ = 0;
    uint64_t verifiedHiddenHandoffs_ = 0;

    struct HiddenCopyTicket {
        uint64_t signalValue = 0;
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
        bool active = false;
    };
    bool CaptureVerifiedHiddenTimeline(
        DeviceBuf& hiddenBatch, uint32_t tokenIndex,
        uint32_t hiddenWidth, uint32_t batch,
        uint64_t waitValue, HiddenCopyTicket& ticket);
    bool RestoreVerifiedHiddenTimeline(
        uint32_t hiddenWidth, uint64_t waitValue,
        HiddenCopyTicket& ticket);
    bool WaitHiddenCopy(HiddenCopyTicket& ticket);
    uint64_t HiddenTimelineSubmits() const noexcept {
        return hiddenTimelineSubmits_;
    }
    void ResetVerifiedHidden();
    uint64_t QueueSubmitCount() const noexcept { return queueSubmitCount_; }
    uint64_t hiddenTimelineSubmits_ = 0;

    // ========== Layer timeline ==========
    struct LayerTimelineState {
        uint64_t qkvDone = 0;
        uint64_t attnDone = 0;
        uint64_t gateUpDone = 0;
        uint64_t layerDone = 0;
    };
    bool SubmitTimelineCommand(
        VkCommandBuffer cmd, VkQueue q,
        uint64_t waitValue, uint64_t signalValue,
        VkPipelineStageFlags waitStage);
    uint64_t LayerTimelineChains() const noexcept {
        return layerTimelineChains_;
    }
    uint64_t layerTimelineChains_ = 0;

    // ========== Round-trip helpers ==========
    bool RunWeightGroupHostRoundTrip(
        const GpuWeightView* weights, float* const* outputs,
        size_t count, const float* input,
        uint32_t inputCount, uint64_t epoch);
    bool RunWeightHostRoundTrip(
        const GpuWeightView& weight,
        const float* input, float* output,
        uint64_t epoch);

private:
    struct WeightCacheEntry {
        DeviceBuf buffer{};
        size_t bytes = 0;
        int type = 0;
        uint64_t lastUse = 0;
        bool pinned = false;
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

    // B5.2 probe state
    mutable PeerHandoffCaps peerHandoffCaps_{};
    mutable bool peerHandoffCapsProbed_ = false;

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
    uint32_t transferQueueFamilyIndex_ = UINT32_MAX;
    uint32_t transferQueueIndex_ = 0;
    VkQueue transferQueue_ = VK_NULL_HANDLE;
    VkCommandPool transferCommandPool_ = VK_NULL_HANDLE;
    uint64_t transferQueueSubmits_ = 0;
    bool discoverTransferQueue(
        VkPhysicalDevice physical,
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
    uint32_t kvArenaLayers_ = 0; // K/V arena sizing (layer-split slots)
    uint32_t kvLayerBase_ = 0;  // first absolute layer mapped to cache slot 0

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

    bool evictWeightCacheUntil(size_t incomingBytes);
    bool ensureMappedStaging(bool upload, size_t bytes,
                             DeviceBuf*& buffer, void*& mapped);
    VkDescriptorSet getOpsDescriptor(DeviceBuf& a, DeviceBuf& b,
                                     DeviceBuf& c, DeviceBuf& d);
    VkDescriptorSet getQuantDescriptor(DeviceBuf& weights,
                                       DeviceBuf& input, DeviceBuf& output);
    bool ensureReusableFusedSubmitObjects();
    bool uploadToBufferRange(DeviceBuf& dst, const void* src, size_t bytes,
                             VkDeviceSize dstOffset);

    uint64_t queueSubmitCount_ = 0;

    VkCommandBuffer reusableFusedCmd_ = VK_NULL_HANDLE;
    VkQueryPool reusableFusedQuery_ = VK_NULL_HANDLE;
    VkFence reusableFusedFence_ = VK_NULL_HANDLE;

    // ---- Q4K parity harness state (see public accessors above) ----
    struct Q4kParitySample {
        uint32_t rows;
        uint32_t cols;
        uint32_t lane;
    };
    bool ensureQ4kParityPool();
    void accumulateQ4kParitySamples() noexcept;
    VkQueryPool q4kParityQuery_ = VK_NULL_HANDLE;
    std::vector<Q4kParitySample> q4kParityMeta_;
    uint32_t q4kParityNext_ = 0;        // next sample slot this fused layer
    uint32_t q4kParityCapacity_ = 256;   // sample slots (2 queries each)
    uint64_t q4kParitySeq_ = 0;
    uint64_t q4kParitySampleEvery_ = 4;  // 1-in-N sampling; 0 disables
    uint32_t q4kLane_ = 0;
    uint64_t q4kDispatchCount_[3] = {};
    uint64_t q4kRows_[3] = {};
    uint64_t q4kSampledNs_[3] = {};
    uint64_t q4kSampledCount_[3] = {};
    uint64_t q4kSampledRows_[3] = {};
    VkPipeline q4kPipelineSeen_[3] = {};

    uint64_t opsSampledNs_[3][8] = {};
    uint64_t opsSampledCount_[3][8] = {};
    uint64_t opsSampledUnits_[3][8] = {};

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

namespace CPUInference {
using VulkanCompute = Deep2::VulkanCompute;
}
