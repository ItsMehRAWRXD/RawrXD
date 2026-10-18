#!/usr/bin/env python3
"""Reconstruct vulkan_compute.h with all missing 85TPS declarations."""

import pathlib

HEADER_PATH = pathlib.Path("F:/~dev/rawrxd/src/deep2/vulkan_compute.h")
BACKUP_PATH = pathlib.Path("F:/~dev/rawrxd/src/deep2/vulkan_compute.h.backup2")

# Read current header
original = HEADER_PATH.read_text(encoding="utf-8")
if "\r\n" in original:
    lines = original.split("\r\n")
    line_ending = "\r\n"
else:
    lines = original.split("\n")
    line_ending = "\n"

# Ensure backup
if not BACKUP_PATH.exists():
    BACKUP_PATH.write_bytes(HEADER_PATH.read_bytes())

# We will rebuild the file into sections
public_methods_end_marker = "    uint64_t WeightHitCount() const noexcept { return weightHits_; }"
private_section_start_marker = "private:"
class_end_marker = "};"
namespace_end_marker = "} // namespace Deep2"

# Find indices
pub_end_idx = None
priv_start_idx = None
class_end_idx = None
ns_end_idx = None
for i, line in enumerate(lines):
    if public_methods_end_marker in line:
        pub_end_idx = i
    if line.strip().startswith("private:"):
        priv_start_idx = i
    if line.strip() == "};" and class_end_idx is None:
        class_end_idx = i
    if "} // namespace Deep2" in line:
        ns_end_idx = i

assert pub_end_idx is not None, "Could not find public end"
assert priv_start_idx is not None, "Could not find private start"
assert class_end_idx is not None, "Could not find class end"
assert ns_end_idx is not None, "Could not find ns end"

# Build new public declarations block (after WeightHitCount)
new_public_block = """    // ========== Batch Q4K GEMV ==========
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
        uint32_t seqLen, uint32_t basePos, uint32_t batch);
    VkPipeline specAttnPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout specAttnPipelineLayout_ = VK_NULL_HANDLE;
    struct SpecAttnPush {
        uint32_t headDim = 0, heads = 0, kvHeads = 0, seqLen = 0;
        uint32_t basePos = 0, batch = 0;
        float scale = 1.0f;
    };

    // ========== KV mirror ==========
    bool EnsureSpecKvMirror(uint32_t layers, uint32_t kvHeads,
                            uint32_t headDim, uint32_t maxSeq);
    bool UploadSpecKvRange(uint32_t layer, uint32_t start, uint32_t count,
                           const float* kTokenMajor, const float* vTokenMajor);
    bool RunSpecAttentionResident(
        uint32_t layer, const float* q, float* output,
        uint32_t heads, uint32_t kvHeads, uint32_t headDim,
        uint32_t seqLen, uint32_t basePos, uint32_t batch);
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
    uint64_t weightUseClock_ = 0;
    uint64_t pinnedWeightBytes_ = 0;
    uint64_t pinnedWeightEntries_ = 0;

    // ========== Resident group Q4K ==========
    bool RunWeightGroupResidentInputQ4K(
        uint32_t cols, uint32_t batch, uint64_t epoch);
    bool EnsureResidentGroupOutputs(const GpuWeightView* weights,
                                      size_t weightCount, uint32_t batch);
    DeviceBuf& ResidentGroupOutput(size_t index) noexcept {
        return residentGroupOutputs_[index];
    }
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
    };
    bool BeginQ4KResidentAsync(
        uint32_t batch, uint64_t epoch, Q4KAsyncTicket& ticket);
    bool WaitQ4KResidentAsync(Q4KAsyncTicket& ticket, uint64_t* gpuNs = nullptr);
    void CancelQ4KAsync(Q4KAsyncTicket& ticket);
    uint64_t Q4KAsyncSubmits() const noexcept { return q4kAsyncSubmits_; }
    uint64_t Q4KAsyncWaitNs() const noexcept { return q4kAsyncWaitNs_; }
    uint64_t q4kAsyncSubmits_ = 0;
    uint64_t q4kAsyncWaitNs_ = 0;

    // ========== Download ring ==========
    struct TransferRingSlot {
        size_t capacity = 0;
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
    };
    bool SubmitQ4KThenDownloadTimeline(
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
    };
    bool CaptureVerifiedHiddenTimeline(
        uint32_t hiddenWidth, uint32_t batch,
        uint64_t waitValue, HiddenCopyTicket& ticket);
    bool RestoreVerifiedHiddenTimeline(
        uint32_t hiddenWidth, uint64_t waitValue,
        HiddenCopyTicket& ticket);
    bool WaitHiddenCopy(HiddenCopyTicket& ticket);
    uint64_t HiddenTimelineSubmits() const noexcept {
        return hiddenTimelineSubmits_;
    }
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
        const GpuWeightView* weights, size_t weightCount,
        uint32_t cols, uint32_t batch, uint64_t epoch);
    bool RunWeightHostRoundTrip(
        const GpuWeightView& weight,
        uint32_t cols, uint32_t batch, uint64_t epoch);
"""

# New private methods and fields block (before the closing }; of class)
new_private_block = """    bool evictWeightCacheUntil(size_t incomingBytes);
    bool ensureMappedStaging(bool upload, size_t bytes,
                             DeviceBuf*& buffer, void*& mapped);
    VkDescriptorSet getOpsDescriptor(DeviceBuf& a, DeviceBuf& b,
                                     DeviceBuf& c, DeviceBuf& d);
    VkDescriptorSet getQuantDescriptor(DeviceBuf& weights,
                                       DeviceBuf& input, DeviceBuf& output);
    bool ensureReusableFusedSubmitObjects();
    bool uploadToBufferRange(DeviceBuf& dst, const void* src, size_t bytes,
                             VkDeviceSize dstOffset);
    void dispatchSpecOps(DeviceBuf& a, DeviceBuf& b, DeviceBuf& c, DeviceBuf& d,
                         const SpecOpsPush& p);

    uint64_t queueSubmitCount_ = 0;

    VkCommandBuffer reusableFusedCmd_ = VK_NULL_HANDLE;
    VkQueryPool reusableFusedQuery_ = VK_NULL_HANDLE;
    VkFence reusableFusedFence_ = VK_NULL_HANDLE;

    DeviceBuf uploadStaging_{};
    DeviceBuf downloadStaging_{};
    void* uploadMapped_ = nullptr;
    void* downloadMapped_ = nullptr;
    size_t uploadStagingBytes_ = 0;
    size_t downloadStagingBytes_ = 0;

    std::unordered_map<uint64_t, VkDescriptorSet> opsDescriptorCache_;
    std::unordered_map<uint64_t, VkDescriptorSet> quantDescriptorCache_;
"""

# Now rebuild lines
new_lines = []

# 1. Lines before public end (inclusive)
for i in range(pub_end_idx + 1):
    new_lines.append(lines[i])

# 2. Insert new public block
for line in new_public_block.split("\n"):
    new_lines.append(line)

# 3. Lines between public end and private start (should be blank mostly)
for i in range(pub_end_idx + 1, priv_start_idx):
    new_lines.append(lines[i])

# 4. private: line itself
new_lines.append(lines[priv_start_idx])

# 5. Insert augmented WeightCacheEntry and new private block before existing private content
# Find WeightCacheEntry in private section
wce_start = None
wce_end = None
for i in range(priv_start_idx, class_end_idx):
    if "struct WeightCacheEntry" in lines[i]:
        wce_start = i
    if wce_start is not None and "};" in lines[i] and i > wce_start:
        wce_end = i
        break

assert wce_start is not None and wce_end is not None, "Could not find WeightCacheEntry"

# Keep lines from priv_start+1 up to wce_end (existing private content before WeightCacheEntry close)
for i in range(priv_start_idx + 1, wce_end + 1):
    new_lines.append(lines[i])

# Add lastUse and pinned to WeightCacheEntry
# (they should go before the closing }; of WeightCacheEntry)
# Replace the last line we added (which is the closing }; of WeightCacheEntry)
# with the augmented content
new_lines.pop()  # remove the }; that closes WeightCacheEntry
new_lines.append("        uint64_t lastUse = 0;")
new_lines.append("        bool pinned = false;")
new_lines.append("    };")

# 6. Add remaining original private content (from after WeightCacheEntry to before class_end)
for i in range(wce_end + 1, class_end_idx):
    new_lines.append(lines[i])

# 7. Insert new private block before class_end
for line in new_private_block.split("\n"):
    new_lines.append(line)

# 8. Class end
new_lines.append("};")

# 9. Remaining lines after class_end (namespace close etc)
for i in range(class_end_idx + 1, len(lines)):
    new_lines.append(lines[i])

# Write result
result = line_ending.join(new_lines)
HEADER_PATH.write_text(result, encoding="utf-8")
print("Wrote augmented vulkan_compute.h")
print(f"Old lines: {len(lines)}, New lines: {len(new_lines)}")
