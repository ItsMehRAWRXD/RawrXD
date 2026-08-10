#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <array>
#include <functional>
#include <mutex>

// Define RAWR_VULKAN_AVAILABLE before including gguf_loader.h so that
// vulkan_compute.h uses the correct type definitions (real Vulkan or stubs).
#if defined(RAWR_ENABLE_VULKAN) || defined(RAWR_HAS_VULKAN)
    #if __has_include(<vulkan/vulkan.h>)
        #define RAWR_VULKAN_AVAILABLE 1
    #else
        #pragma message("Vulkan SDK headers not found — using CPU fallback for dual GPU testing")
        #define RAWR_VULKAN_AVAILABLE 0
    #endif
#else
    #define RAWR_VULKAN_AVAILABLE 0
#endif

#ifndef VK_NULL_HANDLE
#define VK_NULL_HANDLE 0
#endif

#include "gguf_loader.h"

// Vulkan handle/struct types. The header under include/ (NOT the src/ file of
// the same name, which is a real VulkanCompute wrapper that hard-requires the
// SDK) is the single source of truth: it provides real Vulkan types when the
// SDK is present and CPU-fallback stubs otherwise. Include it explicitly by a
// path that cannot resolve to the adjacent src/vulkan_compute.h.
#include "../include/vulkan_compute.h"

#include <windows.h>

// B014: Per-invocation compute decomposition profiler
#include "../B014/build/b014_profiler.hpp"

// A few extra Vulkan handle typedefs the loader references that the CPU
// fallback in vulkan_compute.h may not declare. Guard against real headers.
#if !RAWR_VULKAN_AVAILABLE
#ifndef VK_VERSION_1_0
#ifndef RAWR_MODEL_LOADER_VK_EXTRA_STUBS
#define RAWR_MODEL_LOADER_VK_EXTRA_STUBS
typedef uint32_t VkFlags;
#endif
#endif
#endif

struct Tensor
{
    std::string name;
  uint64_t tensor_index = 0;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
    void* data;  // Mapped pointer (Raw)

    // Vulkan
    VkBuffer gpuBuffer = VK_NULL_HANDLE;
    VkDeviceMemory gpuMemory = VK_NULL_HANDLE;
    bool onGPU = false;

    // CPU Float cache for reference implementation
    std::vector<float> cpuFloatData;
};

/// File-backed byte span for a tensor (Swarm / prefetch planning). Offsets are relative to GGUF payload.
struct TensorFileSpan
{
    std::string name;
    std::uint64_t fileOffset = 0;
    std::uint64_t sizeBytes = 0;
};

// struct GGUFHeader removed - use definition in RawrXD_Interfaces.h via gguf_loader.h if needed
// Or rely on the fact that RawrXD_Interfaces.h is the source of truth.

// GGUF Q4_0 block structure
struct Q4_0_Block
{
    uint16_t d;      // float16 scale
    uint8_t qs[16];  // 32 nibbles
};

class RawrXDModelLoader
{
  public:
    class StreamingPin
    {
      public:
        StreamingPin(RawrXDModelLoader* loader, uint64_t offset, size_t size);
        ~StreamingPin();

        StreamingPin(const StreamingPin&) = delete;
        StreamingPin& operator=(const StreamingPin&) = delete;

        StreamingPin(StreamingPin&& other) noexcept;
        StreamingPin& operator=(StreamingPin&& other) noexcept;

        bool IsValid() const { return m_base != nullptr; }
        void* GetPointer(uint64_t localOffset) const;
        size_t GetSize() const { return m_size; }

      private:
        RawrXDModelLoader* m_loader = nullptr;
        void* m_base = nullptr;
        size_t m_size = 0;
    };

    RawrXDModelLoader();
    ~RawrXDModelLoader();
    using ModelLoadErrorCallback = std::function<void(const std::string& stage, const std::string& message)>;

    bool Load(const wchar_t* path, VkDevice device, VkPhysicalDevice physDevice);
    virtual float* GetTensor(const std::string& name);
    virtual bool GetTensorRow(const std::string& name, size_t rowIndex, float* out, size_t cols);
    bool StreamingMatMul(const std::string& name, const float* x, float* y, size_t K, size_t N);

    // B010: Weight-residency profiling counters (profiling-only, no caching)
    struct WeightAccessProfile
    {
        std::atomic<std::uint64_t> totalCalls{0};           // Total StreamingMatMul calls
        std::atomic<std::uint64_t> totalBytesRead{0};       // Sum of rowBytes * rows processed
        std::atomic<std::uint64_t> totalMapCalls{0};        // StreamingPin constructions (map attempts)
        std::atomic<std::uint64_t> totalUnmapCalls{0};      // StreamingPin destructions (unmap)
        std::atomic<std::uint64_t> totalIncidentalMaps{0};  // MapIncidentalWindow calls
        std::atomic<std::uint64_t> totalAcquisitionNs{0};   // Time in tensor lookup + pin
        std::atomic<std::uint64_t> totalComputeNs{0};       // Time in dequant + dot product
        // B013: Fine-grained compute decomposition
        std::atomic<std::uint64_t> totalDequantNs{0};       // Time in Q4_K → F32 dequantization only
        std::atomic<std::uint64_t> totalDotProductNs{0};    // Time in dot-product / GEMM only
        std::atomic<std::uint64_t> totalLoopOverheadNs{0};  // Time in loop/indexing/packing overhead
        std::atomic<std::uint64_t> totalSyncNs{0};          // Time in thread sync / scheduling
        std::atomic<std::uint64_t> uniqueTensorsAcquired{0}; // Unique tensor names loaded
        std::unordered_map<std::string, std::atomic<std::uint64_t>> perTensorCalls;
        std::mutex perTensorMutex;
    };
    WeightAccessProfile m_weightProfile;
    void ResetWeightProfile() ;
    void PrintWeightProfile() const;

    // ============================================================================
    // B011 — Weight Residency Cache
    // ============================================================================
    struct B011ResidencyStats
    {
        std::atomic<std::uint64_t> acquisitions{0};
        std::atomic<std::uint64_t> cacheHits{0};
        std::atomic<std::uint64_t> cacheMisses{0};
        std::atomic<std::uint64_t> mapCount{0};
        std::atomic<std::uint64_t> unmapCount{0};
        std::atomic<std::uint64_t> bytesRead{0};
        std::atomic<std::uint64_t> bytesResident{0};
        std::atomic<std::uint64_t> acquisitionNs{0};
        std::atomic<std::uint64_t> computeNs{0};
        // B013: Fine-grained compute decomposition (mirrors WeightAccessProfile)
        std::atomic<std::uint64_t> dequantNs{0};
        std::atomic<std::uint64_t> dotProductNs{0};
        std::atomic<std::uint64_t> loopOverheadNs{0};
        std::atomic<std::uint64_t> syncNs{0};

        void Reset()
        {
            acquisitions.store(0, std::memory_order_relaxed);
            cacheHits.store(0, std::memory_order_relaxed);
            cacheMisses.store(0, std::memory_order_relaxed);
            mapCount.store(0, std::memory_order_relaxed);
            unmapCount.store(0, std::memory_order_relaxed);
            bytesRead.store(0, std::memory_order_relaxed);
            bytesResident.store(0, std::memory_order_relaxed);
            acquisitionNs.store(0, std::memory_order_relaxed);
            computeNs.store(0, std::memory_order_relaxed);
            dequantNs.store(0, std::memory_order_relaxed);
            dotProductNs.store(0, std::memory_order_relaxed);
            loopOverheadNs.store(0, std::memory_order_relaxed);
            syncNs.store(0, std::memory_order_relaxed);
        }
    };

    struct B011ResidentWeight
    {
        std::shared_ptr<std::vector<uint8_t>> storage;
        uint64_t fileOffset = 0;
        uint64_t byteSize = 0;
        uint64_t modelGeneration = 0;
        std::atomic<std::uint64_t> lastUse{0};
    };

    void B011ResetResidencyStats();
    void B011PrintResidencyStats() const;
    void B011EnableResidency(bool enabled);
    bool B011ResidencyEnabled() const;
    void B011ClearResidency();
    const B011ResidencyStats& B011GetStats() const { return m_b011Stats; }

    // B014: Per-invocation compute decomposition profiler accessors
    void B014EnableProfiling(bool enabled) { m_b014Profiler.Enable(enabled); }
    bool B014ProfilingEnabled() const { return m_b014Profiler.IsEnabled(); }
    void B014ClearProfile() { m_b014Profiler.Clear(); }
    rawrxd::b014::B014Profiler::Summary B014ComputeSummary() const { return m_b014Profiler.ComputeSummary(); }
    bool B014ExportProfileJson(const std::string& path) const { return m_b014Profiler.ExportJson(path); }
    bool B014ExportProfileCsv(const std::string& path) const { return m_b014Profiler.ExportCsv(path); }
    bool GetTensorResidencyInfo(const std::string& name, std::uint64_t& canonicalId,
                  std::uint64_t& storageBytes) const
    {
      auto it = m_tensors.find(name);
      if (it == m_tensors.end())
      {
        return false;
      }

      const Tensor& t = it->second;
      canonicalId = static_cast<std::uint64_t>(t.tensor_index);
      storageBytes = static_cast<std::uint64_t>(CalculateTensorDataSize(t));
      return true;
    }
    void ReleaseTensor(const std::string& name);
    void SetLoadErrorCallback(ModelLoadErrorCallback callback);
    const std::string& GetLastLoadErrorMessage() const;
    bool UsingLargePages() const { return m_useLargePages; }
    uint64_t GetFileSizeBytes() const { return m_fileSize; }
    [[nodiscard]] std::vector<TensorFileSpan> listTensorFileSpans() const;
    void* GetCurrentViewBase() const;
    void* GetCurrentView() const;
    void SetPrefetchEnabled(bool enabled) { m_prefetchEnabled = enabled; }
    void SetWorkingSetLockEnabled(bool enabled) { m_workingSetLockEnabled = enabled; }
    void SetSilencePrivilegeWarnings(bool enabled) { m_silencePrivilegeWarnings = enabled; }
    bool HintRange(uint64_t offset, size_t size);

  private:
    // B011: Weight residency cache
    mutable std::mutex m_b011ResidencyMutex;
    std::unordered_map<std::string, std::shared_ptr<B011ResidentWeight>> m_b011Residency;
    B011ResidencyStats m_b011Stats;
    std::atomic<bool> m_b011ResidencyEnabled{false};
    std::atomic<std::uint64_t> m_b011ResidencyGeneration{1};
    std::atomic<std::uint64_t> m_b011ResidencyClock{0};

    std::shared_ptr<B011ResidentWeight> B011AcquireResidentWeight(
        const std::string& tensorName,
        const uint8_t* source,
        size_t bytes,
        uint64_t fileOffset);

    // B014: Per-invocation compute decomposition profiler
    rawrxd::b014::B014Profiler m_b014Profiler;

    VkDevice m_device;
    VkPhysicalDeviceMemoryProperties m_memProps;
    HANDLE m_file;
    HANDLE m_mapping;
    void* m_mappedView;
    uint64_t m_fileSize;
    bool m_useLargePages = false;
    bool m_prefetchEnabled = false;
    bool m_workingSetLockEnabled = false;
    bool m_workingSetLocked = false;
    bool m_silencePrivilegeWarnings = false;

    // Sliding window memory mapping for large files
    void* virtualBase;    // Reserved virtual address space
    uint64_t windowSize;  // Size of each mapping window (2GB default)

    /// Tier-1 multi-window: several independent compute MapViews (legacy path); sovereign/reserved use slot 0.
    struct ComputeMapSlot
    {
        void* view = nullptr;
        void* viewBase = nullptr;
        uint64_t fileOffset = 0;
        size_t mappedSize = 0;
        uint64_t lastTouch = 0;
        bool usesPlaceholderUnmap = false;
        bool usesReservedApertureEx = false;
        /// Refcount: slot must not be LRU-evicted while >0 (see markComputeRangeInUse).
        std::uint32_t inUseCount = 0;
    };
    static constexpr std::size_t kMaxComputeMapSlots = 3;
    std::array<ComputeMapSlot, kMaxComputeMapSlots> m_computeSlots{};
    uint64_t m_computeSlotClock = 0;
    mutable std::atomic<std::uint64_t> m_slidingTelNoEvictableSlot{0};
    mutable std::atomic<std::uint64_t> m_slidingTelSovereignRemapInUse{0};
    mutable std::atomic<std::uint64_t> m_slidingTelPromotionSkipped{0};
    mutable std::atomic<std::uint64_t> m_slidingTelSwarmPinBackoffCycles{0};
    bool m_placeholderApertureActive = false;
    bool m_reservedApertureActive = false;
    bool m_reservedApertureReserved = false;
    bool m_streamingActive = false;
    uint32_t m_streamingDepth = 0;
    uint64_t m_streamingRangeStart = 0;
    uint64_t m_streamingRangeEnd = 0;
    size_t m_streamingLockedWindowSize = 0;

    /// Serialize compute window (MapWindow) vs prefetch window (MapPrefetchWindow) for safe dual mapping.
    mutable std::mutex m_slidingWindowMutex;
    uint64_t prefetchOffset = 0;
    size_t prefetchViewSize = 0;
    void* prefetchView = nullptr;
    void* prefetchViewBase = nullptr;
    void unmapComputeViewLocked_();
    void unmapComputeSlotLocked_(std::size_t index);
    void bumpComputeSlotTouchLocked_(ComputeMapSlot& slot);
    [[nodiscard]] std::size_t findEmptyComputeSlotIndexLocked_() const;
    /// LRU among slots in [firstInclusive, lastExclusive) that have a view and inUseCount==0; returns
    /// m_computeSlots.size() if none.
    [[nodiscard]] std::size_t pickLruEvictableAmongLocked_(std::size_t firstInclusive, std::size_t lastExclusive) const;
    [[nodiscard]] ComputeMapSlot* findComputeSlotCoveringLocked_(uint64_t offset, size_t size);
    /// Returns m_computeSlots.size() if no slot can be used (all occupied and in-use).
    [[nodiscard]] std::size_t pickComputeSlotForLegacyMapLocked_();
    [[nodiscard]] std::size_t pickComputeSlotForPromotionLocked_();
    [[nodiscard]] bool mapNewViewIntoComputeSlotLocked_(std::size_t slotIndex, uint64_t windowStart, size_t& mapSize,
                                                        bool useSovereign, bool useReservedAperture,
                                                        uint64_t apertureSize, uint64_t offset, size_t requestSize);
    void unmapPrefetchViewLocked_();

    // Metadata
    int n_embd = 0;
    int n_layers = 0;
    int n_heads = 0;
    int n_heads_kv = 0;
    int n_ctx = 0;
    int vocab_size = 0;
    int n_ffn = 0;  // feed_forward_length (0 = infer from dim*4)
    int n_experts = 0;
    int n_experts_used = 0;
    std::string m_metadataArchitecture;
    std::string m_metadataTokenizerModel;
    uint32_t m_metadataFileType = 0xFFFFFFFFu;  // GGUF file_type identifier
    bool m_gpuUploadEnabled = true;
    std::string m_lastLoadErrorStage;
    std::string m_lastLoadErrorMessage;
    ModelLoadErrorCallback m_loadErrorCallback;

    // Persistent Vulkan transfer resources (lazily initialized on first upload)
    VkPhysicalDevice m_physDevice = VK_NULL_HANDLE;
    VkQueue m_transferQueue = VK_NULL_HANDLE;
    VkCommandPool m_transferCmdPool = VK_NULL_HANDLE;
    uint32_t m_transferQueueFamily = 0;
    std::mutex m_transferInitMutex;
    bool m_transferInitOk = false;

    bool InitTransferResources();

  public:
    int getDim() const { return n_embd; }
    int getLayers() const { return n_layers; }
    int getHeads() const { return n_heads; }
    int getKVHeads() const { return n_heads_kv; }
    int getCtx() const { return n_ctx; }
    int getVocabSize() const { return vocab_size; }
    int getFFNDim() const { return n_ffn; }
    int getExperts() const { return n_experts; }
    /// MoE metadata (`expert_used_count`); 0 if unset — callers may fall back to a small default.
    int getExpertsUsedCount() const { return n_experts_used; }
    /// True if \p name appears in the loaded tensor map (does not materialize weights).
    [[nodiscard]] bool hasTensorNamed(const std::string& name) const;

  private:
    std::unordered_map<std::string, Tensor> m_tensors;

  public:
    // Helpers
    uint8_t* ParseMetadata(uint8_t* ptr, uint64_t count);
    uint8_t* ParseTensorInfo(uint8_t* ptr, Tensor& t);
    [[nodiscard]] size_t CalculateTensorDataSize(const Tensor& t) const;
    void LoadTensorAsync(Tensor& t);
    void DequantAndUploadQ4_0(Tensor& t, void* blocks, size_t N);
    void DequantAndUploadQ8_0(Tensor& t, void* blocks, size_t N);
    void DequantAndUploadQ4_K(Tensor& t, void* blocks, size_t N);
    void UploadF32(Tensor& t, void* data, size_t N);
    void CreateGPUBuffer(Tensor& t, void* data, size_t size);
    void UploadViaStaging(void* data, size_t size, VkBuffer dstBuffer);
    uint32_t FindMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties);
    int64_t CalculateVRAMUsage();

    // Chunked processing for large tensors
    void DequantChunkQ4_0(Tensor& t, void* blocks, size_t chunkElements, size_t offset);
    void DequantChunkQ8_0(Tensor& t, void* blocks, size_t chunkElements, size_t offset);
    void DequantChunkQ4_K(Tensor& t, void* blocks, size_t chunkElements, size_t offset);
    void DequantChunkQ4_0_AVX512(Tensor& t, void* blocks, size_t chunkElements, size_t offset);
    void DequantChunkQ2_K(Tensor& t, void* blocks, size_t chunkElements, size_t offset);
    void DequantChunkQ3_K(Tensor& t, void* blocks, size_t chunkElements, size_t offset);
    void DequantChunkQ5_K(Tensor& t, void* blocks, size_t chunkElements, size_t offset);
    void DequantChunkQ6_K(Tensor& t, void* blocks, size_t chunkElements, size_t offset);
    void UploadChunkF32(Tensor& t, void* data, size_t chunkElements, size_t offset);
    void UploadToGPU(Tensor& t);

    // Sliding window mapping helpers
    bool InitializeSlidingWindow(uint64_t fileSize);
    void CleanupSlidingWindow();
    void* MapWindow(uint64_t offset, size_t size);
    void UnmapWindow();
    /// Refcount the compute slot that fully contains [offset, offset+size). Call after MapWindow/pin; pair with unmark.
    void markComputeRangeInUse(std::uint64_t offset, std::uint64_t size);
    void unmarkComputeRangeInUse(std::uint64_t offset, std::uint64_t size);
    /// Independent MapViewOfFile-backed range for background prefetch (Swarm). Never replaces the compute MapWindow.
    void* MapPrefetchWindow(uint64_t offset, size_t size);
    void UnmapPrefetchWindow();
    /// True while a prefetch MapView exists (false after promotion into compute or explicit unmap).
    bool HasActivePrefetchMapping() const;
    /// True if the active compute MapWindow fully covers [offset, offset+size) in file space.
    bool ComputeMappingCovers(uint64_t offset, uint64_t size) const;

    /// Counters for MapWindow pressure / Swarm pin backoff (relaxed atomics; tuning only).
    struct SlidingWindowTelemetry
    {
        std::uint64_t noEvictableComputeSlot = 0;
        std::uint64_t sovereignRemapBlockedInUse = 0;
        std::uint64_t promotionSkippedNoEvictableSlot = 0;
        std::uint64_t swarmPinBackoffCycles = 0;
    };
    [[nodiscard]] SlidingWindowTelemetry slidingWindowTelemetrySnapshot() const;
    void recordSwarmPinBackoffCycle() const;
    bool MapIncidentalWindow(uint64_t offset, size_t size, void*& viewBase, uint8_t*& dataPtr);
    void UnmapIncidentalWindow(void* viewBase);
    void BeginStreamingRange(uint64_t offset, size_t size);
    void EndStreamingRange();
    // Internal demonstration / self-test helper
    void RunInternalSelfTest();

    // Sovereign capabilities demonstration
    void DemonstrateSovereignCapabilities();

    // Backend mode and file type validation
    bool IsSupportedFileType(uint32_t fileType) const;
    bool ResolveBackendModeAndPreflight(const wchar_t* path, uint64_t modelBytes, std::string& lane,
                                        std::string& reason);
};
