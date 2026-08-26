// ============================================================================
// ElasticResidencyManager.hpp
// VAL-051.7+ — Unified tensor residency with representation-aware staging
// and in-flight ownership state machine.
//
// Architecture:
//   Cold (NVMe/GGUF) → StreamingIn → WarmCompressed → WarmStaged →
//   Uploading → Hot (VRAM) → Evicting → (back to WarmCompressed or Cold)
//
// Key invariant: GPU_WAIT_US ≈ 0. All transfers are async and predictive.
// ============================================================================

#ifndef ELASTIC_RESIDENCY_MANAGER_HPP
#define ELASTIC_RESIDENCY_MANAGER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <thread>
#include <queue>
#include <chrono>

namespace Deep2 {

// ============================================================================
// Residency State Machine
// ============================================================================
enum class ResidencyState : uint8_t {
    Cold          = 0,   // On NVMe / GGUF only. Not in RAM.
    StreamingIn   = 1,   // Async IO in progress NVMe → RAM.
    WarmCompressed= 2,   // In RAM, native quantized format (Q4_0, Q4_K, etc).
    WarmStaged    = 3,   // In RAM, dequantized to FP16/FP32 for backend that needs it.
    Uploading     = 4,   // Async DMA in progress RAM → VRAM.
    Hot           = 5,   // In VRAM, ready for GPU compute.
    Evicting      = 6,   // Async DMA/completion in progress VRAM → RAM or free.
    Failed        = 7,   // Terminal error state (e.g., allocation failure, validation error).
};

// ============================================================================
// Tensor Representation Format
// ============================================================================
enum class TensorFormat : uint8_t {
    Unknown       = 0,
    Q4_0          = 1,   // GGML_TYPE_Q4_0
    Q4_1          = 2,   // GGML_TYPE_Q4_1
    Q4_K          = 3,   // GGML_TYPE_Q4_K
    Q5_0          = 4,   // GGML_TYPE_Q5_0
    Q5_1          = 5,   // GGML_TYPE_Q5_1
    Q5_K          = 6,   // GGML_TYPE_Q5_K
    Q6_K          = 7,   // GGML_TYPE_Q6_K
    Q8_0          = 8,   // GGML_TYPE_Q8_0
    Q2_K          = 9,   // GGML_TYPE_Q2_K
    Q3_K          = 10,  // GGML_TYPE_Q3_K
    FP16          = 11,  // Native FP16
    FP32          = 12,  // Native FP32
};

// ============================================================================
// Residency Configuration
// ============================================================================
struct ElasticResidencyConfig {
    // RAM budget for compressed weights (the "warm" tier)
    size_t maxWarmCompressedBytes = 4ULL * 1024 * 1024 * 1024;  // 4 GB default

    // RAM budget for staged (dequantized) weights. Ephemeral.
    size_t maxWarmStagedBytes = 512ULL * 1024 * 1024;         // 512 MB default

    // VRAM budget for hot weights (current + prefetch)
    size_t maxHotBytes = 2ULL * 1024 * 1024 * 1024;           // 2 GB default

    // Page alignment for mappings
    size_t pageAlignment = 4096;

    // NVMe read granularity
    size_t nvmeReadGranularity = 65536;

    // Number of layers to prefetch ahead
    uint32_t prefetchLookahead = 2;

    // Whether to keep staged buffers after upload (for CPU fallback)
    bool retainStagedAfterUpload = false;

    // Whether to use quantized GEMV directly on GPU (skip staging)
    bool useQuantizedGpuPath = false;

    // Expert-aware: number of experts to keep hot for MoE
    uint32_t moeHotExpertCount = 4;
};

// ============================================================================
// Telemetry Counters (expanded per user spec)
// ============================================================================
struct ResidencyTelemetry {
    std::atomic<uint64_t> nvmeReadUs{0};
    std::atomic<uint64_t> ramStageUs{0};
    std::atomic<uint64_t> ramToVramUs{0};
    std::atomic<uint64_t> gpuWaitUs{0};
    std::atomic<uint64_t> gpuComputeUs{0};
    std::atomic<uint64_t> prefetchHit{0};
    std::atomic<uint64_t> prefetchMiss{0};
    std::atomic<uint64_t> vramEvictionUs{0};
    std::atomic<uint64_t> cpuFallbackUs{0};
    std::atomic<uint64_t> stateRaceBlocked{0};  // times a transition was blocked

    void Reset() {
        nvmeReadUs = 0; ramStageUs = 0; ramToVramUs = 0;
        gpuWaitUs = 0; gpuComputeUs = 0;
        prefetchHit = 0; prefetchMiss = 0;
        vramEvictionUs = 0; cpuFallbackUs = 0; stateRaceBlocked = 0;
    }

    void Initialize(int /*numLayers*/, int /*numExperts*/) {
        Reset();
    }

    void PrintReport() const {
        printf("--- Residency Telemetry Report ---\n");
        printf("  NVMe read us      : %llu\n", (unsigned long long)nvmeReadUs.load());
        printf("  RAM stage us      : %llu\n", (unsigned long long)ramStageUs.load());
        printf("  RAM->VRAM us      : %llu\n", (unsigned long long)ramToVramUs.load());
        printf("  GPU wait us       : %llu\n", (unsigned long long)gpuWaitUs.load());
        printf("  GPU compute us    : %llu\n", (unsigned long long)gpuComputeUs.load());
        printf("  Prefetch hits     : %llu\n", (unsigned long long)prefetchHit.load());
        printf("  Prefetch misses   : %llu\n", (unsigned long long)prefetchMiss.load());
        printf("  VRAM eviction us  : %llu\n", (unsigned long long)vramEvictionUs.load());
        printf("  CPU fallback us   : %llu\n", (unsigned long long)cpuFallbackUs.load());
        printf("  State race blocked: %llu\n", (unsigned long long)stateRaceBlocked.load());
        printf("  Efficiency        : %.4f\n", ComputeEfficiency());
        printf("----------------------------------\n");
    }

    double ComputeEfficiency() const {
        uint64_t compute = gpuComputeUs.load();
        uint64_t wait = gpuWaitUs.load();
        if (compute + wait == 0) return 0.0;
        return (double)compute / (double)(compute + wait);
    }
};

// ============================================================================
// Resident Tensor Entry (unified)
// ============================================================================
struct ElasticResidentTensor {
    std::string name;
    uint32_t layerIndex = 0;        // for dense transformers
    uint32_t expertIndex = ~0u;     // ~0u = dense, else MoE expert ID

    // Source location in GGUF
    size_t fileOffset = 0;
    size_t compressedBytes = 0;
    const void* sourceData = nullptr; // optional: already-mapped GGUF data pointer

    // RAM buffers (representation-aware)
    void* compressedData = nullptr;   // WarmCompressed: native quantized bytes
    size_t compressedAllocated = 0;

    void* stagedData = nullptr;       // WarmStaged: FP16/FP32 for CPU/GPU upload
    size_t stagedBytes = 0;
    size_t stagedAllocated = 0;

    // VRAM buffer
    void* gpuData = nullptr;          // Hot: device memory handle (opaque)
    size_t gpuBytes = 0;

    // State machine
    std::atomic<ResidencyState> state{ResidencyState::Cold};
    std::atomic<uint32_t> generation{0};      // incremented on every eviction
    std::atomic<uint64_t> lastUseSequence{0}; // LRU
    std::atomic<uint32_t> inFlightOps{0};   // refcount for async ops

    // Format tracking
    TensorFormat nativeFormat = TensorFormat::Unknown;
    TensorFormat stagedFormat = TensorFormat::Unknown;  // what stagedData holds

    // For predictive prefetch: predicted next use layer/token
    std::atomic<uint32_t> predictedNextLayer{~0u};
};

// ============================================================================
// Transfer Request (internal scheduler queue)
// ============================================================================
struct TransferRequest {
    enum class Type : uint8_t {
        NvmeToRam,      // Cold → WarmCompressed
        DequantStage,   // WarmCompressed → WarmStaged
        RamToVram,      // WarmStaged or WarmCompressed → Hot
        VramToRam,      // Hot → WarmCompressed (eviction)
        FreeStaged,     // WarmStaged → WarmCompressed
    };
    Type type;
    std::string tensorName;
    uint32_t priority = 0;  // lower = higher priority
    std::chrono::steady_clock::time_point enqueueTime;
};

// ============================================================================
// Expert Prediction Interface (for MoE)
// ============================================================================
class IExpertPredictor {
public:
    virtual ~IExpertPredictor() = default;
    // Given current layer and hidden state, return predicted top-K expert IDs
    virtual std::vector<uint32_t> PredictNextExperts(
        uint32_t currentLayer,
        const void* hiddenState,   // opaque: FP32 vector of hidden_dim
        size_t hiddenDim,
        uint32_t topK) = 0;
};

// ============================================================================
// ElasticResidencyManager
// ============================================================================
class ElasticResidencyManager {
public:
    ElasticResidencyManager();
    ~ElasticResidencyManager();

    // Non-copyable, non-movable
    ElasticResidencyManager(const ElasticResidencyManager&) = delete;
    ElasticResidencyManager& operator=(const ElasticResidencyManager&) = delete;

    // ── Lifecycle ────────────────────────────────────────────────────
    bool Initialize(const ElasticResidencyConfig& config);
    void Shutdown();

    // ── Tensor Registration ──────────────────────────────────────────
    // Register a tensor that lives in the GGUF at fileOffset, compressedBytes.
    bool RegisterTensor(const std::string& name,
                        uint32_t layerIndex,
                        uint32_t expertIndex,
                        size_t fileOffset,
                        size_t compressedBytes,
                        TensorFormat nativeFormat,
                        const void* sourceData = nullptr);

    // ── State Queries ────────────────────────────────────────────────
    ResidencyState GetTensorState(const std::string& name) const;
    bool IsTensorReadyForCompute(const std::string& name) const;  // Hot or WarmStaged

    // ── Synchronous Acquire (for CPU path) ───────────────────────────
    // Returns a pointer to usable weight data. May trigger staging.
    // For quantized CPU kernels: returns compressedData.
    // For FP32 CPU kernels: returns stagedData.
    const void* AcquireForCpu(const std::string& name, TensorFormat desiredFormat);
    void ReleaseFromCpu(const std::string& name);

    // ── Async Prefetch (for GPU path) ────────────────────────────────
    // Request that tensor become Hot by the time it is needed.
    // Non-blocking. Returns immediately; actual work happens on scheduler thread.
    void PrefetchToGpu(const std::string& name, uint32_t targetLayer);

    // ── GPU Compute Binding ──────────────────────────────────────────
    // Called by Deep2Engine before launching a kernel.
    // Ensures tensor is Hot. Blocks ONLY if prefetch failed to keep up.
    const void* BindForGpuCompute(const std::string& name);
    void UnbindFromGpuCompute(const std::string& name);

    // ── Predictive Scheduling ──────────────────────────────────────
    // Set the expert predictor for MoE-aware prefetch.
    void SetExpertPredictor(std::shared_ptr<IExpertPredictor> predictor);

    // Notify scheduler of upcoming layer/expert needs.
    void PredictLayerNeeds(uint32_t nextLayer,
                           const void* routerHiddenState,
                           size_t hiddenDim);

    // ── Eviction / Memory Pressure ───────────────────────────────────
    void EvictLeastRecentlyUsed(size_t bytesNeeded);
    void EvictAllHot();  // Emergency: free all VRAM

    // ── Telemetry ────────────────────────────────────────────────────
    const ResidencyTelemetry& GetTelemetry() const { return telemetry_; }
    void PrintTelemetry() const;

    // ── Internal: Scheduler Thread ───────────────────────────────────
    void SchedulerThreadBody();

private:
    // ── State Transition Guards ──────────────────────────────────────
    // Attempt atomic transition. Returns false if tensor is in a conflicting
    // in-flight state (e.g., trying to evict while uploading).
    bool TryTransition(const std::string& name,
                       ResidencyState expected,
                       ResidencyState desired);

    // ── Transfer Implementations ───────────────────────────────────
    void ExecuteNvmeToRam(ElasticResidentTensor& tensor);
    void ExecuteDequantStage(ElasticResidentTensor& tensor);
    void ExecuteRamToVram(ElasticResidentTensor& tensor);
    void ExecuteVramToRam(ElasticResidentTensor& tensor);
    void ExecuteFreeStaged(ElasticResidentTensor& tensor);

    // ── Memory Accounting ────────────────────────────────────────────
    bool ReserveWarmCompressed(size_t bytes);
    bool ReserveWarmStaged(size_t bytes);
    bool ReserveHot(size_t bytes);
    void ReleaseWarmCompressed(size_t bytes);
    void ReleaseWarmStaged(size_t bytes);
    void ReleaseHot(size_t bytes);

    // ── Helpers ──────────────────────────────────────────────────────
    // Returns a shared_ptr to keep tensor alive while caller holds reference.
    std::shared_ptr<ElasticResidentTensor> FindTensor(const std::string& name);
    std::shared_ptr<const ElasticResidentTensor> FindTensor(const std::string& name) const;
    void EnqueueRequest(TransferRequest::Type type,
                        const std::string& name,
                        uint32_t priority);

    // ── Members ──────────────────────────────────────────────────────
    ElasticResidencyConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdownRequested_{false};

    std::map<std::string, std::shared_ptr<ElasticResidentTensor>> tensors_;
    mutable std::mutex tensorsMutex_;

    // Scheduler queue
    std::queue<TransferRequest> requestQueue_;
    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::thread schedulerThread_;

    // State-change notification for blocking waits (e.g. BindForGpuCompute)
    std::condition_variable stateCv_;

    // Memory budgets (tracked)
    std::atomic<size_t> warmCompressedUsed_{0};
    std::atomic<size_t> warmStagedUsed_{0};
    std::atomic<size_t> hotUsed_{0};

    // LRU sequence counter
    std::atomic<uint64_t> useSequence_{0};

    // Telemetry
    ResidencyTelemetry telemetry_;

    // Expert predictor (optional, for MoE)
    std::shared_ptr<IExpertPredictor> expertPredictor_;
    mutable std::mutex predictorMutex_;

    // File handle for NVMe reads (platform-specific)
    void* fileHandle_ = nullptr;  // Windows: HANDLE, Linux: int fd
};

} // namespace Deep2

#endif // ELASTIC_RESIDENCY_MANAGER_HPP
