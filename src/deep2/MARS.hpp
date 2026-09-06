// ============================================================================
// MARS.hpp - Memory Allocation + Routing System
// Dynamic dual-GPU VRAM allocator with tensor leases
// Replaces static GPU parity with runtime tensor placement decisions
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <functional>
#include <atomic>
#include <chrono>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Hotpatch Result
// ============================================================================
enum class HotpatchResult {
    SUCCESS = 0,
    SOURCE_NOT_FOUND,
    ALREADY_ON_TARGET,
    GPU_UNHEALTHY,
    DESTINATION_FULL,
    MIGRATION_FAILED
};

// ============================================================================
// Tensor Lease — dynamic GPU ownership (not permanent assignment)
// ============================================================================
struct VRAMLease {
    uint64_t    tensorId = 0;
    std::string tensorName;

    int         currentGPU = -1;      // Where tensor currently lives
    int         preferredGPU = -1;    // Preferred placement hint
    int         originalGPU = -1;     // First placement (for rollback)

    size_t      bytes = 0;
    float       priority = 0.0f;      // Higher = less likely to evict
    bool        hotpatchable = true;  // Can be moved without reload
    bool        resident = false;     // Currently in VRAM
    bool        recoverable = true;   // Can be rebuilt from GGUF
    bool        pinned = false;       // Cannot be evicted

    void*       devicePtr = nullptr;  // GPU-side pointer
    void*       hostPtr = nullptr;    // Host-mapped pointer (if any)

    uint64_t    lastAccess = 0;       // Timestamp of last access
    uint32_t    accessCount = 0;      // Number of accesses

    enum class State {
        HostOnly,       // Not on GPU
        GPU_A,          // On GPU 0
        GPU_B,          // On GPU 1
        Mirrored,       // On both GPUs
        Dropped,        // GPU copy released
        Recovered,      // Restored from GGUF
        Migrating       // In transit
    } state = State::HostOnly;

    void RecordAccess() {
        lastAccess = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count());
        accessCount++;
    }
};

// ============================================================================
// GPU State — per-GPU metrics
// ============================================================================
struct GPUState {
    int     gpuId = -1;
    size_t  totalBytes = 0;
    size_t  usedBytes = 0;
    size_t  freeBytes = 0;
    float   load = 0.0f;
    float   bandwidth = 0.0f;
    float   tps = 0.0f;
    bool    healthy = true;
};

// ============================================================================
// GPU Agent — independent execution agent
// ============================================================================
struct GPUAgent {
    int     id = -1;
    size_t  totalVRAM = 0;
    size_t  freeVRAM = 0;
    float   tps = 0.0f;           // Tokens/sec capability
    float   load = 0.0f;          // Current utilization 0..1
    float   bandwidth = 0.0f;     // GB/s memory bandwidth
    bool    active = false;
    bool    healthy = true;

    bool initialize();
    bool execute(const void* tensor, size_t bytes);
    bool canAccept(size_t bytes) const;
};

// ============================================================================
// Dynamic Parity — runtime GPU state for balancing decisions
// ============================================================================
struct DynamicParity {
    size_t  vramFree[2] = {0, 0};
    float   load[2] = {0.0f, 0.0f};
    float   bandwidth[2] = {0.0f, 0.0f};
    bool    canMoveTensor = true;

    GPUState gpu[2];
    float   imbalance = 0.0f;
    uint64_t lastRebalance = 0;

    void Update(const GPUAgent& gpu0, const GPUAgent& gpu1);
    int SelectBestGPU(size_t bytes, float priority) const;
};

// ============================================================================
// VRAM Block — tracked allocation unit
// ============================================================================
struct VRAMBlock {
    uint64_t tensorId = 0;
    uint64_t offset = 0;
    size_t   bytes = 0;
    int      ownerGPU = -1;       // 0 or 1
    bool     resident = false;
    bool     recoverable = true;  // GGUF source still valid
};

// ============================================================================
// Dual GPU Split — result of tensor placement planning
// ============================================================================
struct DualGPUSplit {
    std::vector<VRAMBlock> gpu0;
    std::vector<VRAMBlock> gpu1;
    size_t                 vramUsed0 = 0;
    size_t                 vramUsed1 = 0;

    bool Validate(size_t vram0, size_t vram1) const;
};

// ============================================================================
// Tensor Recovery Record
// ============================================================================
struct TensorRecovery {
    uint64_t            tensorId = 0;
    VRAMLease::State    previous = VRAMLease::State::HostOnly;
    VRAMLease::State    current  = VRAMLease::State::HostOnly;
    std::string         reason;
};

// ============================================================================
// Eviction Policy
// ============================================================================
enum class EvictionPolicy {
    LRU = 0,
    LFU,
    PRIORITY,
    HYBRID
};

// ============================================================================
// GPU Pool — per-GPU tensor storage
// ============================================================================
struct GPUPool {
    size_t totalBytes = 0;
    size_t usedBytes = 0;
    size_t peakUsedBytes = 0;
    bool healthy = true;
    mutable std::mutex mutex;
    std::unordered_map<uint64_t, std::unique_ptr<VRAMLease>> tensors;
};

// ============================================================================
// LiveTelemetry — observed resource flow for INV-4 learning + Resource Map
// ============================================================================
struct LiveTelemetry {
    uint64_t usedVram[2] = {0, 0};
    uint64_t peakVram[2] = {0, 0};
    uint64_t totalVram[2] = {0, 0};
    uint64_t peakVramTotal = 0;
    uint64_t bytesHostToGpu = 0;
    uint64_t bytesNvmeToRam = 0;
    uint32_t migrations = 0;
    uint32_t residencyMisses = 0;
    uint32_t spillToRam = 0;
    uint32_t spillToNvme = 0;
    uint32_t pinnedCount = 0;
    uint32_t residentCount = 0;
    uint32_t hostOnlyCount = 0;
};

// ============================================================================
// Forward declaration
// ============================================================================
class MARSController;

// ============================================================================
// Tensor Hotpatch — runtime tensor migration
// ============================================================================
class TensorHotpatch {
public:
    explicit TensorHotpatch(MARSController* controller);

    HotpatchResult Redirect(uint64_t tensorId, int targetGPU);
    std::vector<HotpatchResult> RedirectBatch(
        const std::vector<std::pair<uint64_t, int>>& migrations);
    bool Prestage(uint64_t tensorId, int targetGPU);
    bool VerifyIntegrity(uint64_t tensorId);

private:
    MARSController* controller_ = nullptr;
    std::mutex migrationMutex_;
};

// ============================================================================
// MARS Controller — dynamic orchestration layer
// ============================================================================
class MARSController {
public:
    MARSController();
    ~MARSController();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Initialize(size_t gpu0TotalVRAM, size_t gpu1TotalVRAM);
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }

    // ------------------------------------------------------------------------
    // Tensor lease management
    // ------------------------------------------------------------------------
    VRAMLease* PlaceTensor(
        uint64_t    tensorId,
        const std::string& name,
        size_t      bytes,
        float       priority,
        bool        pin = false
    );

    bool EvictTensor(uint64_t tensorId);
    bool EvictLeastImportant(int gpu, size_t minBytesToFree);

    // ------------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------------
    VRAMLease* GetTensor(uint64_t tensorId);
    VRAMLease* FindTensorByName(const std::string& name);
    void RecordTensorAccess(uint64_t tensorId);

    // ------------------------------------------------------------------------
    // Rebalancing
    // ------------------------------------------------------------------------
    void Rebalance();

    // ------------------------------------------------------------------------
    // Fault handling
    // ------------------------------------------------------------------------
    bool HandleTensorFault(uint64_t tensorId);
    bool HandleGPUFailure(int gpu);

    // ------------------------------------------------------------------------
    // Parity
    // ------------------------------------------------------------------------
    DynamicParity GetCurrentParity() const;

    // ------------------------------------------------------------------------
    // Health
    // ------------------------------------------------------------------------
    bool IsGPUHealthy(int gpu) const;
    void MarkGPUUnhealthy(int gpu);
    void MarkGPUHealthy(int gpu);

    // ------------------------------------------------------------------------
    // Hotpatch access
    // ------------------------------------------------------------------------
    TensorHotpatch* GetTensorHotpatch() const { return hotpatch_.get(); }

    // ------------------------------------------------------------------------
    // Live telemetry (INV-4 / Resource Map / TunerSuggest)
    // ------------------------------------------------------------------------
    void ResetRunTelemetry();
    void NoteHostToGpu(uint64_t bytes);
    void NoteNvmeToRam(uint64_t bytes);
    void NoteResidencyMiss();
    void NoteSpillToRam();
    void NoteSpillToNvme();
    LiveTelemetry SnapshotTelemetry() const;
    void CollectEffectivePlacement(
        std::vector<std::pair<std::string, int>>& outNameToGpu) const;

    // ------------------------------------------------------------------------
    // Internal allocation (host placeholder for device memory)
    // ------------------------------------------------------------------------
    void* AllocateDeviceMemory(size_t bytes);
    void FreeDeviceMemory(void* ptr);

private:
    std::atomic<bool> initialized_{false};
    std::mutex globalMutex_;

    GPUPool pools_[2];

    std::atomic<size_t> totalAllocated_{0};
    std::atomic<size_t> totalFreed_{0};
    std::atomic<size_t> migrationCount_{0};
    std::atomic<size_t> faultCount_{0};
    std::atomic<uint64_t> bytesHostToGpu_{0};
    std::atomic<uint64_t> bytesNvmeToRam_{0};
    std::atomic<uint32_t> residencyMisses_{0};
    std::atomic<uint32_t> spillToRam_{0};
    std::atomic<uint32_t> spillToNvme_{0};

    size_t minFreeBytes_ = 64 * 1024 * 1024;  // 64 MB minimum free
    float rebalanceThreshold_ = 0.2f;        // 20% imbalance threshold
    EvictionPolicy evictionPolicy_ = EvictionPolicy::HYBRID;

    std::unique_ptr<TensorHotpatch> hotpatch_;

    void TouchPeakLocked(int gpu);

    // Internal methods (friend access for TensorHotpatch)
    int SelectBestGPU(size_t bytes, float priority);
    bool CanFit(int gpu, size_t bytes);
    size_t CalculateEvictionScore(const VRAMLease& lease);
    bool MigrateTensorInternal(uint64_t tensorId, int sourceGPU, int targetGPU);
    void UpdateParityMetrics();

    friend class TensorHotpatch;
};

// Optional process-wide MARS used by observation / Resource Map (nullable).
inline MARSController*& ActiveMARSController() {
    static MARSController* p = nullptr;
    return p;
}

// ============================================================================
// Free helpers
// ============================================================================
DualGPUSplit SplitGGUFTensors(
    const std::vector<std::pair<std::string, size_t>>& namedSizes,
    size_t gpu0VRAM,
    size_t gpu1VRAM
);

} // namespace MARS
} // namespace Deep2
