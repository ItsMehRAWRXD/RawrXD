// ============================================================================
// DualGPUHook.hpp - Hook/Unhook System for Dual GPU Recovery
// ============================================================================
// Attaches to a TensorGraph to freeze residency, enable recovery, and
// restore GPU placement after reverse hotpatch operations.
//
// Rule: DROP only GPU copies. Never drop GGUF source data.
//       VRAM tensor → DROP → GGUF mapped tensor → VERIFY → GPU tensor → RECREATE
// ============================================================================

#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <mutex>
#include <functional>

namespace Deep2 {

// Forward declarations
struct TensorInfo;
class TensorGraph;

// ============================================================================
// VRAM Block — tracks residency for one tensor on one GPU
// ============================================================================
struct VRAMBlock {
    uint64_t tensorId  = 0;
    uint64_t offset    = 0;     // Offset within GPU memory pool
    size_t   bytes     = 0;

    int      ownerGPU  = -1;    // 0 or 1; -1 = host/unassigned
    bool     resident  = false; // Currently in VRAM?
    bool     recoverable = true; // Can be rebuilt from GGUF source?

    std::string name;
};

// ============================================================================
// Dual GPU Split — result of partitioning a model across two GPUs
// ============================================================================
struct DualGPUSplit {
    std::vector<VRAMBlock> gpu0;
    std::vector<VRAMBlock> gpu1;

    size_t TotalBlocks() const { return gpu0.size() + gpu1.size(); }
    size_t TotalBytesGPU0() const;
    size_t TotalBytesGPU1() const;
};

// ============================================================================
// Dual GPU Hook
// ============================================================================
class DualGPUHook {
public:
    DualGPUHook();
    ~DualGPUHook();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Attach(TensorGraph& graph);
    void Detach(TensorGraph& graph);
    bool IsActive() const { return active_; }

    // ------------------------------------------------------------------------
    // Residency control
    // ------------------------------------------------------------------------
    void FreezeResidency();   // Prevent migrations during recovery
    void UnfreezeResidency(); // Allow normal migration
    bool IsFrozen() const { return frozen_; }

    // ------------------------------------------------------------------------
    // Block operations
    // ------------------------------------------------------------------------
    bool DropBlock(VRAMBlock& block);      // Release GPU copy only
    bool UndropBlock(VRAMBlock& block);    // Re-upload from GGUF source
    bool RebindBlock(VRAMBlock& block, int targetGPU);

    // ------------------------------------------------------------------------
    // Bulk operations
    // ------------------------------------------------------------------------
    void DropAllOnGPU(int gpu);
    void UndropAllOnGPU(int gpu);
    void RecoverAll();

    // ------------------------------------------------------------------------
    // Split planner
    // ------------------------------------------------------------------------
    static DualGPUSplit SplitGGUF(
        const std::vector<TensorInfo>& tensors,
        size_t gpu0VRAM,
        size_t gpu1VRAM);

    // ------------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------------
    using DropCallback    = std::function<void(const VRAMBlock&)>;
    using UndropCallback  = std::function<void(const VRAMBlock&)>;
    using RecoverCallback = std::function<void(const VRAMBlock&, int fromGPU, int toGPU)>;

    void SetDropCallback(DropCallback cb);
    void SetUndropCallback(UndropCallback cb);
    void SetRecoverCallback(RecoverCallback cb);

    // ------------------------------------------------------------------------
    // Stats
    // ------------------------------------------------------------------------
    struct Stats {
        uint64_t blocksDropped   = 0;
        uint64_t blocksUndropped = 0;
        uint64_t blocksRebound   = 0;
        uint64_t bytesRecovered  = 0;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    bool active_  = false;
    bool frozen_  = false;

    mutable std::mutex mutex_;
    std::vector<VRAMBlock> blocks_;

    DropCallback    onDrop_;
    UndropCallback  onUndrop_;
    RecoverCallback onRecover_;

    Stats stats_;
    mutable std::mutex statsMutex_;

    // Internal
    bool UploadFromGGUF(VRAMBlock& block);
    void ReleaseVRAM(int gpu, uint64_t tensorId);
};

} // namespace Deep2
