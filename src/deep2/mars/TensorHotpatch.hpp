// ============================================================================
// TensorHotpatch.hpp - MARS: Memory Allocation + Routing System
// Redirect, Rollback, Verify tensor placement at runtime.
// ============================================================================

#pragma once

#include "VRAMLease.hpp"
#include "VRAMManager.hpp"
#include <vector>
#include <unordered_map>
#include <mutex>
#include <functional>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Hotpatch Result
// ============================================================================
enum class HotpatchResult {
    OK,              // Success
    ALREADY_THERE,   // Tensor already on target
    NO_VRAM,         // Target GPU has no room
    NOT_HOTPATCHABLE,// Tensor is pinned
    MIGRATION_FAILED,// Copy failed
    VERIFY_FAILED,   // Post-move verification failed
    ROLLBACK_OK,     // Successfully rolled back
    ROLLBACK_FAILED  // Rollback also failed (critical)
};

// ============================================================================
// Tensor Hotpatch Controller
// Runtime tensor placement redirection with rollback support.
// ============================================================================
class TensorHotpatch {
public:
    TensorHotpatch();
    ~TensorHotpatch();

    // ------------------------------------------------------------------------
    // Attach VRAM manager
    // ------------------------------------------------------------------------
    void AttachVRAMManager(VRAMManager* manager);

    // ------------------------------------------------------------------------
    // Core Operations
    // ------------------------------------------------------------------------
    // Redirect a tensor to a different GPU
    HotpatchResult Redirect(uint64_t tensorId, int targetGPU);

    // Redirect by lease reference
    HotpatchResult Redirect(VRAMLease* lease, int targetGPU);

    // Rollback last redirect on this tensor
    HotpatchResult Rollback(uint64_t tensorId);

    // Rollback to specific GPU
    HotpatchResult RollbackTo(uint64_t tensorId, int originalGPU);

    // Verify tensor integrity after move
    bool Verify(uint64_t tensorId);

    // Verify all resident tensors
    size_t VerifyAll();

    // ------------------------------------------------------------------------
    // Bulk Operations
    // ------------------------------------------------------------------------
    // Redirect all tensors matching predicate
    size_t RedirectWhere(std::function<bool(const VRAMLease&)> predicate, int targetGPU);

    // Evict low-priority tensors to host to free VRAM
    size_t EvictLowPriority(int gpu, float priorityThreshold);

    // Rebalance: move tensors to equalize VRAM usage
    void Rebalance();

    // ------------------------------------------------------------------------
    // Reverse Recovery
    // ------------------------------------------------------------------------
    // Handle tensor fault by finding available VRAM and rehydrating
    HotpatchResult ReverseRecover(uint64_t tensorId);

    // Handle GPU failure by migrating all tensors off it
    HotpatchResult HandleGPUFailure(int failedGPU);

    // ------------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------------
    bool IsHotpatchable(uint64_t tensorId) const;
    int  GetCurrentGPU(uint64_t tensorId) const;
    size_t GetRedirectCount() const { return redirectCount_; }
    size_t GetRollbackCount() const { return rollbackCount_; }
    size_t GetVerifyFailureCount() const { return verifyFailureCount_; }

    // ------------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------------
    using RedirectCallback = std::function<void(uint64_t tensorId, int from, int to)>;
    using RollbackCallback = std::function<void(uint64_t tensorId, int restoredGPU)>;
    using FaultCallback    = std::function<void(uint64_t tensorId, int failedGPU)>;

    void SetRedirectCallback(RedirectCallback cb);
    void SetRollbackCallback(RollbackCallback cb);
    void SetFaultCallback(FaultCallback cb);

private:
    VRAMManager* vramManager_ = nullptr;

    // Per-tensor redirect history (for rollback)
    struct RedirectRecord {
        int fromGPU;
        int toGPU;
        uint64_t timestamp;
    };
    std::unordered_map<uint64_t, std::vector<RedirectRecord>> redirectHistory_;
    mutable std::mutex historyMutex_;

    // Counters
    std::atomic<size_t> redirectCount_{0};
    std::atomic<size_t> rollbackCount_{0};
    std::atomic<size_t> verifyFailureCount_{0};

    // Callbacks
    RedirectCallback onRedirect_;
    RollbackCallback onRollback_;
    FaultCallback    onFault_;

    // Internal
    void RecordRedirect(uint64_t tensorId, int from, int to);
    bool PerformCopy(int fromGPU, int toGPU, uint64_t tensorId, size_t bytes);
};

} // namespace MARS
} // namespace Deep2
