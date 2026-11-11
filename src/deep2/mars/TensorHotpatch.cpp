// ============================================================================
// TensorHotpatch.cpp - MARS: Memory Allocation + Routing System
// ============================================================================

#include "TensorHotpatch.hpp"
#include <algorithm>
#include <cstdio>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Constructor / Destructor
// ============================================================================
TensorHotpatch::TensorHotpatch() = default;
TensorHotpatch::~TensorHotpatch() = default;

// ============================================================================
// Attach
// ============================================================================
void TensorHotpatch::AttachVRAMManager(VRAMManager* manager) {
    vramManager_ = manager;
}

// ============================================================================
// Core Operations
// ============================================================================
HotpatchResult TensorHotpatch::Redirect(uint64_t tensorId, int targetGPU) {
    if (!vramManager_) {
        return HotpatchResult::MIGRATION_FAILED;
    }

    VRAMLease* lease = vramManager_->GetLease(tensorId);
    if (!lease) {
        return HotpatchResult::MIGRATION_FAILED;
    }
    return Redirect(lease, targetGPU);
}

HotpatchResult TensorHotpatch::Redirect(VRAMLease* lease, int targetGPU) {
    if (!lease || !vramManager_) {
        return HotpatchResult::MIGRATION_FAILED;
    }

    if (lease->currentGPU == targetGPU) {
        return HotpatchResult::ALREADY_THERE;
    }

    if (!lease->hotpatchable || lease->pinned) {
        return HotpatchResult::NOT_HOTPATCHABLE;
    }

    int sourceGPU = lease->currentGPU;
    size_t bytes = lease->bytes;

    // Attempt migration via VRAMManager
    bool ok = vramManager_->Migrate(lease, targetGPU);
    if (!ok) {
        return HotpatchResult::NO_VRAM;
    }

    // Simulate copy (in real impl, this is GPU DMA)
    if (!PerformCopy(sourceGPU, targetGPU, lease->tensorId, bytes)) {
        // Try rollback
        vramManager_->RollbackLastMigration(lease->tensorId);
        return HotpatchResult::MIGRATION_FAILED;
    }

    // Verify after move
    if (!Verify(lease->tensorId)) {
        verifyFailureCount_++;
        // Rollback
        vramManager_->RollbackLastMigration(lease->tensorId);
        return HotpatchResult::VERIFY_FAILED;
    }

    RecordRedirect(lease->tensorId, sourceGPU, targetGPU);
    redirectCount_++;

    if (onRedirect_) {
        onRedirect_(lease->tensorId, sourceGPU, targetGPU);
    }

    printf("[TensorHotpatch] Redirected '%s' GPU %d -> GPU %d\n",
           lease->name.c_str(), sourceGPU, targetGPU);
    return HotpatchResult::OK;
}

HotpatchResult TensorHotpatch::Rollback(uint64_t tensorId) {
    if (!vramManager_) {
        return HotpatchResult::ROLLBACK_FAILED;
    }

    {
        std::lock_guard<std::mutex> lock(historyMutex_);
        auto it = redirectHistory_.find(tensorId);
        if (it == redirectHistory_.end() || it->second.empty()) {
            return HotpatchResult::ROLLBACK_FAILED;
        }

        const RedirectRecord& rec = it->second.back();
        bool ok = vramManager_->RollbackLastMigration(tensorId);
        if (ok) {
            it->second.pop_back();
            rollbackCount_++;

            if (onRollback_) {
                onRollback_(tensorId, rec.fromGPU);
            }

            printf("[TensorHotpatch] Rolled back tensor %llu to GPU %d\n",
                   (unsigned long long)tensorId, rec.fromGPU);
            return HotpatchResult::ROLLBACK_OK;
        }
    }

    return HotpatchResult::ROLLBACK_FAILED;
}

HotpatchResult TensorHotpatch::RollbackTo(uint64_t tensorId, int originalGPU) {
    VRAMLease* lease = vramManager_ ? vramManager_->GetLease(tensorId) : nullptr;
    if (!lease) {
        return HotpatchResult::ROLLBACK_FAILED;
    }

    if (lease->currentGPU == originalGPU) {
        return HotpatchResult::ALREADY_THERE;
    }

    HotpatchResult r = Redirect(tensorId, originalGPU);
    if (r == HotpatchResult::OK) {
        rollbackCount_++;
        if (onRollback_) {
            onRollback_(tensorId, originalGPU);
        }
        return HotpatchResult::ROLLBACK_OK;
    }
    return HotpatchResult::ROLLBACK_FAILED;
}

bool TensorHotpatch::Verify(uint64_t tensorId) {
    VRAMLease* lease = vramManager_ ? vramManager_->GetLease(tensorId) : nullptr;
    if (!lease) {
        return false;
    }
    // Simplified: verify lease is resident and has valid GPU
    if (!lease->IsResident()) {
        return false;
    }
    if (lease->currentGPU < 0 || lease->currentGPU >= 2) {
        return false;
    }
    // In real impl: checksum or hash comparison after copy
    return true;
}

size_t TensorHotpatch::VerifyAll() {
    if (!vramManager_) return 0;

    size_t failures = 0;
    // Iterate all leases - simplified: we don't have an iterator API,
    // so this is a placeholder for full verification sweep
    return failures;
}

// ============================================================================
// Bulk Operations
// ============================================================================
size_t TensorHotpatch::RedirectWhere(std::function<bool(const VRAMLease&)> predicate,
                                      int targetGPU) {
    if (!vramManager_) return 0;

    size_t count = 0;
    // Note: Without a lease iterator, this is limited.
    // In production, VRAMManager would expose a foreach or snapshot.
    (void)predicate;
    (void)targetGPU;
    return count;
}

size_t TensorHotpatch::EvictLowPriority(int gpu, float priorityThreshold) {
    if (!vramManager_) return 0;

    size_t count = 0;
    // Would iterate leases and evict those below threshold on given GPU
    (void)gpu;
    (void)priorityThreshold;
    return count;
}

void TensorHotpatch::Rebalance() {
    if (!vramManager_) return;

    auto dp = vramManager_->GetDynamicParity();
    size_t used0 = vramManager_->GetUsedVRAM(0);
    size_t used1 = vramManager_->GetUsedVRAM(1);
    size_t total0 = vramManager_->GetTotalVRAM(0);
    size_t total1 = vramManager_->GetTotalVRAM(1);

    float ratio0 = total0 > 0 ? (float)used0 / total0 : 0.0f;
    float ratio1 = total1 > 0 ? (float)used1 / total1 : 0.0f;

    // If one GPU is significantly more loaded, move tensors to the other
    const float threshold = 0.15f; // 15% imbalance threshold
    if (ratio0 > ratio1 + threshold) {
        // Move some from GPU0 to GPU1
        // (requires lease iteration - simplified here)
        printf("[TensorHotpatch] Rebalance: GPU0 %.1f%% -> GPU1 %.1f%%\n",
               ratio0 * 100.0f, ratio1 * 100.0f);
    } else if (ratio1 > ratio0 + threshold) {
        printf("[TensorHotpatch] Rebalance: GPU1 %.1f%% -> GPU0 %.1f%%\n",
               ratio1 * 100.0f, ratio0 * 100.0f);
    }
}

// ============================================================================
// Reverse Recovery
// ============================================================================
HotpatchResult TensorHotpatch::ReverseRecover(uint64_t tensorId) {
    VRAMLease* lease = vramManager_ ? vramManager_->GetLease(tensorId) : nullptr;
    if (!lease) {
        return HotpatchResult::MIGRATION_FAILED;
    }

    printf("[TensorHotpatch] ReverseRecover for '%s' (faulted on GPU %d)\n",
           lease->name.c_str(), lease->currentGPU);

    // Mark as failed
    lease->state = LeaseState::FAILED;
    lease->needsRebuild = true;

    if (onFault_) {
        onFault_(tensorId, lease->currentGPU);
    }

    // Find available VRAM on either GPU
    int targetGPU = -1;
    for (int gpu = 0; gpu < 2; ++gpu) {
        if (gpu != lease->currentGPU &&
            vramManager_->GetFreeVRAM(gpu) >= lease->bytes) {
            targetGPU = gpu;
            break;
        }
    }

    if (targetGPU < 0) {
        // No VRAM available - evict to host
        vramManager_->Evict(lease);
        printf("[TensorHotpatch] ReverseRecover: evicted to host (no VRAM)\n");
        return HotpatchResult::NO_VRAM;
    }

    // Rehydrate on target GPU
    HotpatchResult r = Redirect(lease, targetGPU);
    if (r == HotpatchResult::OK) {
        lease->needsRebuild = false;
        lease->state = LeaseState::RESIDENT;
        printf("[TensorHotpatch] ReverseRecover: rehydrated on GPU %d\n", targetGPU);
    }
    return r;
}

HotpatchResult TensorHotpatch::HandleGPUFailure(int failedGPU) {
    if (!vramManager_) {
        return HotpatchResult::MIGRATION_FAILED;
    }

    printf("[TensorHotpatch] Handling GPU %d failure - migrating all tensors\n", failedGPU);

    int otherGPU = (failedGPU == 0) ? 1 : 0;
    vramManager_->MigrateAll(failedGPU, otherGPU);

    // Mark failed GPU as unhealthy
    GPUState state;
    state.index = failedGPU;
    state.healthy = false;
    vramManager_->UpdateGPUState(failedGPU, state);

    return HotpatchResult::OK;
}

// ============================================================================
// Queries
// ============================================================================
bool TensorHotpatch::IsHotpatchable(uint64_t tensorId) const {
    VRAMLease* lease = vramManager_ ? vramManager_->GetLease(tensorId) : nullptr;
    return lease && lease->hotpatchable && !lease->pinned;
}

int TensorHotpatch::GetCurrentGPU(uint64_t tensorId) const {
    VRAMLease* lease = vramManager_ ? vramManager_->GetLease(tensorId) : nullptr;
    return lease ? lease->currentGPU : -1;
}

// ============================================================================
// Callbacks
// ============================================================================
void TensorHotpatch::SetRedirectCallback(RedirectCallback cb) {
    onRedirect_ = cb;
}
void TensorHotpatch::SetRollbackCallback(RollbackCallback cb) {
    onRollback_ = cb;
}
void TensorHotpatch::SetFaultCallback(FaultCallback cb) {
    onFault_ = cb;
}

// ============================================================================
// Internal
// ============================================================================
void TensorHotpatch::RecordRedirect(uint64_t tensorId, int from, int to) {
    std::lock_guard<std::mutex> lock(historyMutex_);
    RedirectRecord rec;
    rec.fromGPU = from;
    rec.toGPU = to;
    rec.timestamp = 0; // Could use steady_clock
    redirectHistory_[tensorId].push_back(rec);
}

bool TensorHotpatch::PerformCopy(int fromGPU, int toGPU, uint64_t tensorId, size_t bytes) {
    // In production: GPU DMA copy between devices
    // For now: simulate success
    (void)fromGPU;
    (void)toGPU;
    (void)tensorId;
    (void)bytes;
    return true;
}

} // namespace MARS
} // namespace Deep2
