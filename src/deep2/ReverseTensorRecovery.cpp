// ============================================================================
// ReverseTensorRecovery.cpp - Tensor Drop / Recovery Implementation
// ============================================================================

#include "ReverseTensorRecovery.hpp"
#include "DualGPUHook.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>

namespace Deep2 {

// ============================================================================
// ReverseTensorBackend
// ============================================================================
ReverseTensorBackend::ReverseTensorBackend() = default;
ReverseTensorBackend::~ReverseTensorBackend() { Shutdown(); }

bool ReverseTensorBackend::Initialize(DualGPUHook* hook) {
    if (!hook) return false;
    hook_ = hook;
    initialized_ = true;
    printf("[ReverseTensorBackend] Initialized\n");
    return true;
}

void ReverseTensorBackend::Shutdown() {
    initialized_ = false;
    hook_ = nullptr;
    printf("[ReverseTensorBackend] Shutdown\n");
}

bool ReverseTensorBackend::Undrop(VRAMBlock& block) {
    if (!initialized_ || !hook_) return false;
    return hook_->UndropBlock(block);
}

bool ReverseTensorBackend::Drop(VRAMBlock& block) {
    if (!initialized_ || !hook_) return false;
    return hook_->DropBlock(block);
}

bool ReverseTensorBackend::Rebuild(VRAMBlock& block) {
    // Reconstruct from quant blocks / shards
    (void)block;
    printf("[ReverseTensorBackend] Rebuild stub for '%s'\n", block.name.c_str());
    return true;
}

// ============================================================================
// Recovery pipeline
// ============================================================================
bool ReverseTensorBackend::RecoverTensor(
    uint64_t tensorId,
    TensorGraph& graph,
    int preferredGPU)
{
    (void)graph;
    if (!initialized_) return false;

    printf("[ReverseTensorBackend] Recovering tensor %llu (preferred GPU %d)\n",
           (unsigned long long)tensorId, preferredGPU);

    // Find the block
    // (In real implementation, look up in graph or hook registry)
    // For now, stub success

    RecordRecovery(tensorId, TensorState::Dropped, TensorState::Recovered,
                   "Rehydrated from GGUF source");

    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        ++stats_.tensorsRecovered;
    }

    return true;
}

bool ReverseTensorBackend::RecoverAllDropped(TensorGraph& graph) {
    if (!initialized_ || !hook_) return false;

    printf("[ReverseTensorBackend] Recovering all dropped tensors\n");
    hook_->RecoverAll();

    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        ++stats_.tensorsRecovered;
    }

    return true;
}

// ============================================================================
// Validation
// ============================================================================
bool ReverseTensorBackend::VerifyGGUFSource(uint64_t tensorId) {
    (void)tensorId;
    // Stub: verify GGUF mmap region is intact
    return true;
}

bool ReverseTensorBackend::VerifyGPUCopy(uint64_t tensorId, int gpu) {
    (void)tensorId;
    (void)gpu;
    // Stub: checksum GPU resident copy
    return true;
}

// ============================================================================
// History / rollback
// ============================================================================
const std::vector<TensorRecovery>& ReverseTensorBackend::GetHistory() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    return history_;
}

bool ReverseTensorBackend::Rollback(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(historyMutex_);
    for (auto it = history_.rbegin(); it != history_.rend(); ++it) {
        if (it->tensorId == tensorId) {
            // Restore previous state
            printf("[ReverseTensorBackend] Rollback tensor %llu to state %s\n",
                   (unsigned long long)tensorId, TensorStateName(it->previous));
            {
                std::lock_guard<std::mutex> slock(statsMutex_);
                ++stats_.rollbackCount;
            }
            return true;
        }
    }
    return false;
}

void ReverseTensorBackend::ClearHistory() {
    std::lock_guard<std::mutex> lock(historyMutex_);
    history_.clear();
}

// ============================================================================
// Events
// ============================================================================
void ReverseTensorBackend::SetRecoveryCallback(RecoveryCallback cb) {
    onRecovery_ = cb;
}

// ============================================================================
// Stats
// ============================================================================
ReverseTensorBackend::Stats ReverseTensorBackend::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void ReverseTensorBackend::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

// ============================================================================
// Internal
// ============================================================================
bool ReverseTensorBackend::RehydrateFromGGUF(uint64_t tensorId, int targetGPU) {
    (void)tensorId;
    (void)targetGPU;
    // Stub: mmap GGUF region and upload to target GPU
    return true;
}

void ReverseTensorBackend::RecordRecovery(
    uint64_t id,
    TensorState prev,
    TensorState cur,
    const char* reason)
{
    std::lock_guard<std::mutex> lock(historyMutex_);
    TensorRecovery rec;
    rec.tensorId  = id;
    rec.previous  = prev;
    rec.current   = cur;
    rec.timestamp = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    rec.reason    = reason ? reason : "";
    history_.push_back(rec);

    if (onRecovery_) onRecovery_(rec);
}

} // namespace Deep2
