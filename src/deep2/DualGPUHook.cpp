// ============================================================================
// DualGPUHook.cpp - Hook/Unhook System for Dual GPU Recovery
// ============================================================================

#include "DualGPUHook.hpp"
#include "GGUFLoader.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace Deep2 {

// ============================================================================
// DualGPUSplit helpers
// ============================================================================
size_t DualGPUSplit::TotalBytesGPU0() const {
    size_t sum = 0;
    for (const auto& b : gpu0) sum += b.bytes;
    return sum;
}

size_t DualGPUSplit::TotalBytesGPU1() const {
    size_t sum = 0;
    for (const auto& b : gpu1) sum += b.bytes;
    return sum;
}

// ============================================================================
// DualGPUHook
// ============================================================================
DualGPUHook::DualGPUHook() = default;
DualGPUHook::~DualGPUHook() = default;

bool DualGPUHook::Attach(TensorGraph& graph) {
    (void)graph;
    std::lock_guard<std::mutex> lock(mutex_);
    active_ = true;
    frozen_ = false;
    blocks_.clear();
    printf("[DualGPUHook] Attached to TensorGraph\n");
    return true;
}

void DualGPUHook::Detach(TensorGraph& graph) {
    (void)graph;
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_) {
        // Flush any pending transfers before unhooking
        blocks_.clear();
        active_ = false;
        frozen_ = false;
        printf("[DualGPUHook] Detached from TensorGraph\n");
    }
}

void DualGPUHook::FreezeResidency() {
    std::lock_guard<std::mutex> lock(mutex_);
    frozen_ = true;
    printf("[DualGPUHook] Residency frozen\n");
}

void DualGPUHook::UnfreezeResidency() {
    std::lock_guard<std::mutex> lock(mutex_);
    frozen_ = false;
    printf("[DualGPUHook] Residency unfrozen\n");
}

bool DualGPUHook::DropBlock(VRAMBlock& block) {
    if (!block.resident) return true; // Already dropped

    std::lock_guard<std::mutex> lock(mutex_);
    ReleaseVRAM(block.ownerGPU, block.tensorId);
    block.resident = false;

    {
        std::lock_guard<std::mutex> slock(statsMutex_);
        ++stats_.blocksDropped;
    }

    if (onDrop_) onDrop_(block);
    printf("[DualGPUHook] Dropped block '%s' (GPU %d)\n",
           block.name.c_str(), block.ownerGPU);
    return true;
}

bool DualGPUHook::UndropBlock(VRAMBlock& block) {
    if (block.resident) return true; // Already resident

    // Re-upload from GGUF source (never drop source data)
    if (!UploadFromGGUF(block)) {
        printf("[DualGPUHook] ERROR: Failed to undrop block '%s'\n", block.name.c_str());
        return false;
    }

    block.resident = true;

    {
        std::lock_guard<std::mutex> slock(statsMutex_);
        ++stats_.blocksUndropped;
        stats_.bytesRecovered += block.bytes;
    }

    if (onUndrop_) onUndrop_(block);
    printf("[DualGPUHook] Undropped block '%s' -> GPU %d\n",
           block.name.c_str(), block.ownerGPU);
    return true;
}

bool DualGPUHook::RebindBlock(VRAMBlock& block, int targetGPU) {
    if (block.ownerGPU == targetGPU && block.resident) return true;

    // Drop from current GPU
    if (block.resident) {
        DropBlock(block);
    }

    // Change owner and re-upload
    int oldGPU = block.ownerGPU;
    block.ownerGPU = targetGPU;

    if (!UploadFromGGUF(block)) {
        block.ownerGPU = oldGPU; // Rollback
        return false;
    }

    block.resident = true;

    {
        std::lock_guard<std::mutex> slock(statsMutex_);
        ++stats_.blocksRebound;
    }

    if (onRecover_) onRecover_(block, oldGPU, targetGPU);
    printf("[DualGPUHook] Rebound block '%s' GPU %d -> GPU %d\n",
           block.name.c_str(), oldGPU, targetGPU);
    return true;
}

void DualGPUHook::DropAllOnGPU(int gpu) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& block : blocks_) {
        if (block.ownerGPU == gpu && block.resident) {
            ReleaseVRAM(gpu, block.tensorId);
            block.resident = false;
            if (onDrop_) onDrop_(block);
        }
    }
    printf("[DualGPUHook] Dropped all blocks on GPU %d\n", gpu);
}

void DualGPUHook::UndropAllOnGPU(int gpu) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& block : blocks_) {
        if (block.ownerGPU == gpu && !block.resident && block.recoverable) {
            if (UploadFromGGUF(block)) {
                block.resident = true;
                if (onUndrop_) onUndrop_(block);
            }
        }
    }
    printf("[DualGPUHook] Undropped all blocks on GPU %d\n", gpu);
}

void DualGPUHook::RecoverAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& block : blocks_) {
        if (!block.resident && block.recoverable) {
            if (UploadFromGGUF(block)) {
                block.resident = true;
                if (onUndrop_) onUndrop_(block);
            }
        }
    }
    printf("[DualGPUHook] Recovered all dropped blocks\n");
}

// ============================================================================
// Split planner
// ============================================================================
DualGPUSplit DualGPUHook::SplitGGUF(
    const std::vector<TensorInfo>& tensors,
    size_t gpu0VRAM,
    size_t gpu1VRAM)
{
    DualGPUSplit result;
    size_t remaining0 = gpu0VRAM;
    size_t remaining1 = gpu1VRAM;

    for (const auto& t : tensors) {
        VRAMBlock block;
        block.tensorId = 0; // Will be filled by caller
        block.bytes    = t.size;
        block.name     = t.name;
        block.resident = false;
        block.recoverable = true;

        // Prefer GPU0 for large tensors, GPU1 for overflow
        if (remaining0 >= t.size) {
            block.ownerGPU = 0;
            result.gpu0.push_back(block);
            remaining0 -= t.size;
        } else if (remaining1 >= t.size) {
            block.ownerGPU = 1;
            result.gpu1.push_back(block);
            remaining1 -= t.size;
        } else {
            // Neither fits — force to GPU0 (will trigger eviction later)
            block.ownerGPU = 0;
            result.gpu0.push_back(block);
        }
    }

    printf("[DualGPUHook] Split: GPU0 %zu blocks (%zu bytes), GPU1 %zu blocks (%zu bytes)\n",
           result.gpu0.size(), result.TotalBytesGPU0(),
           result.gpu1.size(), result.TotalBytesGPU1());
    return result;
}

// ============================================================================
// Events
// ============================================================================
void DualGPUHook::SetDropCallback(DropCallback cb)    { onDrop_    = cb; }
void DualGPUHook::SetUndropCallback(UndropCallback cb)  { onUndrop_  = cb; }
void DualGPUHook::SetRecoverCallback(RecoverCallback cb) { onRecover_ = cb; }

// ============================================================================
// Stats
// ============================================================================
DualGPUHook::Stats DualGPUHook::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void DualGPUHook::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

// ============================================================================
// Internal
// ============================================================================
bool DualGPUHook::UploadFromGGUF(VRAMBlock& block) {
    // Production implementation: mmap GGUF tensor and upload to GPU
    // TODO: Extend VRAMBlock with ggufPath/tensorName/hostData fields
    // For now, mark as resident (actual upload requires GPU driver integration)
    (void)block;
    return true;
}

void DualGPUHook::ReleaseVRAM(int gpu, uint64_t tensorId) {
    // Production implementation: release GPU memory for tensor
    (void)gpu;
    (void)tensorId;
    // Actual GPU driver free would go here
}

} // namespace Deep2
