// ============================================================================
// MARS.cpp - Memory Allocation + Routing System Implementation
// ============================================================================
#include "MARS.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <chrono>

namespace Deep2 {
namespace MARS {

// ============================================================================
// TensorHotpatch Implementation
// ============================================================================
TensorHotpatch::TensorHotpatch(MARSController* controller) 
    : controller_(controller) {}

HotpatchResult TensorHotpatch::Redirect(uint64_t tensorId, int targetGPU) {
    if (!controller_) return HotpatchResult::MIGRATION_FAILED;
    
    std::lock_guard<std::mutex> lock(migrationMutex_);
    
    VRAMLease* lease = controller_->GetTensor(tensorId);
    if (!lease) return HotpatchResult::SOURCE_NOT_FOUND;
    if (lease->currentGPU == targetGPU) return HotpatchResult::ALREADY_ON_TARGET;
    if (!controller_->IsGPUHealthy(targetGPU)) return HotpatchResult::GPU_UNHEALTHY;
    
    // Check if target has space
    if (!controller_->CanFit(targetGPU, lease->bytes)) {
        // Try to free space
        controller_->EvictLeastImportant(targetGPU, lease->bytes);
        if (!controller_->CanFit(targetGPU, lease->bytes)) {
            return HotpatchResult::DESTINATION_FULL;
        }
    }
    
    // Perform migration
    if (controller_->MigrateTensorInternal(tensorId, lease->currentGPU, targetGPU)) {
        return HotpatchResult::SUCCESS;
    }
    
    return HotpatchResult::MIGRATION_FAILED;
}

std::vector<HotpatchResult> TensorHotpatch::RedirectBatch(
    const std::vector<std::pair<uint64_t, int>>& migrations) {
    std::vector<HotpatchResult> results;
    results.reserve(migrations.size());
    
    for (const auto& [tensorId, targetGPU] : migrations) {
        results.push_back(Redirect(tensorId, targetGPU));
    }
    
    return results;
}

bool TensorHotpatch::Prestage(uint64_t tensorId, int targetGPU) {
    // Pre-allocate space on target GPU without copying data yet
    VRAMLease* lease = controller_->GetTensor(tensorId);
    if (!lease) return false;
    
    // Just verify space is available
    return controller_->CanFit(targetGPU, lease->bytes);
}

bool TensorHotpatch::VerifyIntegrity(uint64_t tensorId) {
    VRAMLease* lease = controller_->GetTensor(tensorId);
    if (!lease) return false;
    
    // Verify the tensor is resident and has valid device pointer
    return lease->resident && lease->devicePtr != nullptr && lease->currentGPU >= 0;
}

// ============================================================================
// MARSController Implementation
// ============================================================================
MARSController::MARSController() 
    : hotpatch_(std::make_unique<TensorHotpatch>(this)) {}

MARSController::~MARSController() {
    Shutdown();
}

bool MARSController::Initialize(size_t gpu0VRAMBytes, size_t gpu1VRAMBytes) {
    std::lock_guard<std::mutex> lock(globalMutex_);
    
    if (initialized_.load()) {
        printf("[MARS] Already initialized\n");
        return true;
    }
    
    pools_[0].totalBytes = gpu0VRAMBytes;
    pools_[0].usedBytes = 0;
    pools_[0].healthy = true;
    
    pools_[1].totalBytes = gpu1VRAMBytes;
    pools_[1].usedBytes = 0;
    pools_[1].healthy = true;
    
    initialized_.store(true);
    
    printf("[MARS] Initialized: GPU0=%.2f GB, GPU1=%.2f GB\n",
           gpu0VRAMBytes / (1024.0 * 1024.0 * 1024.0),
           gpu1VRAMBytes / (1024.0 * 1024.0 * 1024.0));
    
    return true;
}

void MARSController::Shutdown() {
    std::lock_guard<std::mutex> lock(globalMutex_);
    
    if (!initialized_.load()) return;
    
    // Evict all tensors
    for (int gpu = 0; gpu < 2; gpu++) {
        std::lock_guard<std::mutex> poolLock(pools_[gpu].mutex);
        for (auto& [id, lease] : pools_[gpu].tensors) {
            if (lease && lease->devicePtr) {
                FreeDeviceMemory(lease->devicePtr);
                totalFreed_ += lease->bytes;
            }
        }
        pools_[gpu].tensors.clear();
        pools_[gpu].usedBytes = 0;
    }
    
    initialized_.store(false);
    printf("[MARS] Shutdown complete. Total allocated: %.2f MB, Total freed: %.2f MB\n",
           totalAllocated_.load() / (1024.0 * 1024.0),
           totalFreed_.load() / (1024.0 * 1024.0));
}

VRAMLease* MARSController::PlaceTensor(
    uint64_t tensorId,
    const std::string& name,
    size_t bytes,
    float priority,
    bool pin) {
    
    if (!initialized_.load()) {
        printf("[MARS] ERROR: Not initialized\n");
        return nullptr;
    }
    
    // Select best GPU
    int gpu = SelectBestGPU(bytes, priority);
    if (gpu < 0) {
        printf("[MARS] ERROR: No GPU can fit tensor '%s' (%.2f MB)\n",
               name.c_str(), bytes / (1024.0 * 1024.0));
        return nullptr;
    }
    
    // Try to allocate
    std::lock_guard<std::mutex> poolLock(pools_[gpu].mutex);
    
    // Check if already exists
    auto it = pools_[gpu].tensors.find(tensorId);
    if (it != pools_[gpu].tensors.end()) {
        printf("[MARS] Tensor '%s' already exists on GPU%d\n", name.c_str(), gpu);
        return it->second.get();
    }
    
    // Try to make room if needed
    if (!CanFit(gpu, bytes)) {
        if (!EvictLeastImportant(gpu, bytes)) {
            printf("[MARS] ERROR: Cannot make room for '%s' on GPU%d\n", name.c_str(), gpu);
            return nullptr;
        }
    }
    
    // Create lease
    auto lease = std::make_unique<VRAMLease>();
    lease->tensorId = tensorId;
    lease->tensorName = name;
    lease->currentGPU = gpu;
    lease->originalGPU = gpu;
    lease->bytes = bytes;
    lease->priority = priority;
    lease->pinned = pin;
    lease->resident = true;
    lease->devicePtr = AllocateDeviceMemory(bytes);
    
    if (!lease->devicePtr) {
        printf("[MARS] ERROR: Failed to allocate device memory for '%s'\n", name.c_str());
        return nullptr;
    }
    
    VRAMLease* result = lease.get();
    pools_[gpu].tensors[tensorId] = std::move(lease);
    pools_[gpu].usedBytes += bytes;
    if (pools_[gpu].usedBytes > pools_[gpu].peakUsedBytes)
        pools_[gpu].peakUsedBytes = pools_[gpu].usedBytes;
    totalAllocated_ += bytes;
    bytesHostToGpu_ += bytes;
    
    printf("[MARS] Placed '%s' (%.2f MB) on GPU%d (priority=%.2f)\n",
           name.c_str(), bytes / (1024.0 * 1024.0), gpu, priority);
    
    return result;
}

bool MARSController::EvictTensor(uint64_t tensorId) {
    for (int gpu = 0; gpu < 2; gpu++) {
        std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
        
        auto it = pools_[gpu].tensors.find(tensorId);
        if (it != pools_[gpu].tensors.end()) {
            VRAMLease* lease = it->second.get();
            if (lease->pinned) {
                printf("[MARS] Cannot evict pinned tensor '%s'\n", lease->tensorName.c_str());
                return false;
            }
            
            if (lease->devicePtr) {
                FreeDeviceMemory(lease->devicePtr);
                totalFreed_ += lease->bytes;
            }
            
            pools_[gpu].usedBytes -= lease->bytes;
            printf("[MARS] Evicted '%s' (%.2f MB) from GPU%d\n",
                   lease->tensorName.c_str(), lease->bytes / (1024.0 * 1024.0), gpu);
            pools_[gpu].tensors.erase(it);
            return true;
        }
    }
    return false;
}

bool MARSController::EvictLeastImportant(int gpu, size_t minBytesToFree) {
    std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
    
    if (pools_[gpu].tensors.empty()) return false;
    
    // Collect evictable tensors
    std::vector<VRAMLease*> candidates;
    for (auto& [id, lease] : pools_[gpu].tensors) {
        if (!lease->pinned && lease->resident) {
            candidates.push_back(lease.get());
        }
    }
    
    if (candidates.empty()) return false;
    
    // Sort by eviction score (lower = more evictable)
    std::sort(candidates.begin(), candidates.end(),
        [this](VRAMLease* a, VRAMLease* b) {
            return CalculateEvictionScore(*a) < CalculateEvictionScore(*b);
        });
    
    // Evict until we have enough space
    size_t freed = 0;
    for (VRAMLease* lease : candidates) {
        if (freed >= minBytesToFree) break;
        
        auto it = pools_[gpu].tensors.find(lease->tensorId);
        if (it != pools_[gpu].tensors.end()) {
            if (it->second->devicePtr) {
                FreeDeviceMemory(it->second->devicePtr);
                totalFreed_ += it->second->bytes;
            }
            freed += it->second->bytes;
            pools_[gpu].usedBytes -= it->second->bytes;
            spillToRam_++;
            printf("[MARS] Evicted '%s' (%.2f MB) from GPU%d (score=%zu)\n",
                   it->second->tensorName.c_str(),
                   it->second->bytes / (1024.0 * 1024.0),
                   gpu,
                   CalculateEvictionScore(*it->second));
            pools_[gpu].tensors.erase(it);
        }
    }
    
    return freed >= minBytesToFree;
}

VRAMLease* MARSController::GetTensor(uint64_t tensorId) {
    for (int gpu = 0; gpu < 2; gpu++) {
        std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
        auto it = pools_[gpu].tensors.find(tensorId);
        if (it != pools_[gpu].tensors.end()) {
            it->second->RecordAccess();
            return it->second.get();
        }
    }
    return nullptr;
}

VRAMLease* MARSController::FindTensorByName(const std::string& name) {
    for (int gpu = 0; gpu < 2; gpu++) {
        std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
        for (auto& [id, lease] : pools_[gpu].tensors) {
            if (lease->tensorName == name) {
                lease->RecordAccess();
                return lease.get();
            }
        }
    }
    return nullptr;
}

void MARSController::RecordTensorAccess(uint64_t tensorId) {
    VRAMLease* lease = GetTensor(tensorId);
    if (lease) {
        lease->RecordAccess();
    }
}

void MARSController::Rebalance() {
    if (!initialized_.load()) return;
    
    DynamicParity parity = GetCurrentParity();
    if (parity.imbalance < rebalanceThreshold_) {
        return;  // Already balanced enough
    }
    
    printf("[MARS] Rebalancing: imbalance=%.2f%%\n", parity.imbalance * 100.0f);
    
    // Find overloaded GPU
    int overloaded = (parity.load[0] > parity.load[1]) ? 0 : 1;
    int underloaded = 1 - overloaded;
    
    if (!IsGPUHealthy(underloaded)) {
        printf("[MARS] Cannot rebalance: GPU%d is unhealthy\n", underloaded);
        return;
    }
    
    // Migrate tensors from overloaded to underloaded
    std::vector<VRAMLease*> candidates;
    {
        std::lock_guard<std::mutex> lock(pools_[overloaded].mutex);
        for (auto& [id, lease] : pools_[overloaded].tensors) {
            if (!lease->pinned && lease->hotpatchable) {
                candidates.push_back(lease.get());
            }
        }
    }
    
    // Sort by priority (migrate lowest priority first)
    std::sort(candidates.begin(), candidates.end(),
        [](VRAMLease* a, VRAMLease* b) { return a->priority < b->priority; });
    
    size_t migrated = 0;
    size_t targetMigration = (pools_[overloaded].usedBytes - pools_[underloaded].usedBytes) / 2;
    
    for (VRAMLease* lease : candidates) {
        if (migrated >= targetMigration) break;
        
        if (MigrateTensorInternal(lease->tensorId, overloaded, underloaded)) {
            migrated += lease->bytes;
            migrationCount_++;
        }
    }
    
    printf("[MARS] Rebalanced: migrated %.2f MB from GPU%d to GPU%d\n",
           migrated / (1024.0 * 1024.0), overloaded, underloaded);
}

bool MARSController::HandleTensorFault(uint64_t tensorId) {
    faultCount_++;
    
    VRAMLease* lease = GetTensor(tensorId);
    if (!lease) {
        printf("[MARS] Fault: Tensor %llu not found\n", tensorId);
        return false;
    }
    
    printf("[MARS] Fault: Tensor '%s' on GPU%d\n", 
           lease->tensorName.c_str(), lease->currentGPU);
    
    // Try to recover by migrating to other GPU
    int otherGPU = 1 - lease->currentGPU;
    if (IsGPUHealthy(otherGPU)) {
        HotpatchResult result = hotpatch_->Redirect(tensorId, otherGPU);
        if (result == HotpatchResult::SUCCESS) {
            printf("[MARS] Recovered: Migrated '%s' to GPU%d\n",
                   lease->tensorName.c_str(), otherGPU);
            return true;
        }
    }
    
    // Mark source GPU as potentially unhealthy
    MarkGPUUnhealthy(lease->currentGPU);
    
    return false;
}

bool MARSController::HandleGPUFailure(int gpu) {
    if (gpu < 0 || gpu > 1) return false;
    
    printf("[MARS] GPU%d failure detected!\n", gpu);
    MarkGPUUnhealthy(gpu);
    
    // Migrate all tensors from failed GPU to healthy GPU
    int targetGPU = 1 - gpu;
    if (!IsGPUHealthy(targetGPU)) {
        printf("[MARS] CRITICAL: Both GPUs unhealthy!\n");
        return false;
    }
    
    std::vector<uint64_t> tensorsToMigrate;
    {
        std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
        for (auto& [id, lease] : pools_[gpu].tensors) {
            tensorsToMigrate.push_back(id);
        }
    }
    
    size_t migrated = 0;
    for (uint64_t tensorId : tensorsToMigrate) {
        if (MigrateTensorInternal(tensorId, gpu, targetGPU)) {
            migrated++;
            migrationCount_++;
        }
    }
    
    printf("[MARS] Migrated %zu tensors from GPU%d to GPU%d\n", migrated, gpu, targetGPU);
    return true;
}

DynamicParity MARSController::GetCurrentParity() const {
    DynamicParity parity;
    
    for (int gpu = 0; gpu < 2; gpu++) {
        std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
        
        parity.gpu[gpu].gpuId = gpu;
        parity.gpu[gpu].totalBytes = pools_[gpu].totalBytes;
        parity.gpu[gpu].usedBytes = pools_[gpu].usedBytes;
        parity.gpu[gpu].freeBytes = pools_[gpu].totalBytes - pools_[gpu].usedBytes;
        parity.gpu[gpu].healthy = pools_[gpu].healthy;
        
        parity.vramFree[gpu] = parity.gpu[gpu].freeBytes;
        
        // Calculate load as percentage of VRAM used
        if (pools_[gpu].totalBytes > 0) {
            parity.load[gpu] = static_cast<float>(pools_[gpu].usedBytes) / 
                              static_cast<float>(pools_[gpu].totalBytes);
        }
    }
    
    // Calculate imbalance
    float avgLoad = (parity.load[0] + parity.load[1]) / 2.0f;
    if (avgLoad > 0) {
        parity.imbalance = std::abs(parity.load[0] - parity.load[1]) / avgLoad;
    }
    
    parity.lastRebalance = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return parity;
}

bool MARSController::IsGPUHealthy(int gpu) const {
    if (gpu < 0 || gpu > 1) return false;
    std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
    return pools_[gpu].healthy;
}

void MARSController::MarkGPUUnhealthy(int gpu) {
    if (gpu >= 0 && gpu < 2) {
        std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
        pools_[gpu].healthy = false;
        printf("[MARS] GPU%d marked unhealthy\n", gpu);
    }
}

void MARSController::MarkGPUHealthy(int gpu) {
    if (gpu >= 0 && gpu < 2) {
        std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
        pools_[gpu].healthy = true;
        printf("[MARS] GPU%d marked healthy\n", gpu);
    }
}

// ============================================================================
// Internal Methods
// ============================================================================
int MARSController::SelectBestGPU(size_t bytes, float priority) {
    // Prefer GPU with more free space
    size_t free0 = pools_[0].totalBytes - pools_[0].usedBytes;
    size_t free1 = pools_[1].totalBytes - pools_[1].usedBytes;
    
    bool canFit0 = free0 >= bytes + minFreeBytes_;
    bool canFit1 = free1 >= bytes + minFreeBytes_;
    
    if (!canFit0 && !canFit1) return -1;
    if (canFit0 && !canFit1) return 0;
    if (!canFit0 && canFit1) return 1;
    
    // Both can fit - prefer less loaded GPU
    float load0 = static_cast<float>(pools_[0].usedBytes) / pools_[0].totalBytes;
    float load1 = static_cast<float>(pools_[1].usedBytes) / pools_[1].totalBytes;
    
    return (load0 <= load1) ? 0 : 1;
}

bool MARSController::CanFit(int gpu, size_t bytes) {
    if (gpu < 0 || gpu > 1) return false;
    std::lock_guard<std::mutex> lock(pools_[gpu].mutex);
    size_t free = pools_[gpu].totalBytes - pools_[gpu].usedBytes;
    return free >= bytes + minFreeBytes_;
}

size_t MARSController::CalculateEvictionScore(const VRAMLease& lease) {
    // Lower score = more evictable
    float score = 0.0f;
    
    switch (evictionPolicy_) {
        case EvictionPolicy::LRU:
            score = static_cast<float>(lease.lastAccess);
            break;
            
        case EvictionPolicy::LFU:
            score = static_cast<float>(lease.accessCount);
            break;
            
        case EvictionPolicy::PRIORITY:
            score = lease.priority;
            break;
            
        case EvictionPolicy::HYBRID:
        default: {
            // Combined: lower priority + older access + fewer accesses = more evictable
            float ageScore = static_cast<float>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::high_resolution_clock::now().time_since_epoch()).count() -
                lease.lastAccess);
            score = lease.priority * 1000.0f + ageScore * 0.001f + 
                   static_cast<float>(lease.accessCount) * 0.1f;
            break;
        }
    }
    
    return static_cast<size_t>(score);
}

bool MARSController::MigrateTensorInternal(uint64_t tensorId, int sourceGPU, int targetGPU) {
    if (sourceGPU == targetGPU) return true;
    if (sourceGPU < 0 || sourceGPU > 1 || targetGPU < 0 || targetGPU > 1) return false;
    
    std::unique_ptr<VRAMLease> lease;
    {
        std::lock_guard<std::mutex> sourceLock(pools_[sourceGPU].mutex);
        auto it = pools_[sourceGPU].tensors.find(tensorId);
        if (it == pools_[sourceGPU].tensors.end()) return false;
        
        lease = std::move(it->second);
        pools_[sourceGPU].usedBytes -= lease->bytes;
        pools_[sourceGPU].tensors.erase(it);
    }
    
    {
        std::lock_guard<std::mutex> targetLock(pools_[targetGPU].mutex);
        
        // Make room if needed
        if (!CanFit(targetGPU, lease->bytes)) {
            // Unlock and evict, then relock
            // For simplicity, just try to evict without the lock
            if (!EvictLeastImportant(targetGPU, lease->bytes)) {
                // Put it back on source
                std::lock_guard<std::mutex> sourceLock(pools_[sourceGPU].mutex);
                pools_[sourceGPU].tensors[tensorId] = std::move(lease);
                pools_[sourceGPU].usedBytes += lease->bytes;
                return false;
            }
        }
        
        lease->currentGPU = targetGPU;
        pools_[targetGPU].tensors[tensorId] = std::move(lease);
        pools_[targetGPU].usedBytes += lease->bytes;
        if (pools_[targetGPU].usedBytes > pools_[targetGPU].peakUsedBytes)
            pools_[targetGPU].peakUsedBytes = pools_[targetGPU].usedBytes;
    }
    
    migrationCount_++;
    bytesHostToGpu_ += 0; // device↔device; counted separately if needed
    printf("[MARS] Migrated tensor %llu from GPU%d to GPU%d\n",
           (unsigned long long)tensorId, sourceGPU, targetGPU);
    return true;
}

void MARSController::UpdateParityMetrics() {
    // Called periodically to update GPU utilization metrics
    // In a real implementation, this would query GPU drivers
}

void* MARSController::AllocateDeviceMemory(size_t bytes) {
    // In a real implementation, this would call CUDA/HIP/Vulkan allocation
    // For now, allocate host memory as placeholder
    void* ptr = std::malloc(bytes);
    if (ptr) {
        std::memset(ptr, 0, bytes);
    }
    return ptr;
}

void MARSController::FreeDeviceMemory(void* ptr) {
    if (ptr) {
        std::free(ptr);
    }
}

void MARSController::ResetRunTelemetry() {
    bytesHostToGpu_.store(0);
    bytesNvmeToRam_.store(0);
    residencyMisses_.store(0);
    spillToRam_.store(0);
    spillToNvme_.store(0);
    // Keep migrationCount_ cumulative across process; session delta via Snapshot.
    for (int g = 0; g < 2; ++g) {
        std::lock_guard<std::mutex> lock(pools_[g].mutex);
        pools_[g].peakUsedBytes = pools_[g].usedBytes;
    }
}

void MARSController::NoteHostToGpu(uint64_t bytes) { bytesHostToGpu_ += bytes; }
void MARSController::NoteNvmeToRam(uint64_t bytes) { bytesNvmeToRam_ += bytes; }
void MARSController::NoteResidencyMiss() { residencyMisses_++; }
void MARSController::NoteSpillToRam() { spillToRam_++; }
void MARSController::NoteSpillToNvme() { spillToNvme_++; }

LiveTelemetry MARSController::SnapshotTelemetry() const {
    LiveTelemetry t{};
    for (int g = 0; g < 2; ++g) {
        std::lock_guard<std::mutex> lock(pools_[g].mutex);
        t.usedVram[g] = pools_[g].usedBytes;
        t.peakVram[g] = pools_[g].peakUsedBytes;
        t.totalVram[g] = pools_[g].totalBytes;
        for (const auto& [id, lease] : pools_[g].tensors) {
            (void)id;
            if (!lease) continue;
            if (lease->pinned) t.pinnedCount++;
            if (lease->resident) t.residentCount++;
            else t.hostOnlyCount++;
        }
    }
    t.peakVramTotal = t.peakVram[0] + t.peakVram[1];
    t.bytesHostToGpu = bytesHostToGpu_.load();
    t.bytesNvmeToRam = bytesNvmeToRam_.load();
    t.migrations = static_cast<uint32_t>(migrationCount_.load());
    t.residencyMisses = residencyMisses_.load();
    t.spillToRam = spillToRam_.load();
    t.spillToNvme = spillToNvme_.load();
    return t;
}

void MARSController::CollectEffectivePlacement(
    std::vector<std::pair<std::string, int>>& outNameToGpu) const {
    outNameToGpu.clear();
    for (int g = 0; g < 2; ++g) {
        std::lock_guard<std::mutex> lock(pools_[g].mutex);
        for (const auto& [id, lease] : pools_[g].tensors) {
            (void)id;
            if (!lease || !lease->resident) continue;
            outNameToGpu.emplace_back(lease->tensorName, g);
        }
    }
}

} // namespace MARS
} // namespace Deep2
