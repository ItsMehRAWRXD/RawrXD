// ============================================================================
// VRAMManager.cpp - MARS: Memory Allocation + Routing System
// ============================================================================

#include "VRAMManager.hpp"
#include <algorithm>
#include <cstring>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Constructor / Destructor
// ============================================================================
VRAMManager::VRAMManager() = default;

VRAMManager::~VRAMManager() {
    if (initialized_) {
        Shutdown();
    }
}

// ============================================================================
// Lifecycle
// ============================================================================
bool VRAMManager::Initialize(size_t gpu0TotalBytes, size_t gpu1TotalBytes) {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    gpuTotal_[0] = gpu0TotalBytes;
    gpuTotal_[1] = gpu1TotalBytes;
    gpuUsed_[0]  = 0;
    gpuUsed_[1]  = 0;

    gpuState_[0] = GPUState{0, gpu0TotalBytes, gpu0TotalBytes, 0, 0.0f, 0.0f, 0.0f, true};
    gpuState_[1] = GPUState{1, gpu1TotalBytes, gpu1TotalBytes, 0, 0.0f, 0.0f, 0.0f, true};

    initialized_ = true;
    printf("[VRAMManager] Initialized: GPU0=%.2f GB, GPU1=%.2f GB\n",
           gpu0TotalBytes / (1024.0 * 1024.0 * 1024.0),
           gpu1TotalBytes / (1024.0 * 1024.0 * 1024.0));
    return true;
}

void VRAMManager::Shutdown() {
    FreeAll();
    initialized_ = false;
    printf("[VRAMManager] Shutdown complete\n");
}

// ============================================================================
// Core Operations
// ============================================================================
VRAMLease* VRAMManager::Allocate(
    uint64_t tensorId,
    const std::string& name,
    size_t bytes,
    float priority,
    bool hotpatchable) {

    if (!initialized_ || bytes == 0) {
        return nullptr;
    }

    int targetGPU = SelectBestGPU(bytes, priority, false);
    if (targetGPU < 0) {
        // Try to evict something to make room
        targetGPU = FindVictimGPU(bytes, -1);
        if (targetGPU < 0) {
            std::lock_guard<std::mutex> slock(statsMutex_);
            stats_.oomCount++;
            if (onOOM_) {
                bool handled = onOOM_(bytes, targetGPU);
                if (handled) {
                    targetGPU = SelectBestGPU(bytes, priority, false);
                }
            }
            if (targetGPU < 0) {
                printf("[VRAMManager] OOM: Cannot allocate %zu bytes for '%s'\n",
                       bytes, name.c_str());
                return nullptr;
            }
        }
    }

    if (!TryReserveVRAM(targetGPU, bytes)) {
        return nullptr;
    }

    auto lease = std::make_unique<VRAMLease>();
    lease->tensorId     = tensorId;
    lease->name         = name;
    lease->bytes        = bytes;
    lease->currentGPU   = targetGPU;
    lease->preferredGPU = targetGPU;
    lease->priority     = priority;
    lease->hotpatchable = hotpatchable;
    lease->state        = LeaseState::RESIDENT;
    lease->lastAccessTick = 0;
    lease->migrateCount   = 0;
    lease->needsRebuild   = false;
    lease->originalGPU    = targetGPU;

    VRAMLease* ptr = lease.get();

    {
        std::lock_guard<std::mutex> lock(leaseMutex_);
        leases_[tensorId] = std::move(lease);
    }

    {
        std::lock_guard<std::mutex> slock(statsMutex_);
        stats_.totalAllocated += bytes;
        stats_.bytesHostToGpu += bytes;
    }

    printf("[VRAMManager] Allocated '%s' (%zu bytes) on GPU %d\n",
           name.c_str(), bytes, targetGPU);
    return ptr;
}

bool VRAMManager::Evict(VRAMLease* lease) {
    if (!lease || !lease->IsResident()) {
        return false;
    }

    int gpu = lease->currentGPU;
    size_t bytes = lease->bytes;

    ReleaseVRAM(gpu, bytes);

    lease->state = LeaseState::EVICTED;
    lease->currentGPU = -1;
    lease->needsRebuild = false;

    {
        std::lock_guard<std::mutex> slock(statsMutex_);
        stats_.totalEvicted += bytes;
        stats_.spillToRam += 1;
    }

    if (onEvict_) {
        onEvict_(*lease);
    }

    printf("[VRAMManager] Evicted '%s' (%zu bytes) from GPU %d to host\n",
           lease->name.c_str(), bytes, gpu);
    return true;
}

bool VRAMManager::Migrate(VRAMLease* lease, int targetGPU) {
    if (!lease || !lease->hotpatchable || lease->pinned) {
        return false;
    }
    if (lease->currentGPU == targetGPU) {
        return true;
    }
    if (targetGPU < 0 || targetGPU >= 2) {
        return false;
    }

    size_t bytes = lease->bytes;
    int sourceGPU = lease->currentGPU;

    // Reserve on target first
    if (!TryReserveVRAM(targetGPU, bytes)) {
        // Try to make room
        int victim = FindVictimGPU(bytes, targetGPU);
        if (victim == targetGPU) {
            // Need to evict something on target
            // (simplified: just fail for now)
            printf("[VRAMManager] Migrate failed: no room on GPU %d\n", targetGPU);
            return false;
        }
    }

    // Mark migrating
    lease->state = LeaseState::MIGRATING;

    // Release from source
    if (sourceGPU >= 0) {
        ReleaseVRAM(sourceGPU, bytes);
    }

    // Update lease
    lease->currentGPU = targetGPU;
    lease->state = LeaseState::RESIDENT;
    lease->migrateCount++;
    lease->lastAccessTick = 0;

    RecordMigration(*lease, sourceGPU, targetGPU);

    {
        std::lock_guard<std::mutex> slock(statsMutex_);
        stats_.totalMigrated += bytes;
    }

    if (onMigrate_) {
        onMigrate_(*lease, sourceGPU, targetGPU);
    }

    printf("[VRAMManager] Migrated '%s' (%zu bytes) GPU %d -> GPU %d\n",
           lease->name.c_str(), bytes, sourceGPU, targetGPU);
    return true;
}

bool VRAMManager::Restore(VRAMLease* lease, int preferredGPU) {
    if (!lease || lease->state != LeaseState::EVICTED) {
        return false;
    }

    int targetGPU = (preferredGPU >= 0) ? preferredGPU : lease->preferredGPU;
    if (targetGPU < 0) {
        targetGPU = SelectBestGPU(lease->bytes, lease->priority, false);
    }
    if (targetGPU < 0) {
        return false;
    }

    size_t bytes = lease->bytes;
    if (!TryReserveVRAM(targetGPU, bytes)) {
        return false;
    }

    lease->currentGPU = targetGPU;
    lease->state = LeaseState::RESIDENT;
    lease->needsRebuild = false;

    {
        std::lock_guard<std::mutex> slock(statsMutex_);
        stats_.totalRestored += bytes;
    }

    printf("[VRAMManager] Restored '%s' (%zu bytes) to GPU %d\n",
           lease->name.c_str(), bytes, targetGPU);
    return true;
}

void VRAMManager::Free(VRAMLease* lease) {
    if (!lease) return;

    uint64_t tid = lease->tensorId;
    int gpu = lease->currentGPU;
    size_t bytes = lease->bytes;

    if (gpu >= 0) {
        ReleaseVRAM(gpu, bytes);
    }

    {
        std::lock_guard<std::mutex> lock(leaseMutex_);
        leases_.erase(tid);
    }

    {
        std::lock_guard<std::mutex> slock(statsMutex_);
        stats_.totalFreed += bytes;
    }

    printf("[VRAMManager] Freed '%s' (%zu bytes)\n", lease->name.c_str(), bytes);
}

// ============================================================================
// Bulk Operations
// ============================================================================
void VRAMManager::EvictAllOnGPU(int gpu) {
    std::vector<VRAMLease*> toEvict;
    {
        std::lock_guard<std::mutex> lock(leaseMutex_);
        for (auto& [id, lease] : leases_) {
            if (lease->currentGPU == gpu && lease->IsResident()) {
                toEvict.push_back(lease.get());
            }
        }
    }
    for (auto* lease : toEvict) {
        Evict(lease);
    }
}

void VRAMManager::MigrateAll(int fromGPU, int toGPU) {
    std::vector<VRAMLease*> toMigrate;
    {
        std::lock_guard<std::mutex> lock(leaseMutex_);
        for (auto& [id, lease] : leases_) {
            if (lease->currentGPU == fromGPU && lease->hotpatchable && !lease->pinned) {
                toMigrate.push_back(lease.get());
            }
        }
    }
    for (auto* lease : toMigrate) {
        Migrate(lease, toGPU);
    }
}

void VRAMManager::FreeAll() {
    std::lock_guard<std::mutex> lock(leaseMutex_);
    std::lock_guard<std::mutex> glock(gpuMutex_);
    leases_.clear();
    gpuUsed_[0] = 0;
    gpuUsed_[1] = 0;
}

// ============================================================================
// Queries
// ============================================================================
VRAMLease* VRAMManager::GetLease(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(leaseMutex_);
    auto it = leases_.find(tensorId);
    if (it != leases_.end()) {
        return it->second.get();
    }
    return nullptr;
}

const VRAMLease* VRAMManager::GetLease(uint64_t tensorId) const {
    std::lock_guard<std::mutex> lock(leaseMutex_);
    auto it = leases_.find(tensorId);
    if (it != leases_.end()) {
        return it->second.get();
    }
    return nullptr;
}

size_t VRAMManager::GetUsedVRAM(int gpu) const {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    return (gpu >= 0 && gpu < 2) ? gpuUsed_[gpu] : 0;
}

size_t VRAMManager::GetFreeVRAM(int gpu) const {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    return (gpu >= 0 && gpu < 2) ? (gpuTotal_[gpu] - gpuUsed_[gpu]) : 0;
}

size_t VRAMManager::GetTotalVRAM(int gpu) const {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    return (gpu >= 0 && gpu < 2) ? gpuTotal_[gpu] : 0;
}

size_t VRAMManager::GetLeaseCount() const {
    std::lock_guard<std::mutex> lock(leaseMutex_);
    return leases_.size();
}

size_t VRAMManager::GetResidentCount(int gpu) const {
    std::lock_guard<std::mutex> lock(leaseMutex_);
    size_t count = 0;
    for (const auto& [id, lease] : leases_) {
        if (lease->currentGPU == gpu && lease->IsResident()) {
            count++;
        }
    }
    return count;
}

std::vector<VRAMLease*> VRAMManager::SnapshotLeases() const {
    std::lock_guard<std::mutex> lock(leaseMutex_);
    std::vector<VRAMLease*> out;
    out.reserve(leases_.size());
    for (const auto& [id, lease] : leases_) {
        (void)id;
        if (lease) out.push_back(lease.get());
    }
    return out;
}

// ============================================================================
// Dynamic Parity
// ============================================================================
void VRAMManager::UpdateGPUState(int gpu, const GPUState& state) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (gpu >= 0 && gpu < 2) {
        gpuState_[gpu] = state;
    }
}

DynamicParity VRAMManager::GetDynamicParity() const {
    std::lock_guard<std::mutex> glock(gpuMutex_);
    std::lock_guard<std::mutex> slock(stateMutex_);
    DynamicParity dp;
    for (int i = 0; i < 2; ++i) {
        dp.gpu[i] = gpuState_[i];
        dp.gpu[i].index = i;
        dp.gpu[i].vramTotal = gpuTotal_[i];
        dp.gpu[i].vramUsed = gpuUsed_[i];
        dp.gpu[i].vramFree = (gpuTotal_[i] > gpuUsed_[i])
            ? (gpuTotal_[i] - gpuUsed_[i]) : 0;
        dp.gpu[i].healthy = gpuState_[i].healthy;
    }
    return dp;
}

// ============================================================================
// Strategy
// ============================================================================
int VRAMManager::SelectBestGPU(size_t bytes, float priority, bool preferLowLatency) const {
    std::lock_guard<std::mutex> glock(gpuMutex_);
    std::lock_guard<std::mutex> slock(stateMutex_);

    bool fit0 = (gpuTotal_[0] - gpuUsed_[0]) >= bytes;
    bool fit1 = (gpuTotal_[1] - gpuUsed_[1]) >= bytes;

    if (!fit0 && !fit1) {
        return -1;
    }
    if (fit0 && !fit1) {
        return 0;
    }
    if (!fit0 && fit1) {
        return 1;
    }

    // Both fit - use heuristics
    if (preferLowLatency) {
        // Lower load = lower latency
        float load0 = gpuState_[0].load;
        float load1 = gpuState_[1].load;
        return (load0 <= load1) ? 0 : 1;
    } else {
        // More free VRAM = better for bandwidth
        size_t free0 = gpuTotal_[0] - gpuUsed_[0];
        size_t free1 = gpuTotal_[1] - gpuUsed_[1];
        return (free0 >= free1) ? 0 : 1;
    }
}

// ============================================================================
// Rollback
// ============================================================================
bool VRAMManager::RollbackLastMigration(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(historyMutex_);
    auto it = migrationHistory_.find(tensorId);
    if (it == migrationHistory_.end() || it->second.empty()) {
        return false;
    }

    const MigrationRecord& rec = it->second.back();
    VRAMLease* lease = GetLease(tensorId);
    if (!lease) {
        return false;
    }

    // Reverse the migration
    bool ok = Migrate(lease, rec.fromGPU);
    if (ok) {
        it->second.pop_back();
        std::lock_guard<std::mutex> slock(statsMutex_);
        stats_.rollbackCount++;
    }
    return ok;
}

void VRAMManager::ClearMigrationHistory(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(historyMutex_);
    migrationHistory_.erase(tensorId);
}

// ============================================================================
// Stats
// ============================================================================
VRAMManager::Stats VRAMManager::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void VRAMManager::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

void VRAMManager::ResetRunPeaks() {
    {
        std::lock_guard<std::mutex> glock(gpuMutex_);
        gpuPeak_[0] = gpuUsed_[0];
        gpuPeak_[1] = gpuUsed_[1];
    }
    std::lock_guard<std::mutex> slock(statsMutex_);
    stats_.peakUsed[0] = gpuPeak_[0];
    stats_.peakUsed[1] = gpuPeak_[1];
    stats_.bytesHostToGpu = 0;
    stats_.bytesNvmeToRam = 0;
    stats_.residencyMisses = 0;
    stats_.spillToRam = 0;
    stats_.spillToNvme = 0;
}

void VRAMManager::NoteNvmeToRam(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_.bytesNvmeToRam += bytes;
}

void VRAMManager::NoteResidencyMiss() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_.residencyMisses += 1;
}

void VRAMManager::NoteSpillToNvme() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_.spillToNvme += 1;
}

VRAMManager::LiveSnapshot VRAMManager::SnapshotLive() const {
    LiveSnapshot s{};
    {
        std::lock_guard<std::mutex> lock(gpuMutex_);
        s.usedVram[0] = gpuUsed_[0];
        s.usedVram[1] = gpuUsed_[1];
        s.totalVram[0] = gpuTotal_[0];
        s.totalVram[1] = gpuTotal_[1];
        s.peakVram[0] = gpuPeak_[0];
        s.peakVram[1] = gpuPeak_[1];
    }
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        s.bytesHostToGpu = stats_.bytesHostToGpu;
        s.bytesNvmeToRam = stats_.bytesNvmeToRam;
        s.migrations = static_cast<uint32_t>(stats_.totalMigrated / (1ULL << 20));
        if (stats_.totalMigrated > 0 && s.migrations == 0) s.migrations = 1;
        s.residencyMisses = stats_.residencyMisses;
        s.spillToRam = stats_.spillToRam;
        s.spillToNvme = stats_.spillToNvme;
    }
    s.peakVramTotal = s.peakVram[0] + s.peakVram[1];
    s.residentCount = static_cast<uint32_t>(GetResidentCount(0) + GetResidentCount(1));
    return s;
}

// ============================================================================
// Internal
// ============================================================================
bool VRAMManager::TryReserveVRAM(int gpu, size_t bytes) {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    if (gpu < 0 || gpu >= 2) return false;
    if (gpuUsed_[gpu] + bytes > gpuTotal_[gpu]) {
        return false;
    }
    gpuUsed_[gpu] += bytes;
    if (gpuUsed_[gpu] > gpuPeak_[gpu])
        gpuPeak_[gpu] = gpuUsed_[gpu];
    return true;
}

void VRAMManager::ReleaseVRAM(int gpu, size_t bytes) {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    if (gpu < 0 || gpu >= 2) return;
    if (gpuUsed_[gpu] >= bytes) {
        gpuUsed_[gpu] -= bytes;
    } else {
        gpuUsed_[gpu] = 0;
    }
}

int VRAMManager::FindVictimGPU(size_t bytesNeeded, int requestingGPU) const {
    // Find GPU with most evictable (non-pinned, lower priority) leases
    // Return that GPU index so caller can evict from it
    (void)requestingGPU;
    std::lock_guard<std::mutex> lock(leaseMutex_);

    size_t bestBytes = 0;
    int bestGPU = -1;

    for (int gpu = 0; gpu < 2; ++gpu) {
        size_t evictable = 0;
        for (const auto& [id, lease] : leases_) {
            if (lease->currentGPU == gpu && lease->IsResident() &&
                lease->hotpatchable && !lease->pinned &&
                lease->priority < 5.0f) {
                evictable += lease->bytes;
            }
        }
        if (evictable >= bytesNeeded && evictable > bestBytes) {
            bestBytes = evictable;
            bestGPU = gpu;
        }
    }
    return bestGPU;
}

void VRAMManager::RecordMigration(const VRAMLease& lease, int from, int to) {
    std::lock_guard<std::mutex> lock(historyMutex_);
    MigrationRecord rec;
    rec.tensorId = lease.tensorId;
    rec.fromGPU = from;
    rec.toGPU = to;
    rec.bytes = lease.bytes;
    rec.timestamp = 0; // Could use steady_clock
    migrationHistory_[lease.tensorId].push_back(rec);
}

// ============================================================================
// Callbacks
// ============================================================================
void VRAMManager::SetEvictCallback(EvictCallback cb) {
    onEvict_ = cb;
}
void VRAMManager::SetMigrateCallback(MigrateCallback cb) {
    onMigrate_ = cb;
}
void VRAMManager::SetOOMCallback(OOMCallback cb) {
    onOOM_ = cb;
}

} // namespace MARS
} // namespace Deep2
