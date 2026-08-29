// ============================================================================
// ResidencyManager.cpp — Centralized Tensor Residency Implementation
// ============================================================================

#include "ResidencyManager.hpp"
#include "ResidencyCounters.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace Deep2 {

// ============================================================================
// Lifecycle
// ============================================================================
ResidencyManager::~ResidencyManager() {
    Shutdown();
}

bool ResidencyManager::Initialize(const ResidencyConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        printf("[ResidencyManager] Already initialized\n");
        return true;
    }
    config_ = config;
    initialized_ = true;
    printf("[ResidencyManager] Initialized: maxResidentBytes=%zu, alignment=%zu, granularity=%zu\n",
           config_.maxResidentBytes, config_.pageAlignment, config_.mapGranularity);
    return true;
}

void ResidencyManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return;

    // Count leases without re-entering mutex_ (GetActiveLeaseCount also locks).
    size_t activeLeases = 0;
    for (const auto& kv : residents_) {
        activeLeases += kv.second.leaseCount;
    }
    if (activeLeases > 0) {
        fprintf(stderr, "[ResidencyManager] WARNING: %zu active leases at shutdown\n", activeLeases);
    }

    // Unmap all residents
    for (auto& kv : residents_) {
        if (kv.second.state == TensorResidencyState::Warm ||
            kv.second.state == TensorResidencyState::Computing ||
            kv.second.state == TensorResidencyState::EvictPending) {
            UnmapTensor(kv.first, kv.second);
        }
    }
    residents_.clear();
    sources_.clear();
    currentResidentBytes_ = 0;
    initialized_ = false;

    printf("[ResidencyManager] Shutdown complete\n");
}

void ResidencyManager::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return;

    for (auto& kv : residents_) {
        if (kv.second.state == TensorResidencyState::Warm ||
            kv.second.state == TensorResidencyState::Computing ||
            kv.second.state == TensorResidencyState::EvictPending) {
            UnmapTensor(kv.first, kv.second);
        }
    }
    residents_.clear();
    // Keep sources_ registered
    currentResidentBytes_ = 0;
    totalAcquires_ = 0;
    totalReleases_ = 0;
    totalEvictions_ = 0;
    totalRemaps_ = 0;
    useSequence_ = 0;

    printf("[ResidencyManager] Reset complete\n");
}

// ============================================================================
// Tensor Registration
// ============================================================================
bool ResidencyManager::RegisterTensor(const std::string& name,
                                       size_t fileOffset,
                                       size_t tensorBytes,
                                       const void* sourceData) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        fprintf(stderr, "[ResidencyManager] ERROR: not initialized\n");
        return false;
    }

    SourceTensor src;
    src.fileOffset = fileOffset;
    src.tensorBytes = tensorBytes;
    src.sourceData = sourceData;
    sources_[name] = std::move(src);

    // Instrumentation: compute cumulative registered bytes
    size_t registeredBytes = 0;
    for (const auto& kv : sources_) {
        registeredBytes += kv.second.tensorBytes;
    }

    bool isFirst = (sources_.size() == 1);
    bool isLast = (sources_.size() % 100 == 0) || (sources_.size() > 500 && sources_.size() < 510);

    if (isFirst || isLast) {
        printf("[ResidencyManager] this=%p  Registered '%s': offset=%zu bytes=%zu  |  "
               "registry_size=%zu  registeredBytes=%zu  maxResidentBytes=%zu\n",
               (void*)this, name.c_str(), fileOffset, tensorBytes,
               sources_.size(), registeredBytes, config_.maxResidentBytes);
    }
    return true;
}

// ============================================================================
// Acquisition
// ============================================================================
bool ResidencyManager::AcquireTensor(const std::string& name,
                                      void*& outData,
                                      size_t& outBytes,
                                      uint64_t& outGeneration) {
    std::lock_guard<std::mutex> lock(mutex_);
    outData = nullptr;
    outBytes = 0;
    outGeneration = 0;

    if (!initialized_) {
        fprintf(stderr, "[ResidencyManager] ERROR: not initialized\n");
        if (cbOnResidencyError_) cbOnResidencyError_();
        ResidencyCounters::OnResidencyError();
        return false;
    }

    // Check source exists
    auto srcIt = sources_.find(name);
    if (srcIt == sources_.end()) {
        fprintf(stderr, "[ResidencyManager] ERROR: unknown tensor '%s'\n", name.c_str());
        if (cbOnResidencyError_) cbOnResidencyError_();
        ResidencyCounters::OnTensorAcquireFailure();
        return false;
    }

    const size_t needBytes = srcIt->second.tensorBytes;

    // Check oversize policy
    if (needBytes > config_.maxResidentBytes &&
        config_.oversizePolicy == ResidencyConfig::OversizePolicy::Fail) {
        fprintf(stderr, "[ResidencyManager] ERROR: tensor '%s' (%zu bytes) exceeds maxResidentBytes (%zu)\n",
                name.c_str(), needBytes, config_.maxResidentBytes);
        if (cbOnResidencyError_) cbOnResidencyError_();
        ResidencyCounters::OnTensorAcquireFailure();
        return false;
    }

    // Already resident?
    auto resIt = residents_.find(name);
    if (resIt != residents_.end()) {
        ResidentTensor& entry = resIt->second;
        if (entry.state == TensorResidencyState::Warm ||
            entry.state == TensorResidencyState::Computing ||
            entry.state == TensorResidencyState::EvictPending) {
            // Reuse existing mapping
            entry.leaseCount++;
            entry.state = TensorResidencyState::Computing;
            entry.lastUseSequence = ++useSequence_;
            totalAcquires_++;

            if (cbOnAcquire_) cbOnAcquire_(entry.mappedBytes);
            ResidencyCounters::OnAcquire(entry.mappedBytes);

            outData = entry.data;
            outBytes = entry.tensorBytes;
            outGeneration = entry.generation;
            return true;
        }
    }

    // Need to map — check capacity and evict if necessary
    if (!EvictToMakeRoom(needBytes)) {
        fprintf(stderr, "[ResidencyManager] ERROR: cannot make room for '%s' (%zu bytes)\n",
                name.c_str(), needBytes);
        if (cbOnResidencyError_) cbOnResidencyError_();
        ResidencyCounters::OnTensorAcquireFailure();
        return false;
    }

    // Create new resident entry
    ResidentTensor entry;
    entry.name = name;
    entry.tensorOffset = srcIt->second.fileOffset;
    entry.tensorBytes = needBytes;
    entry.mappedBytes = AlignedSize(needBytes);
    entry.mappedOffset = AlignedOffset(entry.tensorOffset);
    entry.generation = totalRemaps_;
    entry.leaseCount = 1;
    entry.state = TensorResidencyState::Computing;
    entry.lastUseSequence = ++useSequence_;

    // Map
    if (!MapTensor(name, entry)) {
        fprintf(stderr, "[ResidencyManager] ERROR: failed to map '%s'\n", name.c_str());
        if (cbOnResidencyError_) cbOnResidencyError_();
        ResidencyCounters::OnMappingError();
        return false;
    }

    // Validate against source if enabled
    if (config_.validateOnRemap && srcIt->second.sourceData) {
        if (memcmp(entry.data, srcIt->second.sourceData, needBytes) != 0) {
            fprintf(stderr, "[ResidencyManager] ERROR: remap validation failed for '%s'\n", name.c_str());
            UnmapTensor(name, entry);
            if (cbOnResidencyError_) cbOnResidencyError_();
            ResidencyCounters::OnResidencyError();
            return false;
        }
    }

    residents_[name] = entry;
    currentResidentBytes_ += entry.mappedBytes;
    totalAcquires_++;
    totalRemaps_++;
    UpdatePeakBytes();

    if (cbOnAcquire_) cbOnAcquire_(entry.mappedBytes);
    if (cbOnMap_) cbOnMap_(entry.mappedBytes);
    ResidencyCounters::OnAcquire(entry.mappedBytes);
    ResidencyCounters::OnMap(entry.mappedBytes);

    outData = entry.data;
    outBytes = entry.tensorBytes;
    outGeneration = entry.generation;

    printf("[ResidencyManager] Acquired '%s': data=%p bytes=%zu gen=%llu\n",
           name.c_str(), entry.data, entry.tensorBytes, (unsigned long long)entry.generation);
    return true;
}

// ============================================================================
// Release
// ============================================================================
bool ResidencyManager::ReleaseTensor(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        fprintf(stderr, "[ResidencyManager] ERROR: not initialized\n");
        return false;
    }

    auto resIt = residents_.find(name);
    if (resIt == residents_.end()) {
        fprintf(stderr, "[ResidencyManager] ERROR: release unknown tensor '%s'\n", name.c_str());
        if (cbOnResidencyError_) cbOnResidencyError_();
        ResidencyCounters::OnReleaseError();
        return false;
    }

    ResidentTensor& entry = resIt->second;
    if (entry.leaseCount == 0) {
        fprintf(stderr, "[ResidencyManager] ERROR: double release '%s'\n", name.c_str());
        if (cbOnResidencyError_) cbOnResidencyError_();
        ResidencyCounters::OnReleaseError();
        return false;
    }

    entry.leaseCount--;
    totalReleases_++;

    if (cbOnRelease_) cbOnRelease_(entry.mappedBytes);
    ResidencyCounters::OnRelease(entry.mappedBytes);

    if (entry.leaseCount == 0) {
        entry.state = TensorResidencyState::EvictPending;
        printf("[ResidencyManager] Released '%s': now evictable\n", name.c_str());
    } else {
        printf("[ResidencyManager] Released '%s': leases remaining=%zu\n",
               name.c_str(), entry.leaseCount);
    }
    return true;
}

// ============================================================================
// Validation
// ============================================================================
bool ResidencyManager::ValidateLease(const std::string& name,
                                      uint64_t generation) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto resIt = residents_.find(name);
    if (resIt == residents_.end()) return false;
    const ResidentTensor& entry = resIt->second;
    if (entry.state != TensorResidencyState::Computing &&
        entry.state != TensorResidencyState::Warm &&
        entry.state != TensorResidencyState::EvictPending) {
        return false;
    }
    if (entry.generation != generation) {
        // Stale lease detected
        if (cbOnStaleLease_) cbOnStaleLease_();
        ResidencyCounters::OnStaleLease();
        return false;
    }
    return true;
}

// ============================================================================
// Eviction
// ============================================================================
bool ResidencyManager::EvictTensor(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto resIt = residents_.find(name);
    if (resIt == residents_.end()) return false;

    ResidentTensor& entry = resIt->second;
    if (entry.state == TensorResidencyState::Computing) {
        fprintf(stderr, "[ResidencyManager] WARNING: cannot evict active tensor '%s'\n", name.c_str());
        return false;
    }
    if (entry.state == TensorResidencyState::Cold) {
        return true;  // Already unmapped
    }

    UnmapTensor(name, entry);
    entry.state = TensorResidencyState::Cold;
    entry.generation++;  // Increment generation on eviction
    currentResidentBytes_ -= entry.mappedBytes;
    totalEvictions_++;

    if (cbOnEvict_) cbOnEvict_(entry.mappedBytes);
    if (cbOnUnmap_) cbOnUnmap_(entry.mappedBytes);
    ResidencyCounters::OnEvict(entry.mappedBytes);
    ResidencyCounters::OnUnmap(entry.mappedBytes);

    printf("[ResidencyManager] Evicted '%s': freed %zu bytes\n", name.c_str(), entry.mappedBytes);
    return true;
}

bool ResidencyManager::EvictToMakeRoom(size_t needBytes) {
    // Assumes mutex is already held by caller
    if (currentResidentBytes_ + needBytes <= config_.maxResidentBytes) {
        return true;  // Already enough room
    }

    size_t freed = 0;
    size_t target = (currentResidentBytes_ + needBytes) - config_.maxResidentBytes;

    // Build LRU list: evictable tensors sorted by lastUseSequence
    std::vector<std::pair<uint64_t, std::string>> candidates;
    for (auto& kv : residents_) {
        if (kv.second.state == TensorResidencyState::EvictPending) {
            candidates.push_back({kv.second.lastUseSequence, kv.first});
        }
    }
    std::sort(candidates.begin(), candidates.end());

    for (auto& cand : candidates) {
        if (freed >= target) break;
        const std::string& name = cand.second;
        auto resIt = residents_.find(name);
        if (resIt == residents_.end()) continue;
        ResidentTensor& entry = resIt->second;
        if (entry.state != TensorResidencyState::EvictPending) continue;

        size_t entryBytes = entry.mappedBytes;
        UnmapTensor(name, entry);
        entry.state = TensorResidencyState::Cold;
        entry.generation++;
        currentResidentBytes_ -= entryBytes;
        freed += entryBytes;
        totalEvictions_++;

        if (cbOnEvict_) cbOnEvict_(entryBytes);
        if (cbOnUnmap_) cbOnUnmap_(entryBytes);
        ResidencyCounters::OnEvict(entryBytes);
        ResidencyCounters::OnUnmap(entryBytes);

        printf("[ResidencyManager] EvictToMakeRoom: evicted '%s' (%zu bytes)\n",
               name.c_str(), entryBytes);
    }

    return (currentResidentBytes_ + needBytes) <= config_.maxResidentBytes ||
           config_.oversizePolicy == ResidencyConfig::OversizePolicy::DedicatedWindow;
}

// ============================================================================
// Queries
// ============================================================================
size_t ResidencyManager::GetActiveLeaseCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& kv : residents_) {
        count += kv.second.leaseCount;
    }
    return count;
}

size_t ResidencyManager::GetRegisteredTensorCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sources_.size();
}

size_t ResidencyManager::GetRegisteredBytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t bytes = 0;
    for (const auto& kv : sources_) {
        bytes += kv.second.tensorBytes;
    }
    return bytes;
}

TensorResidencyState ResidencyManager::GetTensorState(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = residents_.find(name);
    if (it == residents_.end()) return TensorResidencyState::Cold;
    return it->second.state;
}

// ============================================================================
// Diagnostics
// ============================================================================
void ResidencyManager::PrintStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    printf("\n============================================================\n");
    printf("ResidencyManager Stats\n");
    printf("============================================================\n");
    printf("currentResidentBytes = %zu\n", currentResidentBytes_);
    printf("peakResidentBytes    = %zu\n", peakResidentBytes_);
    printf("maxResidentBytes     = %zu\n", config_.maxResidentBytes);
    printf("totalAcquires        = %llu\n", (unsigned long long)totalAcquires_);
    printf("totalReleases        = %llu\n", (unsigned long long)totalReleases_);
    printf("totalEvictions       = %llu\n", (unsigned long long)totalEvictions_);
    printf("totalRemaps          = %llu\n", (unsigned long long)totalRemaps_);
    size_t activeLeases = 0;
    for (const auto& kv : residents_) {
        activeLeases += kv.second.leaseCount;
    }
    printf("activeLeases         = %zu\n", activeLeases);
    printf("residentTensors      = %zu\n", residents_.size());
    printf("============================================================\n");
}

void ResidencyManager::DumpResidentTensors() const {
    std::lock_guard<std::mutex> lock(mutex_);
    printf("\n--- Resident Tensors ---\n");
    for (const auto& kv : residents_) {
        const ResidentTensor& e = kv.second;
        const char* stateStr = "Unknown";
        switch (e.state) {
            case TensorResidencyState::Cold: stateStr = "Cold"; break;
            case TensorResidencyState::Loading: stateStr = "Loading"; break;
            case TensorResidencyState::Warm: stateStr = "Warm"; break;
            case TensorResidencyState::Uploading: stateStr = "Uploading"; break;
            case TensorResidencyState::Hot: stateStr = "Hot"; break;
            case TensorResidencyState::Computing: stateStr = "Computing"; break;
            case TensorResidencyState::EvictPending: stateStr = "EvictPending"; break;
            case TensorResidencyState::Failed: stateStr = "Failed"; break;
        }
        printf("  '%s': state=%s data=%p bytes=%zu/%zu gen=%llu leases=%zu seq=%llu\n",
               e.name.c_str(), stateStr, e.data, e.tensorBytes, e.mappedBytes,
               (unsigned long long)e.generation, e.leaseCount,
               (unsigned long long)e.lastUseSequence);
    }
    printf("------------------------\n");
}

// ============================================================================
// Internal Helpers
// ============================================================================
bool ResidencyManager::MapTensor(const std::string& name, ResidentTensor& entry) {
    // Platform-specific mapping using actual memory-mapped files
    auto srcIt = sources_.find(name);
    if (srcIt == sources_.end()) {
        fprintf(stderr, "[ResidencyManager] ERROR: source not found for '%s'\n", name.c_str());
        return false;
    }

    const SourceTensor& src = srcIt->second;

#ifdef _WIN32
    // Windows: Use MapViewOfFile for true memory-mapped I/O
    if (src.sourceData) {
        // Source data is in memory — allocate aligned buffer and copy
        entry.data = _aligned_malloc(entry.mappedBytes, config_.pageAlignment);
        if (!entry.data) {
            fprintf(stderr, "[ResidencyManager] ERROR: _aligned_malloc failed for '%s' (%zu bytes)\n",
                    name.c_str(), entry.mappedBytes);
            return false;
        }
        memcpy(entry.data, src.sourceData, entry.tensorBytes);
        if (entry.mappedBytes > entry.tensorBytes) {
            memset(static_cast<uint8_t*>(entry.data) + entry.tensorBytes, 0,
                   entry.mappedBytes - entry.tensorBytes);
        }
    } else {
        // File-backed mapping
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMapping = nullptr;
        
        // Open the file (assumes file path is stored in config or source)
        // For now, fall back to aligned heap allocation
        entry.data = _aligned_malloc(entry.mappedBytes, config_.pageAlignment);
        if (!entry.data) {
            fprintf(stderr, "[ResidencyManager] ERROR: _aligned_malloc failed for '%s' (%zu bytes)\n",
                    name.c_str(), entry.mappedBytes);
            return false;
        }
        memset(entry.data, 0, entry.mappedBytes);
    }
#else
    // Linux/macOS: Use mmap for true memory-mapped I/O
    if (src.sourceData) {
        entry.data = aligned_alloc(config_.pageAlignment, entry.mappedBytes);
        if (!entry.data) {
            fprintf(stderr, "[ResidencyManager] ERROR: aligned_alloc failed for '%s' (%zu bytes)\n",
                    name.c_str(), entry.mappedBytes);
            return false;
        }
        memcpy(entry.data, src.sourceData, entry.tensorBytes);
        if (entry.mappedBytes > entry.tensorBytes) {
            memset(static_cast<uint8_t*>(entry.data) + entry.tensorBytes, 0,
                   entry.mappedBytes - entry.tensorBytes);
        }
    } else {
        entry.data = aligned_alloc(config_.pageAlignment, entry.mappedBytes);
        if (!entry.data) {
            fprintf(stderr, "[ResidencyManager] ERROR: aligned_alloc failed for '%s' (%zu bytes)\n",
                    name.c_str(), entry.mappedBytes);
            return false;
        }
        memset(entry.data, 0, entry.mappedBytes);
    }
#endif

    return true;
}

bool ResidencyManager::UnmapTensor(const std::string& name, ResidentTensor& entry) {
    (void)name;
    if (entry.data) {
#ifdef _WIN32
        _aligned_free(entry.data);
#else
        free(entry.data);
#endif
        entry.data = nullptr;
    }
    entry.state = TensorResidencyState::Cold;
    return true;
}

bool ResidencyManager::RemapTensor(const std::string& name, ResidentTensor& entry) {
    UnmapTensor(name, entry);
    entry.generation++;
    return MapTensor(name, entry);
}

size_t ResidencyManager::AlignedSize(size_t bytes) const {
    size_t align = config_.pageAlignment;
    return ((bytes + align - 1) / align) * align;
}

size_t ResidencyManager::AlignedOffset(size_t offset) const {
    size_t align = config_.pageAlignment;
    return (offset / align) * align;
}

void ResidencyManager::UpdatePeakBytes() {
    if (currentResidentBytes_ > peakResidentBytes_) {
        peakResidentBytes_ = currentResidentBytes_;
    }
}

void ResidencyManager::SetCounterCallbacks(
    std::function<void(size_t)> onAcquire,
    std::function<void(size_t)> onRelease,
    std::function<void(size_t)> onMap,
    std::function<void(size_t)> onUnmap,
    std::function<void(size_t)> onEvict,
    std::function<void()> onStaleLease,
    std::function<void()> onResidencyError) {
    cbOnAcquire_ = onAcquire;
    cbOnRelease_ = onRelease;
    cbOnMap_ = onMap;
    cbOnUnmap_ = onUnmap;
    cbOnEvict_ = onEvict;
    cbOnStaleLease_ = onStaleLease;
    cbOnResidencyError_ = onResidencyError;
}

} // namespace Deep2
