// ============================================================================
// VRAMAllocator.cpp - Phase 2: Multi-GPU Scheduler
// VRAM allocation and memory management (reconciled to the current header).
//
// The authoritative per-LUID admission ledger (reservationLedger_) is embedded;
// Initialize(capacities) seeds both the pools and the ledger from real measured
// per-LUID VRAM (HostHardwareSnapshot), so allocation and admission agree.
// ============================================================================

#include "VRAMAllocator.h"

#include <algorithm>
#include <limits>

namespace Deep2 {
namespace MultiGPU {

VRAMAllocator::VRAMAllocator() = default;
VRAMAllocator::~VRAMAllocator() = default;

bool VRAMAllocator::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) return true;
    initialized_ = true;
    return true;
}

bool VRAMAllocator::Initialize(const std::vector<DeviceCapacity>& caps) {
    std::lock_guard<std::mutex> lock(mutex_);
    pools_.clear();
    poolLuid_.clear();
    for (size_t i = 0; i < caps.size(); ++i) {
        MemoryPool p;
        p.deviceIndex = static_cast<int>(i);
        p.totalSize = caps[i].totalBytes;
        p.usedSize = caps[i].totalBytes > caps[i].freeBytes
                         ? caps[i].totalBytes - caps[i].freeBytes
                         : 0;
        p.peakUsedSize = p.usedSize;
        pools_[p.deviceIndex] = p;
        poolLuid_[p.deviceIndex] = caps[i].luid;
        // Seed the atomic admission ledger with the same live free capacity.
        reservationLedger_.SetCapacity(caps[i].luid, caps[i].freeBytes);
    }
    initialized_ = true;
    return true;
}

void VRAMAllocator::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    allocations_.clear();
    pools_.clear();
    poolLuid_.clear();
    initialized_ = false;
}

// ---------------------------------------------------------------------------
// Allocation (public; locks)
// ---------------------------------------------------------------------------
Allocation VRAMAllocator::Allocate(uint64_t size, AllocationType type,
                                   AllocationStrategy strategy,
                                   const std::string& tag) {
    std::lock_guard<std::mutex> lock(mutex_);
    const int dev = SelectDevice(size, strategy, type);
    if (dev < 0) {
        ++stats_.oomCount;
        if (onOOM_) onOOM_(size, -1);
        return Allocation();
    }
    Allocation a = TryAllocate(size, dev, type, tag);
    if (!a.IsValid()) {
        ++stats_.oomCount;
        if (onOOM_) onOOM_(size, dev);
        return a;
    }
    allocations_[a.id] = a;
    stats_.totalAllocated += size;
    UpdatePoolUsage(dev);
    if (onAllocated_) onAllocated_(a);
    return a;
}

Allocation VRAMAllocator::AllocateOnDevice(uint64_t size, int deviceIndex,
                                           AllocationType type,
                                           const std::string& tag) {
    std::lock_guard<std::mutex> lock(mutex_);
    Allocation a = TryAllocate(size, deviceIndex, type, tag);
    if (!a.IsValid()) {
        ++stats_.oomCount;
        if (onOOM_) onOOM_(size, deviceIndex);
        return a;
    }
    allocations_[a.id] = a;
    stats_.totalAllocated += size;
    UpdatePoolUsage(deviceIndex);
    if (onAllocated_) onAllocated_(a);
    return a;
}

void VRAMAllocator::Free(Allocation& allocation) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = allocations_.find(allocation.id);
    if (it != allocations_.end()) {
        const int dev = it->second.deviceIndex;
        const uint64_t sz = it->second.size;
        allocations_.erase(it);
        auto pit = pools_.find(dev);
        if (pit != pools_.end()) {
            pit->second.usedSize = sz > pit->second.usedSize
                                       ? 0
                                       : pit->second.usedSize - sz;
        }
        stats_.totalFreed += sz;
        UpdatePoolUsage(dev);
    }
    if (onFreed_) onFreed_(allocation);
    allocation = Allocation{};
}

void VRAMAllocator::FreeById(uint64_t allocationId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = allocations_.find(allocationId);
    if (it == allocations_.end()) return;
    Allocation a = it->second;
    const int dev = a.deviceIndex;
    const uint64_t sz = a.size;
    allocations_.erase(it);
    auto pit = pools_.find(dev);
    if (pit != pools_.end())
        pit->second.usedSize = sz > pit->second.usedSize ? 0 : pit->second.usedSize - sz;
    stats_.totalFreed += sz;
    UpdatePoolUsage(dev);
    if (onFreed_) onFreed_(a);
}

void VRAMAllocator::FreeAllOnDevice(int deviceIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint64_t> toRemove;
    for (const auto& kv : allocations_)
        if (kv.second.deviceIndex == deviceIndex) toRemove.push_back(kv.first);
    for (uint64_t id : toRemove) {
        Allocation tmp = allocations_[id];
        allocations_.erase(id);
        stats_.totalFreed += tmp.size;
        if (onFreed_) onFreed_(tmp);
    }
    UpdatePoolUsage(deviceIndex);
}

void VRAMAllocator::FreeAllOfType(AllocationType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint64_t> toRemove;
    for (const auto& kv : allocations_)
        if (kv.second.type == type) toRemove.push_back(kv.first);
    for (uint64_t id : toRemove) {
        Allocation tmp = allocations_[id];
        allocations_.erase(id);
        stats_.totalFreed += tmp.size;
        if (onFreed_) onFreed_(tmp);
    }
    for (const auto& kv : pools_) UpdatePoolUsage(kv.first);
}

// ---------------------------------------------------------------------------
// Migration / residency
// ---------------------------------------------------------------------------
bool VRAMAllocator::Migrate(Allocation& allocation, int targetDevice) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = allocations_.find(allocation.id);
    if (it == allocations_.end()) return false;
    if (!CanAllocate(it->second.size, targetDevice)) return false;
    const int oldDev = it->second.deviceIndex;
    it->second.deviceIndex = targetDevice;
    allocation.deviceIndex = targetDevice;
    ++stats_.migrationCount;
    UpdatePoolUsage(oldDev);
    UpdatePoolUsage(targetDevice);
    return true;
}

bool VRAMAllocator::EvictToHost(Allocation& allocation) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = allocations_.find(allocation.id);
    if (it == allocations_.end()) return false;
    it->second.resident = false;
    allocation.resident = false;
    ++stats_.evictionCount;
    return true;
}

bool VRAMAllocator::PromoteToDevice(Allocation& allocation, int deviceIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = allocations_.find(allocation.id);
    if (it == allocations_.end()) return false;
    if (!CanAllocate(it->second.size, deviceIndex)) return false;
    it->second.resident = true;
    it->second.deviceIndex = deviceIndex;
    allocation.resident = true;
    allocation.deviceIndex = deviceIndex;
    UpdatePoolUsage(deviceIndex);
    return true;
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------
uint64_t VRAMAllocator::GetFreeVRAM(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pools_.find(deviceIndex);
    return it == pools_.end() ? 0 : it->second.GetFreeSize();
}

uint64_t VRAMAllocator::GetUsedVRAM(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pools_.find(deviceIndex);
    return it == pools_.end() ? 0 : it->second.usedSize;
}

uint64_t VRAMAllocator::GetTotalVRAM() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t n = 0;
    for (const auto& kv : pools_) n += kv.second.totalSize;
    return n;
}

size_t VRAMAllocator::GetAllocationCount(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceIndex < 0) return allocations_.size();
    size_t c = 0;
    for (const auto& kv : allocations_)
        if (kv.second.deviceIndex == deviceIndex) ++c;
    return c;
}

MemoryPool VRAMAllocator::GetPoolInfo(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pools_.find(deviceIndex);
    return it == pools_.end() ? MemoryPool{} : it->second;
}

std::vector<MemoryPool> VRAMAllocator::GetAllPools() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MemoryPool> out;
    out.reserve(pools_.size());
    for (const auto& kv : pools_) out.push_back(kv.second);
    return out;
}

// ---------------------------------------------------------------------------
// Defragmentation (flat counter allocator: nothing to compact, but recompute)
// ---------------------------------------------------------------------------
bool VRAMAllocator::Defragment(int deviceIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    UpdatePoolUsage(deviceIndex);
    return true;
}

bool VRAMAllocator::CompactMemory() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& kv : pools_) UpdatePoolUsage(kv.first);
    return true;
}

// ---------------------------------------------------------------------------
// Strategy / callbacks / stats
// ---------------------------------------------------------------------------
void VRAMAllocator::SetDefaultStrategy(AllocationStrategy strategy) {
    std::lock_guard<std::mutex> lock(mutex_);
    defaultStrategy_ = strategy;
}

AllocationStrategy VRAMAllocator::GetDefaultStrategy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return defaultStrategy_;
}

void VRAMAllocator::SetAllocationCallback(AllocationCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    onAllocated_ = std::move(cb);
}

void VRAMAllocator::SetDeallocationCallback(DeallocationCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    onFreed_ = std::move(cb);
}

void VRAMAllocator::SetOOMCallback(OOMCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    onOOM_ = std::move(cb);
}

VRAMAllocator::Stats VRAMAllocator::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void VRAMAllocator::ResetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = Stats{};
}

// ---------------------------------------------------------------------------
// Internal helpers (caller holds mutex_)
// ---------------------------------------------------------------------------
bool VRAMAllocator::CanAllocate(uint64_t size, int deviceIndex) const {
    auto it = pools_.find(deviceIndex);
    if (it == pools_.end()) return false;
    return size <= it->second.GetFreeSize();
}

Allocation VRAMAllocator::TryAllocate(uint64_t size, int deviceIndex,
                                      AllocationType type,
                                      const std::string& tag) {
    if (!CanAllocate(size, deviceIndex)) return Allocation{};
    Allocation a;
    a.id = nextAllocationId_++;
    a.deviceIndex = deviceIndex;
    a.size = size;
    a.type = type;
    a.tag = tag;
    a.resident = true;
    MemoryPool& p = pools_[deviceIndex];
    p.usedSize += size;
    if (p.usedSize > p.peakUsedSize) p.peakUsedSize = p.usedSize;
    if (p.usedSize > stats_.peakUsage) stats_.peakUsage = p.usedSize;
    return a;
}

void VRAMAllocator::UpdatePoolUsage(int deviceIndex) {
    auto it = pools_.find(deviceIndex);
    if (it == pools_.end()) return;
    uint64_t used = 0;
    for (const auto& kv : allocations_)
        if (kv.second.deviceIndex == deviceIndex) used += kv.second.size;
    it->second.usedSize = used;
    if (used > it->second.peakUsedSize) it->second.peakUsedSize = used;
}

int VRAMAllocator::SelectDevice(uint64_t size, AllocationStrategy strategy,
                                AllocationType type) {
    switch (strategy) {
        case AllocationStrategy::FIRST_FIT:   return SelectDeviceFirstFit(size);
        case AllocationStrategy::BEST_FIT:    return SelectDeviceBestFit(size);
        case AllocationStrategy::ROUND_ROBIN: return SelectDeviceRoundRobin(size);
        case AllocationStrategy::ROLE_BASED:  return SelectDeviceRoleBased(size, type);
        case AllocationStrategy::PINNED:      return -1; // caller must use AllocateOnDevice
    }
    return -1;
}

int VRAMAllocator::SelectDeviceFirstFit(uint64_t size) {
    for (const auto& kv : pools_)
        if (kv.second.GetFreeSize() >= size) return kv.first;
    return -1;
}

int VRAMAllocator::SelectDeviceBestFit(uint64_t size) {
    int best = -1;
    uint64_t bestFree = std::numeric_limits<uint64_t>::max();
    for (const auto& kv : pools_) {
        const uint64_t f = kv.second.GetFreeSize();
        if (f >= size && f < bestFree) { bestFree = f; best = kv.first; }
    }
    return best;
}

int VRAMAllocator::SelectDeviceRoundRobin(uint64_t size) {
    if (pools_.empty()) return -1;
    const size_t n = pools_.size();
    for (size_t k = 0; k < n; ++k) {
        const int idx = static_cast<int>((roundRobinCursor_ + k) % n);
        auto it = pools_.find(idx);
        if (it != pools_.end() && it->second.GetFreeSize() >= size) {
            roundRobinCursor_ = static_cast<uint32_t>((idx + 1) % n);
            return idx;
        }
    }
    return -1;
}

int VRAMAllocator::SelectDeviceRoleBased(uint64_t size, AllocationType type) {
    (void)type;
    // Prefer the primary (lowest-index) device that fits.
    for (const auto& kv : pools_)
        if (kv.second.GetFreeSize() >= size) return kv.first;
    return -1;
}

// ============================================================================
// ScopedAllocation (RAII)
// ============================================================================
ScopedAllocation::ScopedAllocation(VRAMAllocator& allocator, uint64_t size,
                                   AllocationType type,
                                   AllocationStrategy strategy,
                                   const std::string& tag)
    : allocator_(&allocator) {
    allocation_ = allocator_->Allocate(size, type, strategy, tag);
    ownsAllocation_ = allocation_.IsValid();
}

ScopedAllocation::~ScopedAllocation() {
    if (ownsAllocation_ && allocator_) allocator_->Free(allocation_);
}

ScopedAllocation::ScopedAllocation(ScopedAllocation&& other) noexcept
    : allocator_(other.allocator_),
      allocation_(other.allocation_),
      ownsAllocation_(other.ownsAllocation_) {
    other.ownsAllocation_ = false;
}

ScopedAllocation& ScopedAllocation::operator=(ScopedAllocation&& other) noexcept {
    if (this != &other) {
        if (ownsAllocation_ && allocator_) allocator_->Free(allocation_);
        allocator_ = other.allocator_;
        allocation_ = other.allocation_;
        ownsAllocation_ = other.ownsAllocation_;
        other.ownsAllocation_ = false;
    }
    return *this;
}

Allocation ScopedAllocation::Release() {
    ownsAllocation_ = false;
    return allocation_;
}

// ============================================================================
// C API
// ============================================================================
extern "C" {

void* VRAMAllocator_Create() { return new VRAMAllocator(); }

void VRAMAllocator_Destroy(void* allocator) {
    delete static_cast<VRAMAllocator*>(allocator);
}

bool VRAMAllocator_Initialize(void* allocator) {
    if (!allocator) return false;
    return static_cast<VRAMAllocator*>(allocator)->Initialize();
}

uint64_t VRAMAllocator_Allocate(void* allocator, uint64_t size, int deviceIndex) {
    if (!allocator) return 0;
    Allocation a = static_cast<VRAMAllocator*>(allocator)->AllocateOnDevice(
        size, deviceIndex, AllocationType::TENSOR, "");
    return a.id;
}

void VRAMAllocator_Free(void* allocator, uint64_t allocationId) {
    if (!allocator) return;
    static_cast<VRAMAllocator*>(allocator)->FreeById(allocationId);
}

uint64_t VRAMAllocator_GetFreeVRAM(void* allocator, int deviceIndex) {
    if (!allocator) return 0;
    return static_cast<VRAMAllocator*>(allocator)->GetFreeVRAM(deviceIndex);
}

uint64_t VRAMAllocator_GetTotalVRAM(void* allocator) {
    if (!allocator) return 0;
    return static_cast<VRAMAllocator*>(allocator)->GetTotalVRAM();
}

} // extern "C"

} // namespace MultiGPU
} // namespace Deep2