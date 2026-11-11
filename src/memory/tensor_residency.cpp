/*===========================================================================
 * tensor_residency.cpp
 *
 * VAL-031.1 Local Sovereign Memory Fabric Implementation
 *
 * Unified tensor residency with L0-L5 cache hierarchy
 *===========================================================================*/

#include "tensor_residency.hpp"
#include <iostream>
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Memory {

// LocalRAMDomain implementation
LocalRAMDomain::LocalRAMDomain(uint32_t domainId, uint64_t capacity)
    : domainId_(domainId), capacity_(capacity), used_(0), nextAddress_(0) {
    // Allocate memory pool
    #ifdef _WIN32
    memoryPool_ = (uint8_t*)VirtualAlloc(nullptr, capacity, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    #else
    memoryPool_ = (uint8_t*)aligned_alloc(4096, capacity);
    #endif
}

LocalRAMDomain::~LocalRAMDomain() {
    if (memoryPool_) {
        #ifdef _WIN32
        VirtualFree(memoryPool_, 0, MEM_RELEASE);
        #else
        free(memoryPool_);
        #endif
    }
}

uint64_t LocalRAMDomain::GetAvailable() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex>&(mutex_));
    return capacity_ - used_;
}

bool LocalRAMDomain::Allocate(uint64_t tensorId, uint64_t size, uint64_t& outAddress) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (used_ + size > capacity_) {
        return false;
    }

    // Simple bump allocator - in production would use slab/buddy allocator
    outAddress = nextAddress_;
    nextAddress_ += size;

    // Align to 64 bytes
    if (nextAddress_ % 64 != 0) {
        nextAddress_ += 64 - (nextAddress_ % 64);
    }

    Allocation alloc;
    alloc.address = outAddress;
    alloc.size = size;
    alloc.state = ResidencyState::WARM;
    alloc.pinned = false;

    allocations_[tensorId] = alloc;
    used_ += size;

    return true;
}

bool LocalRAMDomain::Free(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(tensorId);
    if (it == allocations_.end()) {
        return false;
    }

    used_ -= it->second.size;
    allocations_.erase(it);

    // Note: In production, would return to free list, not actually deallocate
    return true;
}

bool LocalRAMDomain::Read(uint64_t address, void* data, uint64_t size) {
    if (!memoryPool_ || address + size > capacity_) {
        return false;
    }

    std::memcpy(data, memoryPool_ + address, size);
    return true;
}

bool LocalRAMDomain::Write(uint64_t address, const void* data, uint64_t size) {
    if (!memoryPool_ || address + size > capacity_) {
        return false;
    }

    std::memcpy(memoryPool_ + address, data, size);
    return true;
}

bool LocalRAMDomain::Evict(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(tensorId);
    if (it == allocations_.end()) {
        return false;
    }

    if (it->second.pinned) {
        return false;  // Cannot evict pinned tensor
    }

    it->second.state = ResidencyState::COLD;
    return true;
}

bool LocalRAMDomain::Promote(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(tensorId);
    if (it == allocations_.end()) {
        return false;
    }

    it->second.state = ResidencyState::HOT;
    return true;
}

bool LocalRAMDomain::Pin(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(tensorId);
    if (it == allocations_.end()) {
        return false;
    }

    it->second.pinned = true;
    it->second.state = ResidencyState::PINNED;
    return true;
}

bool LocalRAMDomain::Unpin(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(tensorId);
    if (it == allocations_.end()) {
        return false;
    }

    it->second.pinned = false;
    it->second.state = ResidencyState::HOT;
    return true;
}

// ResidencyManager implementation
ResidencyManager::ResidencyManager() = default;
ResidencyManager::~ResidencyManager() = default;

bool ResidencyManager::Initialize() {
    // Create default local RAM domain (L3)
    // In production, would detect NUMA topology and create multiple domains
    auto ramDomain = std::make_shared<LocalRAMDomain>(0, 16ULL * 1024 * 1024 * 1024);  // 16GB
    RegisterDomain(ramDomain);

    return true;
}

void ResidencyManager::RegisterDomain(std::shared_ptr<MemoryDomain> domain) {
    std::lock_guard<std::mutex> lock(tableMutex_);
    domains_[domain->GetDomainId()] = domain;
}

ResidencyLookup ResidencyManager::Resolve(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(tableMutex_);

    stats_.totalLookups++;

    auto it = residencyTable_.find(tensorId);
    if (it == residencyTable_.end()) {
        stats_.misses++;
        return ResidencyLookup();  // Not found
    }

    ResidencyLookup result;
    result.found = true;
    result.residency = it->second;

    // Update last access time
    it->second.lastAccess = std::chrono::steady_clock::now().time_since_epoch().count();

    // Check if local
    auto domainIt = domains_.find(it->second.domainId);
    if (domainIt != domains_.end()) {
        result.local = (domainIt->second->GetType() == DomainType::SYSTEM_RAM);
        result.latencyUs = domainIt->second->GetLatencyNs() / 1000;
    }

    if (result.local) {
        stats_.localHits++;
    } else {
        stats_.remoteHits++;
    }

    return result;
}

bool ResidencyManager::EnsureResident(uint64_t tensorId, DomainType minLevel) {
    auto lookup = Resolve(tensorId);

    if (!lookup.found) {
        return false;
    }

    // Check if current level meets requirement
    if (static_cast<uint8_t>(lookup.residency.domainType) <= static_cast<uint8_t>(minLevel)) {
        return true;  // Already at required level or better
    }

    // Need to migrate to better domain
    auto targetDomain = FindBestDomain(minLevel);
    if (!targetDomain) {
        return false;
    }

    return Migrate(tensorId, targetDomain->GetDomainId());
}

bool ResidencyManager::Migrate(uint64_t tensorId, uint32_t targetDomainId) {
    std::lock_guard<std::mutex> lock(tableMutex_);

    auto it = residencyTable_.find(tensorId);
    if (it == residencyTable_.end()) {
        return false;
    }

    auto sourceIt = domains_.find(it->second.domainId);
    auto targetIt = domains_.find(targetDomainId);

    if (sourceIt == domains_.end() || targetIt == domains_.end()) {
        return false;
    }

    if (PerformMigration(tensorId, sourceIt->second, targetIt->second)) {
        it->second.domainId = targetDomainId;
        it->second.domainType = targetIt->second->GetType();
        stats_.migrations++;
        return true;
    }

    return false;
}

size_t ResidencyManager::EvictLRU(uint64_t bytesToFree) {
    std::lock_guard<std::mutex> lock(tableMutex_);

    // Collect all non-pinned tensors with their last access time
    std::vector<std::pair<uint64_t, uint64_t>> candidates;  // tensorId, lastAccess

    for (const auto& [tensorId, residency] : residencyTable_) {
        if (residency.state != ResidencyState::PINNED) {
            candidates.emplace_back(tensorId, residency.lastAccess.load());
        }
    }

    // Sort by last access (oldest first)
    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });

    uint64_t freed = 0;
    size_t evicted = 0;

    for (const auto& [tensorId, _] : candidates) {
        if (freed >= bytesToFree) break;

        auto it = residencyTable_.find(tensorId);
        if (it != residencyTable_.end()) {
            auto domainIt = domains_.find(it->second.domainId);
            if (domainIt != domains_.end()) {
                if (domainIt->second->Evict(tensorId)) {
                    it->second.state = ResidencyState::COLD;
                    freed += it->second.size;
                    evicted++;
                    stats_.evictions++;
                }
            }
        }
    }

    return evicted;
}

bool ResidencyManager::Pin(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(tableMutex_);

    auto it = residencyTable_.find(tensorId);
    if (it == residencyTable_.end()) {
        return false;
    }

    auto domainIt = domains_.find(it->second.domainId);
    if (domainIt == domains_.end()) {
        return false;
    }

    if (domainIt->second->Pin(tensorId)) {
        it->second.state = ResidencyState::PINNED;
        return true;
    }

    return false;
}

bool ResidencyManager::Unpin(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(tableMutex_);

    auto it = residencyTable_.find(tensorId);
    if (it == residencyTable_.end()) {
        return false;
    }

    auto domainIt = domains_.find(it->second.domainId);
    if (domainIt == domains_.end()) {
        return false;
    }

    if (domainIt->second->Unpin(tensorId)) {
        it->second.state = ResidencyState::HOT;
        return true;
    }

    return false;
}

ResidencyManager::Stats ResidencyManager::GetStats() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex>&(tableMutex_));
    return stats_;
}

std::shared_ptr<MemoryDomain> ResidencyManager::FindBestDomain(DomainType minLevel) {
    // Find the fastest domain that meets the minimum level requirement
    std::shared_ptr<MemoryDomain> bestDomain = nullptr;
    uint64_t bestLatency = UINT64_MAX;

    for (const auto& [id, domain] : domains_) {
        if (static_cast<uint8_t>(domain->GetType()) <= static_cast<uint8_t>(minLevel)) {
            if (domain->GetLatencyNs() < bestLatency && domain->GetAvailable() > 0) {
                bestLatency = domain->GetLatencyNs();
                bestDomain = domain;
            }
        }
    }

    return bestDomain;
}

bool ResidencyManager::PerformMigration(uint64_t tensorId,
                                        std::shared_ptr<MemoryDomain> source,
                                        std::shared_ptr<MemoryDomain> target) {
    // Get tensor info from residency table
    auto it = residencyTable_.find(tensorId);
    if (it == residencyTable_.end()) {
        return false;
    }

    uint64_t size = it->second.size;

    // Allocate in target
    uint64_t newAddress;
    if (!target->Allocate(tensorId, size, newAddress)) {
        return false;
    }

    // Read from source
    std::vector<uint8_t> buffer(size);
    if (!source->Read(it->second.address, buffer.data(), size)) {
        target->Free(tensorId);
        return false;
    }

    // Write to target
    if (!target->Write(newAddress, buffer.data(), size)) {
        target->Free(tensorId);
        return false;
    }

    // Free from source
    source->Free(tensorId);

    // Update residency
    it->second.address = newAddress;
    it->second.domainId = target->GetDomainId();
    it->second.domainType = target->GetType();
    it->second.state = ResidencyState::WARM;

    return true;
}

// C API exports
extern "C" {

__declspec(dllexport) void* RawrXD_ResidencyManager_Create() {
    return new RawrXD::Memory::ResidencyManager();
}

__declspec(dllexport) void RawrXD_ResidencyManager_Destroy(void* handle) {
    delete static_cast<RawrXD::Memory::ResidencyManager*>(handle);
}

__declspec(dllexport) int RawrXD_ResidencyManager_Initialize(void* handle) {
    auto* mgr = static_cast<RawrXD::Memory::ResidencyManager*>(handle);
    return mgr->Initialize() ? 0 : -1;
}

__declspec(dllexport) int RawrXD_ResidencyManager_Resolve(void* handle, uint64_t tensorId,
                                                           uint64_t* outAddress, uint32_t* outDomain) {
    auto* mgr = static_cast<RawrXD::Memory::ResidencyManager*>(handle);
    auto result = mgr->Resolve(tensorId);

    if (!result.found) {
        return -1;
    }

    if (outAddress) *outAddress = result.residency.address;
    if (outDomain) *outDomain = result.residency.domainId;

    return 0;
}

__declspec(dllexport) int RawrXD_ResidencyManager_Migrate(void* handle, uint64_t tensorId, uint32_t targetDomain) {
    auto* mgr = static_cast<RawrXD::Memory::ResidencyManager*>(handle);
    return mgr->Migrate(tensorId, targetDomain) ? 0 : -1;
}

} // extern "C"

} // namespace Memory
} // namespace RawrXD
