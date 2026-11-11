#include "TensorResidency.h"
#include <Windows.h>

namespace RawrXD {
namespace Fabric {

ResidencyTable::ResidencyTable() = default;
ResidencyTable::~ResidencyTable() = default;

bool ResidencyTable::RegisterTensor(uint64_t tensorId, const ResidencyEntry& entry) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    if (table_.find(tensorId) != table_.end()) {
        return false;  // Already registered
    }
    
    table_[tensorId] = entry;
    return true;
}

bool ResidencyTable::UnregisterTensor(uint64_t tensorId) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    // Cannot unregister if compute-locked
    if (it->second.state == ResidencyState::COMPUTE_LOCKED) {
        return false;
    }
    
    table_.erase(it);
    return true;
}

bool ResidencyTable::Lookup(uint64_t tensorId, ResidencyEntry& out) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    out = it->second;
    return true;
}

bool ResidencyTable::IsLocal(uint64_t tensorId) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    return it->second.nodeId == 0;  // Node 0 = local
}

bool ResidencyTable::IsResident(uint64_t tensorId) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    auto state = it->second.state;
    return state == ResidencyState::RAM_HOT || 
           state == ResidencyState::RAM_WARM ||
           state == ResidencyState::COMPUTE_LOCKED;
}

bool ResidencyTable::UpdateState(uint64_t tensorId, ResidencyState newState) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    // State machine validation
    auto current = it->second.state;
    
    // Cannot transition from COMPUTE_LOCKED except to EVICTING
    if (current == ResidencyState::COMPUTE_LOCKED && newState != ResidencyState::EVICTING) {
        return false;
    }
    
    // Cannot transition to COMPUTE_LOCKED from EVICTING
    if (newState == ResidencyState::COMPUTE_LOCKED && current == ResidencyState::EVICTING) {
        return false;
    }
    
    it->second.state = newState;
    it->second.version = GenerateVersion();
    
    return true;
}

bool ResidencyTable::UpdateVersion(uint64_t tensorId, uint32_t newVersion) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    it->second.version = newVersion;
    return true;
}

bool ResidencyTable::UpdateAccess(uint64_t tensorId, uint64_t timestamp) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    it->second.lastAccess = timestamp;
    it->second.accessCount++;
    
    // Promote to HOT if accessed frequently
    if (it->second.accessCount > 10 && it->second.state == ResidencyState::RAM_WARM) {
        it->second.state = ResidencyState::RAM_HOT;
    }
    
    return true;
}

bool ResidencyTable::AcquireLease(uint64_t tensorId, uint32_t durationMs, TensorLease& out) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    // Check if already leased
    auto leaseIt = activeLeases_.find(tensorId);
    if (leaseIt != activeLeases_.end()) {
        uint64_t now = GetTickCount64() * 1000;  // Convert to μs
        if (leaseIt->second.IsValid(now)) {
            return false;  // Active lease exists
        }
    }
    
    // Create new lease
    TensorLease lease;
    lease.tensorId = tensorId;
    lease.version = it->second.version;
    lease.expiryUs = (GetTickCount64() * 1000) + (durationMs * 1000);
    lease.ownerNode = it->second.nodeId;
    
    activeLeases_[tensorId] = lease;
    out = lease;
    
    return true;
}

bool ResidencyTable::ReleaseLease(const TensorLease& lease) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = activeLeases_.find(lease.tensorId);
    if (it == activeLeases_.end()) {
        return false;
    }
    
    // Verify lease matches
    if (it->second.version != lease.version) {
        return false;
    }
    
    activeLeases_.erase(it);
    return true;
}

bool ResidencyTable::ValidateLease(const TensorLease& lease) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = activeLeases_.find(lease.tensorId);
    if (it == activeLeases_.end()) {
        return false;
    }
    
    uint64_t now = GetTickCount64() * 1000;
    return it->second.IsValid(now) && it->second.version == lease.version;
}

bool ResidencyTable::TryLockForCompute(uint64_t tensorId) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    // Cannot lock if evicting
    if (it->second.state == ResidencyState::EVICTING) {
        return false;
    }
    
    it->second.state = ResidencyState::COMPUTE_LOCKED;
    return true;
}

bool ResidencyTable::UnlockFromCompute(uint64_t tensorId) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = table_.find(tensorId);
    if (it == table_.end()) {
        return false;
    }
    
    if (it->second.state != ResidencyState::COMPUTE_LOCKED) {
        return false;
    }
    
    it->second.state = ResidencyState::RAM_HOT;
    return true;
}

size_t ResidencyTable::GetResidentCount() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    size_t count = 0;
    for (const auto& [id, entry] : table_) {
        if (entry.state == ResidencyState::RAM_HOT || 
            entry.state == ResidencyState::RAM_WARM ||
            entry.state == ResidencyState::COMPUTE_LOCKED) {
            count++;
        }
    }
    return count;
}

size_t ResidencyTable::GetLockedCount() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    size_t count = 0;
    for (const auto& [id, entry] : table_) {
        if (entry.state == ResidencyState::COMPUTE_LOCKED) {
            count++;
        }
    }
    return count;
}

uint64_t ResidencyTable::GenerateVersion() {
    return versionCounter_.fetch_add(1, std::memory_order_relaxed);
}

} // namespace Fabric
} // namespace RawrXD
