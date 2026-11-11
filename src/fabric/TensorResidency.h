#pragma once

#include <cstdint>
#include <atomic>
#include <unordered_map>
#include <shared_mutex>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Residency States - CPU Cache-like Model
// ============================================================================
enum class ResidencyState : uint32_t {
    INVALID = 0,        // No data present
    NVME_COLD = 1,      // On disk only
    PREFETCHING = 2,    // Async load in progress
    RAM_WARM = 3,       // In RAM but not recently used
    RAM_HOT = 4,        // Recently accessed, keep resident
    COMPUTE_LOCKED = 5, // Currently in use by kernel (no eviction)
    EVICTING = 6        // Being written to disk
};

// ============================================================================
// Residency Entry - Per-Tensor Metadata
// ============================================================================
struct alignas(64) ResidencyEntry {
    uint64_t tensorId;              // Hash of tensor name
    uint64_t offset;                // Byte offset in local memory
    uint32_t size;                  // Tensor size in bytes
    uint32_t nodeId;                // Owning node (0 = local)
    ResidencyState state;           // Current residency state
    uint32_t version;               // Monotonic version counter
    uint64_t lastAccess;            // Timestamp (μs)
    uint32_t accessCount;           // For LRU eviction
    uint32_t pad;                   // Padding to 64 bytes
    
    ResidencyEntry() 
        : tensorId(0), offset(0), size(0), nodeId(0)
        , state(ResidencyState::INVALID), version(0)
        , lastAccess(0), accessCount(0), pad(0) {}
};

// ============================================================================
// Tensor Lease - Versioned Access Token
// ============================================================================
struct alignas(32) TensorLease {
    uint64_t tensorId;
    uint32_t version;
    uint64_t expiryUs;              // Lease expiration timestamp
    uint32_t ownerNode;
    uint32_t pad;
    
    bool IsValid(uint64_t nowUs) const {
        return version != 0 && nowUs < expiryUs;
    }
};

// ============================================================================
// Residency Table - Thread-Safe Tensor Registry
// ============================================================================
class ResidencyTable {
public:
    ResidencyTable();
    ~ResidencyTable();
    
    // Registration
    bool RegisterTensor(uint64_t tensorId, const ResidencyEntry& entry);
    bool UnregisterTensor(uint64_t tensorId);
    
    // Lookup
    bool Lookup(uint64_t tensorId, ResidencyEntry& out);
    bool IsLocal(uint64_t tensorId);
    bool IsResident(uint64_t tensorId);  // RAM_HOT or RAM_WARM
    
    // State Management
    bool UpdateState(uint64_t tensorId, ResidencyState newState);
    bool UpdateVersion(uint64_t tensorId, uint32_t newVersion);
    bool UpdateAccess(uint64_t tensorId, uint64_t timestamp);
    
    // Lease Management
    bool AcquireLease(uint64_t tensorId, uint32_t durationMs, TensorLease& out);
    bool ReleaseLease(const TensorLease& lease);
    bool ValidateLease(const TensorLease& lease);
    
    // Eviction Support
    bool TryLockForCompute(uint64_t tensorId);  // Returns false if EVICTING
    bool UnlockFromCompute(uint64_t tensorId);
    
    // Statistics
    size_t GetEntryCount() const { return table_.size(); }
    size_t GetResidentCount() const;
    size_t GetLockedCount() const;
    
private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, ResidencyEntry> table_;
    std::unordered_map<uint64_t, TensorLease> activeLeases_;
    
    uint64_t GenerateVersion();
    std::atomic<uint32_t> versionCounter_{1};
};

} // namespace Fabric
} // namespace RawrXD
