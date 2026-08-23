// ============================================================================
// VAL-051.7 — ResidencyLease
// Deterministic lease with generation-based stale detection.
// ============================================================================

#ifndef RESIDENCY_LEASE_HPP
#define RESIDENCY_LEASE_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <string>

namespace Deep2 {

// Forward declaration
class ResidencyManager;

// ============================================================================
// Lease State
// ============================================================================
enum class LeaseState : uint8_t {
    Invalid = 0,      // Default-constructed, never acquired
    Active = 1,       // Acquired, generation matches
    Released = 2,     // Explicitly released
    Stale = 3,        // Generation mismatch detected
    Evicted = 4       // Underlying tensor was evicted
};

// ============================================================================
// ResidencyLease
// Lightweight handle representing a borrow on a resident tensor.
// ============================================================================
class ResidencyLease {
public:
    // ── Construction ───────────────────────────────────────────────────
    ResidencyLease() = default;
    ~ResidencyLease() { Invalidate(); }

    // Non-copyable (unique ownership)
    ResidencyLease(const ResidencyLease&) = delete;
    ResidencyLease& operator=(const ResidencyLease&) = delete;

    // Movable (transfer ownership)
    ResidencyLease(ResidencyLease&& other) noexcept;
    ResidencyLease& operator=(ResidencyLease&& other) noexcept;

    // ── Acquisition ──────────────────────────────────────────────────
    // Acquire a lease for a tensor from the residency manager.
    // Returns true on success; lease is Active.
    bool Acquire(ResidencyManager& manager,
                 const std::string& tensorName,
                 size_t expectedBytes);

    // ── Validation ───────────────────────────────────────────────────
    // Check if lease is still valid (active + generation match).
    bool IsValid() const;

    // Check if lease is in Active state.
    bool IsActive() const { return state_ == LeaseState::Active; }

    // Get current lease state.
    LeaseState GetState() const { return state_; }

    // ── Access ───────────────────────────────────────────────────────
    // Get pointer to resident tensor data.
    // Returns nullptr if lease is not valid.
    void* GetData() const { return IsValid() ? data_ : nullptr; }

    // Get typed pointer.
    template<typename T>
    T* GetTypedData() const { return IsValid() ? static_cast<T*>(data_) : nullptr; }

    // Get tensor metadata.
    const std::string& GetTensorName() const { return tensorName_; }
    size_t GetMappedBytes() const { return mappedBytes_; }
    size_t GetRequestedBytes() const { return requestedBytes_; }
    uint64_t GetGeneration() const { return generation_; }
    uint64_t GetLeaseId() const { return leaseId_; }

    // ── Release ────────────────────────────────────────────────────────
    // Release the lease. Idempotent — safe to call multiple times.
    // Returns true if this call actually released an active lease.
    bool Release();

    // Force invalidate without releasing (emergency / teardown).
    void Invalidate();

    // ── Diagnostics ────────────────────────────────────────────────────
    const char* StateString() const;
    void Print() const;

private:
    // Lease identity
    uint64_t leaseId_ = 0;
    static inline uint64_t nextLeaseId_ = 1;

    // Tensor reference
    std::string tensorName_;
    void* data_ = nullptr;
    size_t mappedOffset_ = 0;      // Page-aligned mapped offset
    size_t mappedBytes_ = 0;       // Actual mapped bytes (≥ requested)
    size_t requestedBytes_ = 0;    // Bytes requested by caller

    // Generation for stale detection
    uint64_t generation_ = 0;

    // State
    LeaseState state_ = LeaseState::Invalid;

    // Back-pointer to manager (for release)
    ResidencyManager* manager_ = nullptr;

    // Internal helpers
    void Reset();
    void MoveFrom(ResidencyLease&& other) noexcept;
};

// ============================================================================
// ScopedResidencyLease — RAII wrapper
// ============================================================================
class ScopedResidencyLease {
public:
    explicit ScopedResidencyLease(ResidencyLease& lease) : lease_(lease) {}
    ~ScopedResidencyLease() { lease_.Release(); }

    // Non-copyable, non-movable
    ScopedResidencyLease(const ScopedResidencyLease&) = delete;
    ScopedResidencyLease& operator=(const ScopedResidencyLease&) = delete;
    ScopedResidencyLease(ScopedResidencyLease&&) = delete;
    ScopedResidencyLease& operator=(ScopedResidencyLease&&) = delete;

    ResidencyLease& GetLease() { return lease_; }
    const ResidencyLease& GetLease() const { return lease_; }

private:
    ResidencyLease& lease_;
};

} // namespace Deep2

#endif // RESIDENCY_LEASE_HPP
