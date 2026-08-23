// ============================================================================
// VAL-051.7 — ResidencyManager
// Centralized bounded-window tensor residency with LRU eviction.
// ============================================================================

#ifndef RESIDENCY_MANAGER_HPP
#define RESIDENCY_MANAGER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>

namespace Deep2 {

// Forward declarations
class ResidencyLease;

// ============================================================================
// Residency Configuration
// ============================================================================
struct ResidencyConfig {
    // Maximum resident bytes at any time (excluding alignment overhead)
    size_t maxResidentBytes = 512ULL * 1024 * 1024;  // 512 MB default

    // Page alignment (platform-specific, usually 4096 or 65536)
    size_t pageAlignment = 4096;

    // Mapping granularity — minimum bytes to map at once
    size_t mapGranularity = 65536;

    // Policy for tensors larger than maxResidentBytes
    enum class OversizePolicy {
        Fail = 0,           // Reject oversize tensors
        DedicatedWindow = 1 // Map in dedicated oversized window
    };
    OversizePolicy oversizePolicy = OversizePolicy::DedicatedWindow;

    // Whether to track per-tensor statistics
    bool trackPerTensorStats = true;

    // Whether to validate source bytes on every remap
    bool validateOnRemap = true;
};

// ============================================================================
// Tensor Residency State
// ============================================================================
enum class TensorResidencyState : uint8_t {
    Unmapped = 0,
    Resident = 1,
    InUse = 2,
    Evictable = 3,
    Evicted = 4
};

// ============================================================================
// Resident Tensor Entry
// ============================================================================
struct ResidentTensor {
    std::string name;
    void* data = nullptr;           // Pointer to resident bytes
    size_t tensorOffset = 0;        // Offset within GGUF file
    size_t tensorBytes = 0;         // Actual tensor byte size
    size_t mappedBytes = 0;         // Mapped bytes (aligned)
    size_t mappedOffset = 0;        // Page-aligned mapped offset
    uint64_t generation = 0;        // Incremented on every eviction/remap
    uint64_t lastUseSequence = 0;   // For LRU
    size_t leaseCount = 0;          // Active leases
    TensorResidencyState state = TensorResidencyState::Unmapped;

    // Source validation
    std::vector<uint8_t> sourceChecksum;  // Optional: SHA-256 or CRC
};

// ============================================================================
// ResidencyManager
// Centralized owner of all tensor mapping/remapping/eviction.
// ============================================================================
class ResidencyManager {
public:
    // ── Lifecycle ────────────────────────────────────────────────────
    ResidencyManager() = default;
    ~ResidencyManager();

    // Non-copyable, non-movable
    ResidencyManager(const ResidencyManager&) = delete;
    ResidencyManager& operator=(const ResidencyManager&) = delete;

    // Initialize with configuration
    bool Initialize(const ResidencyConfig& config);

    // Shutdown: release all mappings, assert clean state
    void Shutdown();

    // Reset for new sequence (keeps config)
    void Reset();

    // ── Tensor Registration ──────────────────────────────────────────
    // Register a tensor's source metadata (from GGUF loader)
    bool RegisterTensor(const std::string& name,
                        size_t fileOffset,
                        size_t tensorBytes,
                        const void* sourceData);

    // ── Acquisition ──────────────────────────────────────────────────
    // Acquire a lease on a tensor. May trigger eviction/remap.
    // Returns true on success; caller receives data pointer + generation.
    bool AcquireTensor(const std::string& name,
                       void*& outData,
                       size_t& outBytes,
                       uint64_t& outGeneration);

    // ── Release ──────────────────────────────────────────────────────
    // Release one lease on a tensor.
    bool ReleaseTensor(const std::string& name);

    // ── Validation ───────────────────────────────────────────────────
    // Validate that a pointer + generation is still valid.
    bool ValidateLease(const std::string& name,
                       uint64_t generation) const;

    // ── Eviction ─────────────────────────────────────────────────────
    // Force eviction of a specific tensor (if evictable).
    bool EvictTensor(const std::string& name);

    // Evict oldest eligible tensor(s) to free at least needBytes.
    bool EvictToMakeRoom(size_t needBytes);

    // ── Queries ──────────────────────────────────────────────────────
    size_t GetCurrentResidentBytes() const { return currentResidentBytes_; }
    size_t GetPeakResidentBytes() const { return peakResidentBytes_; }
    size_t GetMaxResidentBytes() const { return config_.maxResidentBytes; }
    uint64_t GetTotalAcquires() const { return totalAcquires_; }
    uint64_t GetTotalReleases() const { return totalReleases_; }
    uint64_t GetTotalEvictions() const { return totalEvictions_; }
    uint64_t GetTotalRemaps() const { return totalRemaps_; }
    size_t GetActiveLeaseCount() const;
    TensorResidencyState GetTensorState(const std::string& name) const;

    // ── Diagnostics ──────────────────────────────────────────────────
    void PrintStats() const;
    void DumpResidentTensors() const;

    // ── Counter Integration ──────────────────────────────────────────
    void SetCounterCallbacks(
        std::function<void(size_t)> onAcquire,
        std::function<void(size_t)> onRelease,
        std::function<void(size_t)> onMap,
        std::function<void(size_t)> onUnmap,
        std::function<void(size_t)> onEvict,
        std::function<void()> onStaleLease,
        std::function<void()> onResidencyError);

private:
    ResidencyConfig config_;
    bool initialized_ = false;

    // Resident tensor registry
    std::map<std::string, ResidentTensor> residents_;

    // Source tensor registry (metadata from GGUF)
    struct SourceTensor {
        size_t fileOffset = 0;
        size_t tensorBytes = 0;
        const void* sourceData = nullptr;
    };
    std::map<std::string, SourceTensor> sources_;

    // Accounting
    size_t currentResidentBytes_ = 0;
    size_t peakResidentBytes_ = 0;
    uint64_t totalAcquires_ = 0;
    uint64_t totalReleases_ = 0;
    uint64_t totalEvictions_ = 0;
    uint64_t totalRemaps_ = 0;
    uint64_t useSequence_ = 0;

    // Thread safety
    mutable std::mutex mutex_;

    // Counter callbacks (optional, for ResidencyCounters integration)
    std::function<void(size_t)> cbOnAcquire_;
    std::function<void(size_t)> cbOnRelease_;
    std::function<void(size_t)> cbOnMap_;
    std::function<void(size_t)> cbOnUnmap_;
    std::function<void(size_t)> cbOnEvict_;
    std::function<void()> cbOnStaleLease_;
    std::function<void()> cbOnResidencyError_;

    // Internal helpers
    bool MapTensor(const std::string& name, ResidentTensor& entry);
    bool UnmapTensor(const std::string& name, ResidentTensor& entry);
    bool RemapTensor(const std::string& name, ResidentTensor& entry);
    size_t AlignedSize(size_t bytes) const;
    size_t AlignedOffset(size_t offset) const;
    void UpdatePeakBytes();
    void InvokeCounterCallbacks();
};

} // namespace Deep2

#endif // RESIDENCY_MANAGER_HPP
