#pragma once
#include "NEVMP.hpp"
#include <atomic>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>

// =============================================================================
// TensorPatchManager - Lock-free patch registry for Sovereign Substrate
// Manages .nevmp patch lifecycle: validation → application → rollback
// =============================================================================

namespace RawrXD {
namespace Sovereign {

// Forward declarations
class HotPatcher;
class SessionStore;

// =============================================================================
// PatchSlot - Atomic patch entry in the registry
// =============================================================================
struct alignas(64) PatchSlot {
    std::atomic<uint64_t> epoch_id{0};           // Patch epoch for versioning
    std::atomic<uint64_t> target_hash{0};      // Tensor identifier hash
    std::atomic<const NEVMP_Patch*> patch{nullptr}; // Pointer to patch data
    std::atomic<bool> active{false};             // Is this slot occupied?
    
    // Cache-line padding to prevent false sharing
    char padding[64 - sizeof(epoch_id) - sizeof(target_hash) 
                    - sizeof(patch) - sizeof(active)];
};

static_assert(sizeof(PatchSlot) == 64, "PatchSlot must be cache-line aligned");

// =============================================================================
// ResolvedPatch - Result of patch lookup
// =============================================================================
struct ResolvedPatch {
    const double* delta_payload;     // Pointer to delta vectors
    uint64_t      vector_count;      // Number of vectors
    uint64_t      epoch;             // Patch epoch
    uint64_t      target_addr;       // Memory aperture offset
    bool          valid;             // Is this patch valid?
    
    ResolvedPatch() 
        : delta_payload(nullptr)
        , vector_count(0)
        , epoch(0)
        , target_addr(0)
        , valid(false) 
    {}
};

// =============================================================================
// PatchTelemetry - Event logging for patch operations
// =============================================================================
struct PatchTelemetry {
    uint64_t tensor_hash;
    uint64_t epoch_version;
    int32_t  status_code;    // NEVMP_Status
    uint32_t payload_bytes;
    uint64_t timestamp;
    
    PatchTelemetry()
        : tensor_hash(0)
        , epoch_version(0)
        , status_code(0)
        , payload_bytes(0)
        , timestamp(0)
    {}
};

using TelemetryCallback = void(*)(const PatchTelemetry&);

// =============================================================================
// TensorPatchManager - Core patch management
// =============================================================================
class TensorPatchManager {
public:
    static constexpr uint64_t NEVMP_MAGIC = 0x4E564D50;
    static constexpr size_t   TABLE_CAPACITY = 1024;  // Power of 2 for fast mask
    static constexpr uint64_t FIB_HASH_MULTIPLIER = 0x9E3779B97F4A7C15ULL; // Golden ratio
    
    TensorPatchManager();
    ~TensorPatchManager();
    
    // Disable copy/move
    TensorPatchManager(const TensorPatchManager&) = delete;
    TensorPatchManager& operator=(const TensorPatchManager&) = delete;
    
    // -------------------------------------------------------------------------
    // Core API
    // -------------------------------------------------------------------------
    
    // Initialize the patch manager with optional telemetry callback
    bool Initialize(TelemetryCallback callback = nullptr);
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Register a new .nevmp patch (thread-safe, lock-free)
    // Returns: NEVMP_Status::OK on success, error code on failure
    NEVMP_Status RegisterPatch(const void* nevmp_data, size_t buffer_size);
    
    // Resolve patch for a given tensor hash (hot path, sub-nanosecond)
    // Returns: true if patch found and valid
    [[nodiscard]] bool Resolve(uint64_t tensor_hash, ResolvedPatch& out_patch) const noexcept;
    
    // Rollback to previous epoch (atomic)
    bool Rollback(uint64_t target_epoch);
    
    // Get current epoch
    uint64_t GetCurrentEpoch() const { return current_epoch_.load(std::memory_order_relaxed); }
    
    // -------------------------------------------------------------------------
    // Titan Engine Integration
    // -------------------------------------------------------------------------
    
    // Apply patch directly to Titan aperture (non-temporal streaming)
    // This is the critical path for inference-time patching
    NEVMP_Status ApplyToAperture(uint64_t tensor_hash, void* aperture_ptr, size_t aperture_size);
    
    // Validate patch without applying (for pre-flight checks)
    NEVMP_Status Validate(const void* nevmp_data, size_t buffer_size) const;
    
    // -------------------------------------------------------------------------
    // Statistics & Monitoring
    // -------------------------------------------------------------------------
    
    size_t GetActivePatchCount() const;
    size_t GetTotalPatchCount() const { return total_patches_.load(std::memory_order_relaxed); }
    
private:
    // Hash table for tensor_hash → PatchSlot lookup
    alignas(64) PatchSlot table_[TABLE_CAPACITY];
    
    // Epoch tracking for rollback
    std::atomic<uint64_t> current_epoch_{0};
    std::atomic<size_t> active_patches_{0};
    std::atomic<size_t> total_patches_{0};
    
    // Telemetry
    TelemetryCallback telemetry_cb_{nullptr};
    
    // Session store for checkpointing
    std::unique_ptr<SessionStore> session_store_;
    
    // -------------------------------------------------------------------------
    // Internal Methods
    // -------------------------------------------------------------------------
    
    // Fast Fibonacci hash to table index
    [[nodiscard]] static size_t HashToIndex(uint64_t hash) noexcept {
        return static_cast<size_t>((hash * FIB_HASH_MULTIPLIER) >> 54) & (TABLE_CAPACITY - 1);
    }
    
    // Find or claim slot for tensor_hash
    PatchSlot* FindOrClaimSlot(uint64_t tensor_hash);
    
    // Dispatch telemetry event
    void DispatchTelemetry(uint64_t hash, uint64_t epoch, int32_t status, uint32_t bytes);
    
    // External MASM functions
    extern "C" {
        int32_t NEVMP_ValidateHeader(const void* header);
        int32_t NEVMP_LoadAndApply(const void* header, void* target, size_t size);
        uint64_t NEVMP_CalculateChecksum(const void* payload, size_t size);
        int32_t NEVMP_Rollback(const void* checkpoint, void* target, size_t size);
    }
};

// =============================================================================
// ScopedPatch - RAII wrapper for automatic patch lifecycle
// =============================================================================
class ScopedPatch {
public:
    ScopedPatch(TensorPatchManager& manager, uint64_t tensor_hash);
    ~ScopedPatch();
    
    // Disable copy/move
    ScopedPatch(const ScopedPatch&) = delete;
    ScopedPatch& operator=(const ScopedPatch&) = delete;
    
    bool IsActive() const { return active_; }
    const ResolvedPatch& GetPatch() const { return patch_; }
    
private:
    TensorPatchManager& manager_;
    uint64_t tensor_hash_;
    ResolvedPatch patch_;
    bool active_;
};

} // namespace Sovereign
} // namespace RawrXD
