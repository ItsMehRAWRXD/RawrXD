#pragma once
// ============================================================================
// VramStreamingController — 24 GiB hard-residency / unlimited-model streaming
// Enforced VRAM ceiling, host-backed spill, measured per-token streaming,
// bounded in-flight traffic, and lock/unlock/set controls.
// ============================================================================
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <functional>

namespace Deep2 {

// Forward declarations
class NVMeStream;
class ElasticResidencyManager;

enum class ResidencyLockState : uint8_t {
    Unlocked = 0,
    Locked   = 1
};

enum class SpillTier : uint8_t {
    None = 0,   // Evict to nowhere (drop)
    HostRAM,    // Evict to host RAM
    HostNVMe    // Evict to host NVMe / disk
};

struct VramStreamingStats {
    // VRAM
    uint64_t vramCeilingBytes = 0;
    uint64_t vramUsedBytes    = 0;
    uint64_t vramPeakBytes    = 0;

    // Host spill
    uint64_t hostRamUsedBytes  = 0;
    uint64_t hostRamPeakBytes  = 0;
    uint64_t hostNvmeUsedBytes = 0;

    // Per-token measured streaming
    uint64_t tokensMeasured      = 0;
    uint64_t tokenBytesMovedSum  = 0;
    uint64_t tokenBytesMovedMax  = 0;
    uint64_t tokenBytesLimitHits = 0;   // tokens that hit the per-token byte limit

    // In-flight traffic
    uint64_t inFlightBytes    = 0;
    uint64_t inFlightBytesMax = 0;
    uint64_t inFlightWaits    = 0;     // times we waited for in-flight budget

    // Lock / enforcement
    uint64_t lockEnforcedBlocks = 0;
    uint64_t ceilingEnforcedEvictions = 0;
    uint64_t spillEvictions = 0;

    // Request counters
    uint64_t prefetchRequests = 0;
    uint64_t prefetchApproved = 0;
    uint64_t prefetchDenied   = 0;
    uint64_t evictRequests    = 0;
    uint64_t evictApproved    = 0;
};

struct TensorResidencyInfo {
    std::string name;
    uint64_t    bytes     = 0;
    bool        resident  = false;   // currently in VRAM
    bool        spilled   = false;   // currently in host RAM / NVMe
    uint64_t    lastToken = 0;       // last token that touched this tensor
    int         priority  = 0;       // higher = harder to evict
};

class VramStreamingController {
public:
    // Default ceiling: 24 GiB
    static constexpr uint64_t kDefaultCeilingGiB = 24;
    static constexpr uint64_t kDefaultTokenBytesLimit = 512 * 1024 * 1024; // 512 MiB/token
    static constexpr uint64_t kDefaultMaxInFlightBytes = 2ull * 1024 * 1024 * 1024; // 2 GiB

    VramStreamingController();
    ~VramStreamingController();

    VramStreamingController(const VramStreamingController&) = delete;
    VramStreamingController& operator=(const VramStreamingController&) = delete;

    // =========================================================================
    // Controls: lock / unlock / set ceiling
    // =========================================================================
    void lockResidency();
    void unlockResidency();
    bool isLocked() const noexcept;

    // Set hard VRAM ceiling in GiB (e.g., 24 → 25,769,803,776 bytes)
    void setVramCeilingGiB(uint32_t gib);
    uint64_t vramCeilingBytes() const noexcept;

    // Enable host-backed spill (when VRAM is full, evict to host RAM instead of dropping)
    void setHostSpillEnabled(bool enable);
    bool isHostSpillEnabled() const noexcept;

    // Set spill tier (where evicted tensors go)
    void setSpillTier(SpillTier tier);
    SpillTier spillTier() const noexcept;

    // =========================================================================
    // Measured per-token streaming
    // =========================================================================
    void setTokenBytesLimit(uint64_t bytes);   // 0 = unlimited
    uint64_t tokenBytesLimit() const noexcept;

    void beginTokenMeasurement(uint64_t tokenIndex);
    void recordBytesMoved(uint64_t bytes);
    bool endTokenMeasurement(uint64_t& outBytesMoved); // returns false if limit hit

    // =========================================================================
    // Bounded in-flight traffic
    // =========================================================================
    void setMaxInFlightBytes(uint64_t bytes);  // 0 = unlimited
    uint64_t maxInFlightBytes() const noexcept;

    // Request bytes in-flight; blocks (or returns false) if over budget
    bool requestInFlightBytes(uint64_t bytes, uint32_t timeoutMs = 0);
    void releaseInFlightBytes(uint64_t bytes);

    // =========================================================================
    // Tensor residency orchestration
    // =========================================================================
    // Register a tensor with known byte size (idempotent)
    void registerTensor(const std::string& name, uint64_t bytes, int priority = 0);

    // Request that a tensor become resident in VRAM.
    // Returns true if approved (may trigger spill/eviction).
    // Returns false if locked, over ceiling+spill, or per-token limit.
    bool requestResident(const std::string& name);

    // Mark tensor as actually resident (called by transfer provider after copy completes)
    void markResident(const std::string& name);

    // Evict a tensor from VRAM (spill to host if enabled)
    bool evict(const std::string& name);

    // Force-evict enough tensors to free 'requiredBytes' from VRAM
    bool makeRoom(uint64_t requiredBytes);

    // Query
    bool isResident(const std::string& name) const;
    uint64_t tensorBytes(const std::string& name) const;
    uint64_t vramUsedBytes() const noexcept;
    uint64_t hostSpillBytes() const noexcept;
    VramStreamingStats stats() const;

    // Reset all tracking (but keep ceiling / config)
    void reset();

    // =========================================================================
    // Integration hooks
    // =========================================================================
    void attachNvmeStream(NVMeStream* stream);
    void attachElasticManager(ElasticResidencyManager* mgr);

    // Snapshot of all tensor states (for telemetry / debugging)
    std::vector<TensorResidencyInfo> snapshot() const;

private:
    mutable std::mutex mtx_;
    std::condition_variable inFlightCv_;

    // Config
    std::atomic<uint64_t> vramCeilingBytes_{kDefaultCeilingGiB * 1024ull * 1024ull * 1024ull};
    std::atomic<bool>     hostSpillEnabled_{true};
    std::atomic<SpillTier> spillTier_{SpillTier::HostRAM};
    std::atomic<uint64_t> tokenBytesLimit_{kDefaultTokenBytesLimit};
    std::atomic<uint64_t> maxInFlightBytes_{kDefaultMaxInFlightBytes};

    // State
    std::atomic<ResidencyLockState> lockState_{ResidencyLockState::Unlocked};
    uint64_t currentTokenIndex_ = 0;
    uint64_t currentTokenBytesMoved_ = 0;
    bool     currentTokenLimitHit_ = false;

    // Accounting
    uint64_t vramUsedBytes_   = 0;
    uint64_t vramPeakBytes_   = 0;
    uint64_t hostRamUsed_     = 0;
    uint64_t hostRamPeak_     = 0;
    uint64_t hostNvmeUsed_    = 0;
    uint64_t inFlightBytes_   = 0;
    uint64_t inFlightPeak_    = 0;

    // Tensor registry
    struct TensorRec {
        uint64_t bytes    = 0;
        bool     resident = false;
        bool     spilled  = false;
        uint64_t lastToken = 0;
        int      priority  = 0;
    };
    std::unordered_map<std::string, TensorRec> tensors_;

    // Stats
    VramStreamingStats stats_;

    // Integration
    NVMeStream* nvmeStream_ = nullptr;
    ElasticResidencyManager* elasticMgr_ = nullptr;

    // Internal helpers
    bool tryMakeRoomLocked(uint64_t requiredBytes);
    void updateVramPeakLocked();
    void updateHostPeakLocked();
    void updateInFlightPeakLocked();
};

} // namespace Deep2
