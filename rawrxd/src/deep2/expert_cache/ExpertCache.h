#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace rawrxd::deep2 {

struct ExpertKey {
    uint32_t layer = 0;
    uint32_t expert = 0;
    bool operator==(const ExpertKey& o) const noexcept { return layer == o.layer && expert == o.expert; }
};

struct ExpertKeyHash {
    size_t operator()(const ExpertKey& k) const noexcept {
        return (static_cast<size_t>(k.layer) << 32) ^ static_cast<size_t>(k.expert);
    }
};

struct ExpertLocation {
    const void* hostPtr = nullptr;     // backing store in RAM / mapped file window
    size_t bytes = 0;
    uint64_t fileOffset = 0;           // optional, for caller-owned file-backed storage
};

struct ExpertCacheStats {
    uint64_t requests = 0;
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t prefetchRequests = 0;
    uint64_t prefetchHits = 0;
    uint64_t evictions = 0;
    uint64_t bytesUploaded = 0;
    uint64_t uploadFailures = 0;
    uint64_t stallMicros = 0;
    uint64_t asyncSubmits = 0;
    uint64_t asyncWaits = 0;
    uint64_t asyncPollReady = 0;
    uint64_t asyncFailures = 0;
    size_t residentBytes = 0;
    size_t budgetBytes = 0;
    size_t inflightBytes = 0;
    uint64_t transferMicros = 0;

    // RAWRXD_DEEP2_BOUNDED_STREAM_001 residency lease accounting.
    uint64_t leasesAcquired = 0;
    uint64_t leasesReleased = 0;
    uint64_t leasesOutstanding = 0;   // acquired - released, sampled live
    uint64_t leaseRejections = 0;     // not resident, or evicted under a pin
    uint64_t evictionsBlockedByPin = 0;
    uint64_t doubleRelease = 0;
    uint64_t unknownLeaseRelease = 0;
    uint64_t residencyPromotions = 0; // times an entry became resident
};

// No-dependency transport surface. Deep2/Vulkan implements these four callbacks.
// The cache never calls Vulkan directly and never performs CPU GEMM.
struct ExpertTransport {
    void* user = nullptr;

    // Allocate device memory for one expert. Return opaque handle or nullptr.
    void* (*allocDevice)(void* user, size_t bytes, uint32_t deviceOrdinal) = nullptr;
    void  (*freeDevice)(void* user, void* deviceHandle, uint32_t deviceOrdinal) = nullptr;

    // Upload backing bytes into device memory. Must return true only when usable by GPU.
    bool  (*upload)(void* user,
                    void* deviceHandle,
                    const void* src,
                    size_t bytes,
                    uint32_t deviceOrdinal) = nullptr;

    // Optional monotonic clock. If null, timing fields remain zero.
    uint64_t (*nowMicros)(void* user) = nullptr;

    // Optional async DMA path. If all three are supplied, prefetch() can submit without
    // blocking. acquire() waits only when it encounters an in-flight expert.
    // Ticket 0 means submission failed.
    uint64_t (*submitUpload)(void* user,
                             void* deviceHandle,
                             const void* src,
                             size_t bytes,
                             uint32_t deviceOrdinal) = nullptr;
    bool (*pollUpload)(void* user, uint64_t ticket, uint32_t deviceOrdinal) = nullptr;
    bool (*waitUpload)(void* user, uint64_t ticket, uint32_t deviceOrdinal) = nullptr;
};

enum class ExpertCachePolicy : uint32_t {
    EmaLfu = 0,
    Lru = 1
};

struct ExpertCacheConfig {
    size_t budgetBytes = 0;
    uint32_t deviceOrdinal = 0;
    float emaAlpha = 0.10f;
    ExpertCachePolicy policy = ExpertCachePolicy::EmaLfu;
    uint32_t prefetchDepth = 1;
};

struct ExpertLease {
    ExpertKey key{};
    void* deviceHandle = nullptr;
    size_t bytes = 0;
    bool hit = false;
    explicit operator bool() const noexcept { return deviceHandle != nullptr; }
};

// RAWRXD_DEEP2_BOUNDED_STREAM_001
//
// A residency lease pins one resident allocation and returns its pointer in the
// same critical section, so the pointer cannot be invalidated between the
// residency check and the pin.
//
// The alternative -- isResident(), then residentHandle(), then a separate
// pin() -- is racy. Eviction can free the device allocation in the window
// between the check and the pin, after which the pinned pointer is already
// dangling. tryAcquireResident() collapses check and pin into one operation
// under the cache mutex, and bumps a per-entry pin count that eviction refuses
// to cross.
//
// residencyGeneration increments every time an entry becomes resident. It is
// the cache's own identity for the current allocation, distinct from the
// producer's prediction sequence, and the consumer uses it to detect a pointer
// that no longer matches the entry it thinks it holds.
struct ResidentLease {
    const void* weights = nullptr;
    size_t bytes = 0;
    uint64_t residencyGeneration = 0;
    uint64_t leaseId = 0;
    ExpertKey key{};
};

class ExpertCache final {
public:
    ExpertCache(ExpertCacheConfig cfg, ExpertTransport transport);
    ~ExpertCache();

    ExpertCache(const ExpertCache&) = delete;
    ExpertCache& operator=(const ExpertCache&) = delete;

    // Register backing location. Safe to call before model execution begins.
    bool registerExpert(ExpertKey key, ExpertLocation loc);

    // Demand path. Guarantees returned handle is resident when successful.
    ExpertLease acquire(ExpertKey key, uint64_t tokenIndex);

    // Non-binding prefetch: same residency operation, but tracked separately.
    bool prefetch(ExpertKey key, uint64_t tokenIndex);

    // RAWRXD_DEEP2_BOUNDED_STREAM_001 residency lease.
    //
    // Atomically verifies the entry is resident AND pins it, returning the
    // consumable pointer in the same critical section. Use this instead of
    // isResident() followed by residentHandle(); that sequence has a window in
    // which eviction can free the allocation, leaving the caller holding a
    // pointer that is already dangling.
    //
    // Never blocks and never performs I/O. If the entry is not resident the
    // call fails; the caller is expected to have issued prefetch() earlier and
    // to come back on a later pass.
    bool tryAcquireResident(ExpertKey key, ResidentLease& out) noexcept;

    // Release a lease taken by tryAcquireResident(). Idempotent per leaseId:
    // a second release of the same id is counted as a violation and ignored.
    // Unknown ids are counted and ignored.
    bool releaseResident(uint64_t leaseId) noexcept;

    // True when the entry is resident and carries at least one live lease.
    // Eviction refuses to reclaim a pinned entry; this is how the policy layer
    // can tell that a refusal happened rather than silently choosing a
    // different victim.
    bool isPinned(ExpertKey key) const;

    // Update predicted reuse probability from the router. 0..1.
    void notePrediction(ExpertKey key, float probability, uint64_t tokenIndex);

    // Optional warm start: hot keys are loaded in caller-supplied order until budget fills.
    size_t warmStart(const std::vector<ExpertKey>& keys, uint64_t tokenIndex = 0);

    // Explicit eviction / teardown controls.
    bool evict(ExpertKey key);
    void clear();

    ExpertCacheStats stats() const;
    bool isResident(ExpertKey key) const;
    void* residentHandle(ExpertKey key) const;

private:
    struct Entry {
        ExpertLocation loc{};
        void* deviceHandle = nullptr;
        uint64_t hits = 0;
        uint64_t lastUsedToken = 0;
        float emaFrequency = 0.0f;
        float predictedValue = 0.0f;
        bool resident = false;
        bool loading = false;
        uint64_t uploadTicket = 0;
        uint64_t uploadStartMicros = 0;

        // RAWRXD_DEEP2_BOUNDED_STREAM_001 lease state.
        // pinCount > 0 forbids eviction. residencyGeneration changes on every
        // transition to resident, so a stale pointer is detectable.
        uint32_t pinCount = 0;
        uint64_t residencyGeneration = 0;
    };

    // A live lease. Keyed by leaseId so release is O(1) and a double release
    // is detectable rather than silently decrementing a pin count.
    struct LiveLease {
        ExpertKey key{};
        uint64_t residencyGeneration = 0;
    };
    std::unordered_map<uint64_t, LiveLease> leases_;
    uint64_t nextLeaseId_ = 1;

    float scoreLocked(const Entry& e, uint64_t nowToken) const;
    bool ensureSpaceLocked(size_t bytesNeeded, uint64_t tokenIndex, const ExpertKey* protectedKey);
    bool loadLocked(const ExpertKey& key, Entry& e, uint64_t tokenIndex, bool isPrefetch, bool* outHit);
    bool finishAsyncLocked(Entry& e, bool wait);
    bool evictLocked(const ExpertKey& key, Entry& e);

    ExpertCacheConfig cfg_{};
    ExpertTransport transport_{};
    mutable std::mutex mu_;
    std::unordered_map<ExpertKey, Entry, ExpertKeyHash> entries_;
    ExpertCacheStats stats_{};
};

} // namespace rawrxd::deep2
