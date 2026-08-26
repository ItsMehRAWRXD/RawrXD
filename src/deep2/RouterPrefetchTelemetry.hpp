// ============================================================================
// RouterPrefetchTelemetry.hpp — Per-expert state transition and timing telemetry
// ============================================================================
// Tracks:
//   - State transitions (Cold→Warm, Warm→Uploading, Uploading→Hot, etc.)
//   - Timing metrics (transfer_us, gpu_wait_us, compute_us, prefetch_hit)
//   - Per-expert cumulative statistics
//
// Design: lightweight, lock-free where possible, opt-in via Deep2Engine.
// ============================================================================

#ifndef ROUTER_PREFETCH_TELEMETRY_HPP
#define ROUTER_PREFETCH_TELEMETRY_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <chrono>
#include <atomic>
#include <mutex>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Expert residency event — one transition or timing sample
// ---------------------------------------------------------------------------
struct RouterPrefetchEvent {
    uint64_t timestampUs = 0;          // Microseconds since epoch
    int layerId = -1;
    int expertId = -1;
    uint8_t fromState = 0;             // TensorResidencyState ordinal
    uint8_t toState = 0;
    uint32_t durationUs = 0;           // Transition time in microseconds
    bool prefetchHit = false;          // True if expert was already Warm/Hot
};

// ---------------------------------------------------------------------------
// Per-expert cumulative telemetry
// ---------------------------------------------------------------------------
struct RouterPrefetchExpertTelemetry {
    int layerId = -1;
    int expertId = -1;

    std::atomic<uint64_t> coldToWarmUs{0};      // NVMe → RAM
    std::atomic<uint64_t> warmToHotUs{0};       // RAM → VRAM (upload)
    std::atomic<uint64_t> gpuWaitUs{0};           // Time compute waited for GPU
    std::atomic<uint64_t> computeUs{0};           // Expert FFN compute time
    std::atomic<uint64_t> prefetchHits{0};       // Expert already resident when requested
    std::atomic<uint64_t> prefetchMisses{0};     // Expert had to be fetched
    std::atomic<uint64_t> totalInvocations{0};   // Total times this expert was selected

    // Async Vulkan transfer counters
    std::atomic<uint64_t> asyncPrefetchSubmitted{0};      // Times async prefetch was submitted
    std::atomic<uint64_t> asyncPrefetchCompleted{0};    // Times async prefetch finished (fence signaled)
    std::atomic<uint64_t> asyncPrefetchReadyAtCompute{0}; // Expert HOT when compute needed it
    std::atomic<uint64_t> asyncPrefetchLate{0};           // Expert still pending at compute time
    std::atomic<uint64_t> fenceWaitUs{0};                   // Time blocked waiting for fence
    std::atomic<uint64_t> synchronousFallbacks{0};        // Times we fell back to sync path

    RouterPrefetchExpertTelemetry() = default;

    // Copy constructor: load values from atomics
    RouterPrefetchExpertTelemetry(const RouterPrefetchExpertTelemetry& other)
        : layerId(other.layerId), expertId(other.expertId),
          coldToWarmUs(other.coldToWarmUs.load()),
          warmToHotUs(other.warmToHotUs.load()),
          gpuWaitUs(other.gpuWaitUs.load()),
          computeUs(other.computeUs.load()),
          prefetchHits(other.prefetchHits.load()),
          prefetchMisses(other.prefetchMisses.load()),
          totalInvocations(other.totalInvocations.load()),
          asyncPrefetchSubmitted(other.asyncPrefetchSubmitted.load()),
          asyncPrefetchCompleted(other.asyncPrefetchCompleted.load()),
          asyncPrefetchReadyAtCompute(other.asyncPrefetchReadyAtCompute.load()),
          asyncPrefetchLate(other.asyncPrefetchLate.load()),
          fenceWaitUs(other.fenceWaitUs.load()),
          synchronousFallbacks(other.synchronousFallbacks.load()) {}

    // Copy assignment: load values from atomics
    RouterPrefetchExpertTelemetry& operator=(const RouterPrefetchExpertTelemetry& other) {
        if (this != &other) {
            layerId = other.layerId;
            expertId = other.expertId;
            coldToWarmUs.store(other.coldToWarmUs.load());
            warmToHotUs.store(other.warmToHotUs.load());
            gpuWaitUs.store(other.gpuWaitUs.load());
            computeUs.store(other.computeUs.load());
            prefetchHits.store(other.prefetchHits.load());
            prefetchMisses.store(other.prefetchMisses.load());
            totalInvocations.store(other.totalInvocations.load());
            asyncPrefetchSubmitted.store(other.asyncPrefetchSubmitted.load());
            asyncPrefetchCompleted.store(other.asyncPrefetchCompleted.load());
            asyncPrefetchReadyAtCompute.store(other.asyncPrefetchReadyAtCompute.load());
            asyncPrefetchLate.store(other.asyncPrefetchLate.load());
            fenceWaitUs.store(other.fenceWaitUs.load());
            synchronousFallbacks.store(other.synchronousFallbacks.load());
        }
        return *this;
    }

    void RecordInvocation(bool wasPrefetched, uint64_t computeMicros);
    void RecordTransition(uint8_t fromState, uint8_t toState, uint64_t durationMicros);
};

// ---------------------------------------------------------------------------
// Global residency telemetry aggregator
// ---------------------------------------------------------------------------
class RouterPrefetchTelemetry {
public:
    RouterPrefetchTelemetry() = default;
    ~RouterPrefetchTelemetry() = default;

    // Initialize telemetry for a given layer/expert grid
    void Initialize(int numLayers, int expertsPerLayer);

    // Record a state transition for a specific expert
    void RecordTransition(int layerId, int expertId,
                          uint8_t fromState, uint8_t toState,
                          uint64_t durationUs);

    // Record that an expert was invoked (compute started)
    void RecordInvocation(int layerId, int expertId, bool prefetchHit);

    // Record compute completion time for an expert
    void RecordComputeTime(int layerId, int expertId, uint64_t computeUs);

    // Record GPU wait time (time compute blocked waiting for upload)
    void RecordGPUWait(int layerId, int expertId, uint64_t waitUs);

    // Record async prefetch submission
    void RecordAsyncPrefetchSubmitted(int layerId, int expertId);

    // Record async prefetch completion (fence signaled)
    void RecordAsyncPrefetchCompleted(int layerId, int expertId);

    // Record whether prefetch was ready when compute needed it
    void RecordAsyncPrefetchReadyAtCompute(int layerId, int expertId, bool wasReady);

    // Record fence wait time (blocking wait for async transfer)
    void RecordFenceWait(int layerId, int expertId, uint64_t waitUs);

    // Record synchronous fallback (async path missed, had to block)
    void RecordSynchronousFallback(int layerId, int expertId);

    // Get per-expert telemetry
    const RouterPrefetchExpertTelemetry* GetExpertTelemetry(int layerId, int expertId) const;

    // Get all events (for diagnostics / export)
    std::vector<RouterPrefetchEvent> GetEvents() const;

    // Summary statistics
    struct Summary {
        uint64_t totalPrefetchHits = 0;
        uint64_t totalPrefetchMisses = 0;
        uint64_t totalTransferUs = 0;      // Sum of cold→warm + warm→hot
        uint64_t totalGPUWaitUs = 0;
        uint64_t totalComputeUs = 0;
        double hitRate = 0.0;

        // Async Vulkan transfer summary
        uint64_t totalAsyncPrefetchSubmitted = 0;
        uint64_t totalAsyncPrefetchCompleted = 0;
        uint64_t totalAsyncPrefetchReadyAtCompute = 0;
        uint64_t totalAsyncPrefetchLate = 0;
        uint64_t totalFenceWaitUs = 0;
        uint64_t totalSynchronousFallbacks = 0;
        double asyncReadyRate = 0.0;  // readyAtCompute / submitted
    };
    Summary GetSummary() const;

    // Reset all counters
    void Reset();

    // Print human-readable report
    void PrintReport() const;

private:
    mutable std::mutex mutex_;
    std::vector<RouterPrefetchExpertTelemetry> expertTelemetry_;  // flattened [layer * experts + expert]
    std::vector<RouterPrefetchEvent> events_;
    int numLayers_ = 0;
    int expertsPerLayer_ = 0;

    size_t FlatIndex(int layerId, int expertId) const;
};

} // namespace Deep2

#endif // ROUTER_PREFETCH_TELEMETRY_HPP
