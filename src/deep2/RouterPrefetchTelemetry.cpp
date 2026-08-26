// ============================================================================
// RouterPrefetchTelemetry.cpp — Implementation
// ============================================================================

#include "RouterPrefetchTelemetry.hpp"
#include <cstdio>

namespace Deep2 {

// ---------------------------------------------------------------------------
// RouterPrefetchExpertTelemetry
// ---------------------------------------------------------------------------
void RouterPrefetchExpertTelemetry::RecordInvocation(bool wasPrefetched, uint64_t computeMicros) {
    totalInvocations.fetch_add(1, std::memory_order_relaxed);
    if (wasPrefetched) {
        prefetchHits.fetch_add(1, std::memory_order_relaxed);
    } else {
        prefetchMisses.fetch_add(1, std::memory_order_relaxed);
    }
    computeUs.fetch_add(computeMicros, std::memory_order_relaxed);
}

void RouterPrefetchExpertTelemetry::RecordTransition(uint8_t fromState, uint8_t toState, uint64_t durationMicros) {
    // Aggregate by transition type
    if (fromState == 0 && toState == 2) { // Cold → Warm
        coldToWarmUs.fetch_add(durationMicros, std::memory_order_relaxed);
    } else if (fromState == 2 && toState == 4) { // Warm → Hot
        warmToHotUs.fetch_add(durationMicros, std::memory_order_relaxed);
    } else if (fromState == 3 && toState == 4) { // Uploading → Hot
        warmToHotUs.fetch_add(durationMicros, std::memory_order_relaxed);
    }
}

// ---------------------------------------------------------------------------
// RouterPrefetchTelemetry
// ---------------------------------------------------------------------------
void RouterPrefetchTelemetry::Initialize(int numLayers, int expertsPerLayer) {
    std::lock_guard<std::mutex> lock(mutex_);
    numLayers_ = numLayers;
    expertsPerLayer_ = expertsPerLayer;
    expertTelemetry_.resize(numLayers * expertsPerLayer);
    for (int l = 0; l < numLayers; ++l) {
        for (int e = 0; e < expertsPerLayer; ++e) {
            size_t idx = l * expertsPerLayer + e;
            expertTelemetry_[idx].layerId = l;
            expertTelemetry_[idx].expertId = e;
        }
    }
    events_.clear();
}

void RouterPrefetchTelemetry::RecordTransition(int layerId, int expertId,
                                            uint8_t fromState, uint8_t toState,
                                            uint64_t durationUs) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;

    size_t idx = FlatIndex(layerId, expertId);
    expertTelemetry_[idx].RecordTransition(fromState, toState, durationUs);

    RouterPrefetchEvent ev;
    ev.timestampUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    ev.layerId = layerId;
    ev.expertId = expertId;
    ev.fromState = fromState;
    ev.toState = toState;
    ev.durationUs = static_cast<uint32_t>(std::min(durationUs, (uint64_t)UINT32_MAX));
    events_.push_back(ev);
}

void RouterPrefetchTelemetry::RecordInvocation(int layerId, int expertId, bool prefetchHit) {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;
    size_t idx = FlatIndex(layerId, expertId);
    expertTelemetry_[idx].RecordInvocation(prefetchHit, 0);
}

void RouterPrefetchTelemetry::RecordComputeTime(int layerId, int expertId, uint64_t computeUs) {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;
    size_t idx = FlatIndex(layerId, expertId);
    expertTelemetry_[idx].computeUs.fetch_add(computeUs, std::memory_order_relaxed);
}

void RouterPrefetchTelemetry::RecordGPUWait(int layerId, int expertId, uint64_t waitUs) {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;
    size_t idx = FlatIndex(layerId, expertId);
    expertTelemetry_[idx].gpuWaitUs.fetch_add(waitUs, std::memory_order_relaxed);
}

void RouterPrefetchTelemetry::RecordAsyncPrefetchSubmitted(int layerId, int expertId) {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;
    size_t idx = FlatIndex(layerId, expertId);
    expertTelemetry_[idx].asyncPrefetchSubmitted.fetch_add(1, std::memory_order_relaxed);
}

void RouterPrefetchTelemetry::RecordAsyncPrefetchCompleted(int layerId, int expertId) {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;
    size_t idx = FlatIndex(layerId, expertId);
    expertTelemetry_[idx].asyncPrefetchCompleted.fetch_add(1, std::memory_order_relaxed);
}

void RouterPrefetchTelemetry::RecordAsyncPrefetchReadyAtCompute(int layerId, int expertId, bool wasReady) {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;
    size_t idx = FlatIndex(layerId, expertId);
    if (wasReady) {
        expertTelemetry_[idx].asyncPrefetchReadyAtCompute.fetch_add(1, std::memory_order_relaxed);
    } else {
        expertTelemetry_[idx].asyncPrefetchLate.fetch_add(1, std::memory_order_relaxed);
    }
}

void RouterPrefetchTelemetry::RecordFenceWait(int layerId, int expertId, uint64_t waitUs) {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;
    size_t idx = FlatIndex(layerId, expertId);
    expertTelemetry_[idx].fenceWaitUs.fetch_add(waitUs, std::memory_order_relaxed);
}

void RouterPrefetchTelemetry::RecordSynchronousFallback(int layerId, int expertId) {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return;
    size_t idx = FlatIndex(layerId, expertId);
    expertTelemetry_[idx].synchronousFallbacks.fetch_add(1, std::memory_order_relaxed);
}

const RouterPrefetchExpertTelemetry* RouterPrefetchTelemetry::GetExpertTelemetry(int layerId, int expertId) const {
    if (layerId < 0 || layerId >= numLayers_ || expertId < 0 || expertId >= expertsPerLayer_) return nullptr;
    size_t idx = FlatIndex(layerId, expertId);
    return &expertTelemetry_[idx];
}

std::vector<RouterPrefetchEvent> RouterPrefetchTelemetry::GetEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_;
}

RouterPrefetchTelemetry::Summary RouterPrefetchTelemetry::GetSummary() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Summary s;
    for (const auto& et : expertTelemetry_) {
        s.totalPrefetchHits += et.prefetchHits.load(std::memory_order_relaxed);
        s.totalPrefetchMisses += et.prefetchMisses.load(std::memory_order_relaxed);
        s.totalTransferUs += et.coldToWarmUs.load(std::memory_order_relaxed);
        s.totalTransferUs += et.warmToHotUs.load(std::memory_order_relaxed);
        s.totalGPUWaitUs += et.gpuWaitUs.load(std::memory_order_relaxed);
        s.totalComputeUs += et.computeUs.load(std::memory_order_relaxed);

        s.totalAsyncPrefetchSubmitted += et.asyncPrefetchSubmitted.load(std::memory_order_relaxed);
        s.totalAsyncPrefetchCompleted += et.asyncPrefetchCompleted.load(std::memory_order_relaxed);
        s.totalAsyncPrefetchReadyAtCompute += et.asyncPrefetchReadyAtCompute.load(std::memory_order_relaxed);
        s.totalAsyncPrefetchLate += et.asyncPrefetchLate.load(std::memory_order_relaxed);
        s.totalFenceWaitUs += et.fenceWaitUs.load(std::memory_order_relaxed);
        s.totalSynchronousFallbacks += et.synchronousFallbacks.load(std::memory_order_relaxed);
    }
    uint64_t total = s.totalPrefetchHits + s.totalPrefetchMisses;
    s.hitRate = total > 0 ? (double)s.totalPrefetchHits / (double)total : 0.0;
    s.asyncReadyRate = s.totalAsyncPrefetchSubmitted > 0
        ? (double)s.totalAsyncPrefetchReadyAtCompute / (double)s.totalAsyncPrefetchSubmitted
        : 0.0;
    return s;
}

void RouterPrefetchTelemetry::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& et : expertTelemetry_) {
        et.coldToWarmUs = 0;
        et.warmToHotUs = 0;
        et.gpuWaitUs = 0;
        et.computeUs = 0;
        et.prefetchHits = 0;
        et.prefetchMisses = 0;
        et.totalInvocations = 0;
    }
    events_.clear();
}

void RouterPrefetchTelemetry::PrintReport() const {
    auto s = GetSummary();
    printf("\n============================================================\n");
    printf("ROUTER PREFETCH TELEMETRY REPORT\n");
    printf("============================================================\n");
    printf("Prefetch Hits:   %llu\n", (unsigned long long)s.totalPrefetchHits);
    printf("Prefetch Misses: %llu\n", (unsigned long long)s.totalPrefetchMisses);
    printf("Hit Rate:        %.2f%%\n", s.hitRate * 100.0);
    printf("Total Transfer:  %llu us\n", (unsigned long long)s.totalTransferUs);
    printf("Total GPU Wait:  %llu us\n", (unsigned long long)s.totalGPUWaitUs);
    printf("Total Compute:   %llu us\n", (unsigned long long)s.totalComputeUs);
    printf("------------------------------------------------------------\n");
    printf("ASYNC VULKAN TRANSFER\n");
    printf("------------------------------------------------------------\n");
    printf("Async Submitted: %llu\n", (unsigned long long)s.totalAsyncPrefetchSubmitted);
    printf("Async Completed: %llu\n", (unsigned long long)s.totalAsyncPrefetchCompleted);
    printf("Ready @ Compute: %llu\n", (unsigned long long)s.totalAsyncPrefetchReadyAtCompute);
    printf("Async Late:      %llu\n", (unsigned long long)s.totalAsyncPrefetchLate);
    printf("Async Ready Rate:%.2f%%\n", s.asyncReadyRate * 100.0);
    printf("Fence Wait:      %llu us\n", (unsigned long long)s.totalFenceWaitUs);
    printf("Sync Fallbacks:  %llu\n", (unsigned long long)s.totalSynchronousFallbacks);
    printf("============================================================\n");
}

size_t RouterPrefetchTelemetry::FlatIndex(int layerId, int expertId) const {
    return static_cast<size_t>(layerId) * expertsPerLayer_ + expertId;
}

} // namespace Deep2
