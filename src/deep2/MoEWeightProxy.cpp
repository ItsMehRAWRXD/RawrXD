// ============================================================================
// MoEWeightProxy.cpp - Single entry point for MoE weight acquisition.
// Thin wrapper over MoEWeightsLoader. No backends, no alternatives.
// ============================================================================

#include "MoEWeightProxy.hpp"
#include "MoEWeightsLoader.hpp"
#include <chrono>

namespace Deep2 {

void MoEWeightProxy::Attach(MoEWeightsLoader* loader) {
    std::lock_guard<std::mutex> lock(attachMutex_);
    loader_ = loader;
}

void MoEWeightProxy::Detach() {
    std::lock_guard<std::mutex> lock(attachMutex_);
    loader_ = nullptr;
}

bool MoEWeightProxy::IsAttached() const {
    std::lock_guard<std::mutex> lock(attachMutex_);
    return loader_ != nullptr;
}

MoEWeightHandle MoEWeightProxy::Acquire(int layer, int expert) {
    auto start = std::chrono::high_resolution_clock::now();
    stats_.totalRequests.fetch_add(1, std::memory_order_relaxed);

    MoEWeightHandle h = AcquireInternal(layer, expert);

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
    if (h.valid) {
        stats_.avgLatencyMs = (stats_.avgLatencyMs * 0.95) + (ms * 0.05);
    }
    return h;
}

MoEWeightHandle MoEWeightProxy::AcquireInternal(int layer, int expert) {
    MoEWeightHandle h;
    MoEWeightsLoader* loader;
    {
        std::lock_guard<std::mutex> lock(attachMutex_);
        loader = loader_;
    }
    if (!loader) return h;

    const void* packed = loader->LoadExpert(layer, expert);
    if (!packed) return h;

    // Walk the projection table to find the three slices for this layer.
    const auto& projections = loader->GetExpertProjections();
    size_t gateBytes = 0, upBytes = 0, downBytes = 0;
    for (const auto& info : projections) {
        if (info.layerIdx != layer) continue;
        if (info.expertIdx != -1) continue; // skip router/shared
        switch (info.proj) {
            case ExpertProjection::Gate: gateBytes = info.bytesPerExpert; break;
            case ExpertProjection::Up:   upBytes = info.bytesPerExpert;   break;
            case ExpertProjection::Down: downBytes = info.bytesPerExpert; break;
        }
    }

    h.gateWeights = packed;
    h.upWeights   = static_cast<const uint8_t*>(packed) + gateBytes;
    h.downWeights = static_cast<const uint8_t*>(packed) + gateBytes + upBytes;
    h.expertBytes = gateBytes + upBytes + downBytes;
    h.layer = layer;
    h.expertId = expert;
    h.valid = true;

    stats_.bytesStreamed.fetch_add(h.expertBytes, std::memory_order_relaxed);

    // Forward cache-hit accounting from the loader
    auto s = loader->GetStats();
    stats_.cacheHits.store(s.cacheHits, std::memory_order_relaxed);
    return h;
}

void MoEWeightProxy::SetMaxCacheSize(size_t bytes) const {
    MoEWeightsLoader* loader;
    {
        std::lock_guard<std::mutex> lock(attachMutex_);
        loader = loader_;
    }
    if (loader) loader->SetMaxCacheSize(bytes);
}

size_t MoEWeightProxy::GetCacheSize() const {
    MoEWeightsLoader* loader;
    {
        std::lock_guard<std::mutex> lock(attachMutex_);
        loader = loader_;
    }
    return loader ? loader->GetCacheSize() : 0;
}

void MoEWeightProxy::ResetStats() {
    stats_.totalRequests = 0;
    stats_.cacheHits = 0;
    stats_.bytesStreamed = 0;
    stats_.avgLatencyMs = 0.0;
}

size_t MoEWeightProxy::GetNumExpertLayers() const {
    MoEWeightsLoader* loader;
    {
        std::lock_guard<std::mutex> lock(attachMutex_);
        loader = loader_;
    }
    return loader ? loader->GetNumExpertLayers() : 0;
}

size_t MoEWeightProxy::GetExpertsPerLayer() const {
    MoEWeightsLoader* loader;
    {
        std::lock_guard<std::mutex> lock(attachMutex_);
        loader = loader_;
    }
    return loader ? loader->GetExpertsPerLayer() : 0;
}

const std::string& MoEWeightProxy::GetArchitecture() const {
    static const std::string empty;
    MoEWeightsLoader* loader;
    {
        std::lock_guard<std::mutex> lock(attachMutex_);
        loader = loader_;
    }
    return loader ? loader->GetArchitecture() : empty;
}

} // namespace Deep2
