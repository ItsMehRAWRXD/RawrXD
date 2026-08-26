// ============================================================================
// MoEWeightProxy.cpp - Single entry point for MoE weight acquisition.
// Thin wrapper over MoEWeightsLoader. No backends, no alternatives.
// ============================================================================

#include "MoEWeightProxy.hpp"
#include "MoEWeightsLoader.hpp"
#include "vulkan_compute.h"
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

void MoEWeightProxy::Prefetch(int layer, const std::vector<int>& expertIds) {
    MoEWeightsLoader* loader;
    {
        std::lock_guard<std::mutex> lock(attachMutex_);
        loader = loader_;
    }
    if (!loader) return;

    for (int expertId : expertIds) {
        // Touch the loader's cache for this expert without building a handle.
        // The loader's internal LRU will keep it resident.
        const void* packed = loader->LoadExpert(layer, expertId);
        (void)packed; // We only care about the cache warming side-effect.
    }

    // Forward cache-hit accounting from the loader
    auto s = loader->GetStats();
    stats_.cacheHits.store(s.cacheHits, std::memory_order_relaxed);
}

// ============================================================================
// Async Vulkan transfer path — fence-based scheduling
// ============================================================================
std::vector<uint64_t> MoEWeightProxy::PrefetchAsync(int layer,
                                                    const std::vector<int>& expertIds,
                                                    CPUInference::VulkanCompute* vulkan) {
    std::vector<uint64_t> handles;
    if (!vulkan) return handles;

    MoEWeightsLoader* loader;
    {
        std::lock_guard<std::mutex> lock(attachMutex_);
        loader = loader_;
    }
    if (!loader) return handles;

    auto now = std::chrono::high_resolution_clock::now();
    uint64_t submitUs = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();

    for (int expertId : expertIds) {
        // 1. Load expert weights into host-visible staging (WARM)
        const void* packed = loader->LoadExpert(layer, expertId);
        if (!packed) continue;

        // 2. Resolve expert size from projections
        size_t expertBytes = 0;
        const auto& projections = loader->GetExpertProjections();
        for (const auto& info : projections) {
            if (info.layerIdx != layer) continue;
            if (info.expertIdx != -1) continue;
            expertBytes += info.bytesPerExpert;
        }
        if (expertBytes == 0) continue;

        // 3. Attempt async Vulkan upload.
        //    NOTE: VulkanCompute async methods are currently stubs that return
        //    failure. When they are implemented, replace this block with actual
        //    AllocateBuffer → CreateStagingBuffer → vkCmdCopyBuffer → Submit.
        bool asyncSubmitted = false;
        VkBuffer devBuffer = nullptr;
        VkDeviceMemory devMemory = nullptr;
        VkBuffer stagingBuffer = nullptr;
        VkDeviceMemory stagingMemory = nullptr;
        VkFence fence = nullptr;

        // TODO: Implement real Vulkan async transfer when stubs are functional.
        // For now, the expert is already resident in RAM via LoadExpert(),
        // so we mark the job as completed (CPU fallback).
        (void)devBuffer; (void)devMemory; (void)stagingBuffer;
        (void)stagingMemory; (void)fence;

        // 4. Track the job (completed immediately for CPU fallback,
        //    or pending for true async Vulkan path)
        uint64_t handle;
        {
            std::lock_guard<std::mutex> lock(prefetchMutex_);
            handle = nextJobHandle_++;
            PrefetchJob job;
            job.layer = layer;
            job.expertId = expertId;
            job.submitTimeUs = submitUs;
            job.completed = !asyncSubmitted; // CPU fallback = already ready
            job.consumed = false;
            job.bytesTransferred = expertBytes;
            prefetchJobs_[handle] = std::move(job);
        }
        handles.push_back(handle);
        stats_.asyncPrefetchSubmitted.fetch_add(1, std::memory_order_relaxed);
        if (!asyncSubmitted) {
            stats_.synchronousFallbacks.fetch_add(1, std::memory_order_relaxed);
        }
    }

    return handles;
}

bool MoEWeightProxy::CheckPrefetchReady(uint64_t jobHandle,
                                        CPUInference::VulkanCompute* vulkan) {
    if (!vulkan) return false;

    std::lock_guard<std::mutex> lock(prefetchMutex_);
    auto it = prefetchJobs_.find(jobHandle);
    if (it == prefetchJobs_.end()) return false;

    PrefetchJob& job = it->second;
    if (job.completed) {
        // CPU fallback jobs are marked completed immediately on creation.
        // True async Vulkan jobs need a fence check.
        stats_.asyncPrefetchReadyAtCompute.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // True async path: check Vulkan fence (non-blocking)
    // NOTE: Production code should map jobHandle -> cmd buffer -> fence.
    // With current stubs, FlushAsyncCommands is a no-op, so we rely on
    // the heuristic below.  When Vulkan async is implemented, replace
    // this with vkGetFenceStatus.
    if (vulkan->FlushAsyncCommands()) {
        job.completed = true;
        auto now = std::chrono::high_resolution_clock::now();
        job.readyTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
        stats_.asyncPrefetchCompleted.fetch_add(1, std::memory_order_relaxed);
        stats_.asyncPrefetchReadyAtCompute.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Heuristic fallback for stub Vulkan backend
    auto now = std::chrono::high_resolution_clock::now();
    uint64_t elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count() - job.submitTimeUs;
    if (elapsedUs > 500) {
        job.completed = true;
        job.readyTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
        stats_.asyncPrefetchCompleted.fetch_add(1, std::memory_order_relaxed);
        stats_.asyncPrefetchReadyAtCompute.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    return false;
}

bool MoEWeightProxy::WaitPrefetch(uint64_t jobHandle,
                                  CPUInference::VulkanCompute* vulkan) {
    if (!vulkan) return false;

    auto t0 = std::chrono::high_resolution_clock::now();

    // Block until ready (simplified: spin on CheckPrefetchReady)
    bool ready = false;
    for (int spin = 0; spin < 10000 && !ready; ++spin) {
        ready = CheckPrefetchReady(jobHandle, vulkan);
        if (!ready) {
            // Yield to avoid burning CPU
            std::this_thread::yield();
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    uint64_t waitUs = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    stats_.fenceWaitUs.fetch_add(waitUs, std::memory_order_relaxed);

    if (!ready) {
        stats_.synchronousFallbacks.fetch_add(1, std::memory_order_relaxed);
    }
    return ready;
}

const PrefetchJob* MoEWeightProxy::GetPrefetchJob(uint64_t jobHandle) const {
    std::lock_guard<std::mutex> lock(prefetchMutex_);
    auto it = prefetchJobs_.find(jobHandle);
    if (it != prefetchJobs_.end()) return &it->second;
    return nullptr;
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
