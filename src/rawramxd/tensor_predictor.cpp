/**
 * RawRamXD Phase 7C: Tensor Access Predictor Implementation
 * 
 * Implements pattern recognition and predictive prefetching.
 */

#include "rawramxd/tensor_predictor.hpp"
#include "rawramxd/gpu_fabric.hpp"

#include <iostream>
#include <algorithm>
#include <cmath>
#include <string>

namespace RawRamXD {

// =============================================================================
// PREDICTOR IMPLEMENTATION
// =============================================================================

struct TensorPredictor::Impl {
    std::unordered_map<uint64_t, std::deque<AccessEvent>> accessHistory_;
    std::unordered_map<uint64_t, TensorHotness> hotnessCache_;
    
    uint32_t layerCount_ = 0;
    uint64_t tokenLatencyUs_ = 0;
    uint64_t startTimeUs_ = 0;
    
    // Pattern detection state
    std::unordered_map<uint64_t, std::vector<uint64_t>> interArrivalTimes_;
    
    // Statistics
    Stats stats_{};
    mutable std::mutex mutex_;
    
    uint64_t GetCurrentTimeUs() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    }
    
    void UpdateHotness(uint64_t tensorHandle, const AccessEvent& event) {
        auto& hotness = hotnessCache_[tensorHandle];
        hotness.tensorHandle = tensorHandle;
        
        uint64_t now = GetCurrentTimeUs();
        
        if (hotness.lastAccessUs > 0) {
            uint64_t interArrival = now - hotness.lastAccessUs;
            interArrivalTimes_[tensorHandle].push_back(interArrival);
            
            // Keep only last 100 intervals
            if (interArrivalTimes_[tensorHandle].size() > 100) {
                interArrivalTimes_[tensorHandle].erase(
                    interArrivalTimes_[tensorHandle].begin());
            }
        }
        
        hotness.lastAccessUs = now;
        hotness.accessCount++;
        hotness.totalComputeTimeUs += event.computeTimeUs;
        
        // Calculate frequency (accesses per second)
        uint64_t elapsedSinceStart = now - startTimeUs_;
        if (elapsedSinceStart > 0) {
            hotness.accessFrequency = (float)hotness.accessCount * 1000000.0f / elapsedSinceStart;
        }
        
        // Calculate reuse probability based on history
        if (hotness.accessCount > 1) {
            hotness.reuseProbability = std::min(0.95f, 
                0.5f + 0.45f * (hotness.accessCount / 10.0f));
        }
        
        // Predict next access
        if (!interArrivalTimes_[tensorHandle].empty()) {
            uint64_t avgInterval = 0;
            for (auto interval : interArrivalTimes_[tensorHandle]) {
                avgInterval += interval;
            }
            avgInterval /= interArrivalTimes_[tensorHandle].size();
            hotness.expectedNextAccessUs = now + avgInterval;
        }
        
        // Calculate residency score
        // Higher score = more important to keep resident
        hotness.residencyScore = 
            hotness.accessFrequency * 0.3f +
            hotness.reuseProbability * 0.5f +
            (event.computeTimeUs > 1000 ? 0.2f : 0.0f); // Bonus for expensive ops
    }
    
    AccessPattern DetectPatternInternal(uint64_t tensorHandle) {
        auto it = interArrivalTimes_.find(tensorHandle);
        if (it == interArrivalTimes_.end() || it->second.size() < 3) {
            return AccessPattern::UNKNOWN;
        }
        
        const auto& intervals = it->second;
        
        // Calculate variance
        uint64_t sum = 0;
        for (auto interval : intervals) {
            sum += interval;
        }
        uint64_t mean = sum / intervals.size();
        
        uint64_t variance = 0;
        for (auto interval : intervals) {
            int64_t diff = (int64_t)interval - (int64_t)mean;
            variance += diff * diff;
        }
        variance /= intervals.size();
        
        float cv = (mean > 0) ? std::sqrt((float)variance) / mean : 0; // Coefficient of variation
        
        // Classify based on regularity
        if (cv < 0.1f) {
            return AccessPattern::SEQUENTIAL;
        } else if (cv < 0.3f) {
            return AccessPattern::STRIDED;
        } else if (cv < 0.6f) {
            return AccessPattern::TEMPORAL;
        } else {
            return AccessPattern::RANDOM;
        }
    }
};

TensorPredictor::TensorPredictor() : impl_(std::make_unique<Impl>()) {}
TensorPredictor::~TensorPredictor() = default;

bool TensorPredictor::Initialize(uint32_t layerCount, uint64_t tokenLatencyUs) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    impl_-\u003elayerCount_ = layerCount;
    impl_-\u003etokenLatencyUs_ = tokenLatencyUs;
    impl_-\u003estartTimeUs_ = impl_-\u003eGetCurrentTimeUs();
    return true;
}

void TensorPredictor::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    impl_-\u003eaccessHistory_.clear();
    impl_-\u003ehotnessCache_.clear();
    impl_-\u003einterArrivalTimes_.clear();
}

void TensorPredictor::RecordAccess(const AccessEvent& event) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    
    // Store in history
    impl_-\u003eaccessHistory_[event.tensorHandle].push_back(event);
    
    // Keep only last 1000 events per tensor
    if (impl_-\u003eaccessHistory_[event.tensorHandle].size() > 1000) {
        impl_-\u003eaccessHistory_[event.tensorHandle].pop_front();
    }
    
    // Update hotness
    impl_-\u003eUpdateHotness(event.tensorHandle, event);
}

std::vector<Prediction> TensorPredictor::PredictNextAccesses(uint64_t horizonUs) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    
    std::vector<Prediction> predictions;
    uint64_t now = impl_-\u003eGetCurrentTimeUs();
    
    for (const auto& [handle, hotness] : impl_-\u003ehotnessCache_) {
        if (hotness.reuseProbability < 0.1f) continue;
        
        Prediction pred{};
        pred.tensorHandle = handle;
        pred.probability = hotness.reuseProbability;
        pred.predictedTimeUs = hotness.expectedNextAccessUs;
        pred.pattern = hotness.detectedPattern;
        pred.confidence = hotness.reuseProbability * 
            std::min(1.0f, hotness.accessCount / 10.0f);
        
        // Calculate prefetch deadline
        if (pred.predictedTimeUs > now) {
            pred.prefetchDeadlineUs = pred.predictedTimeUs - (horizonUs / 4);
            if (pred.prefetchDeadlineUs > now) {
                predictions.push_back(pred);
            }
        }
    }
    
    // Sort by probability descending
    std::sort(predictions.begin(), predictions.end(),
        [](const Prediction& a, const Prediction& b) {
            return a.probability > b.probability;
        });
    
    return predictions;
}

TensorHotness TensorPredictor::GetHotness(uint64_t tensorHandle) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    auto it = impl_-\u003ehotnessCache_.find(tensorHandle);
    if (it != impl_-\u003ehotnessCache_.end()) {
        return it->second;
    }
    return TensorHotness{};
}

std::vector<TensorHotness> TensorPredictor::GetHotTensors(uint32_t count) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    
    std::vector<TensorHotness> hot;
    for (const auto& [handle, h] : impl_-\u003ehotnessCache_) {
        hot.push_back(h);
    }
    
    // Sort by residency score descending
    std::sort(hot.begin(), hot.end(),
        [](const TensorHotness& a, const TensorHotness& b) {
            return a.residencyScore > b.residencyScore;
        });
    
    if (hot.size() > count) {
        hot.resize(count);
    }
    return hot;
}

PrefetchWindow TensorPredictor::CalculatePrefetchWindow(uint64_t currentTimeUs, 
                                                        uint64_t nextComputeTimeUs) {
    PrefetchWindow window{};
    window.windowStartUs = currentTimeUs;
    window.windowEndUs = nextComputeTimeUs;
    window.slackTimeUs = (nextComputeTimeUs - currentTimeUs) / 10; // 10% slack
    
    // Estimate transfer time based on bandwidth
    // Assume 256MB tensor at 6.2 GB/s = ~41ms
    window.transferTimeUs = 41000; // Conservative estimate
    
    return window;
}

AccessPattern TensorPredictor::DetectPattern(uint64_t tensorHandle) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    auto pattern = impl_-\u003eDetectPatternInternal(tensorHandle);
    impl_-\u003ehotnessCache_[tensorHandle].detectedPattern = pattern;
    return pattern;
}

void TensorPredictor::UpdatePredictionAccuracy(uint64_t tensorHandle, bool wasCorrect) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    impl_-\u003estats_.totalPredictions++;
    if (wasCorrect) {
        impl_-\u003estats_.correctPredictions++;
    } else {
        impl_-\u003estats_.falsePositives++;
    }
    
    if (impl_-\u003estats_.totalPredictions > 0) {
        impl_-\u003estats_.accuracy = 
            (float)impl_-\u003estats_.correctPredictions / impl_-\u003estats_.totalPredictions;
    }
}

TensorPredictor::Stats TensorPredictor::GetStats() const {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    return impl_-\u003estats_;
}

// =============================================================================
// PREFETCH ORCHESTRATOR IMPLEMENTATION
// =============================================================================

struct PrefetchOrchestrator::Impl {
    struct PendingPrefetch {
        uint64_t tensorHandle;
        uint64_t issueTimeUs;
        uint64_t deadlineUs;
        bool completed;
    };
    
    std::vector<PendingPrefetch> pending_;
    std::unordered_map<uint64_t, uint64_t> lastPrefetch_;
    
    Stats stats_{};
    mutable std::mutex mutex_;
    
    uint64_t GetCurrentTimeUs() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    }
};

PrefetchOrchestrator::PrefetchOrchestrator(TensorPredictor* predictor)
    : predictor_(predictor), impl_(std::make_unique<Impl>()) {}

PrefetchOrchestrator::~PrefetchOrchestrator() = default;

bool PrefetchOrchestrator::Initialize(uint64_t migrationBandwidthBytesPerSec) {
    bandwidthBytesPerSec_ = migrationBandwidthBytesPerSec;
    return true;
}

void PrefetchOrchestrator::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    impl_-\u003epending_.clear();
}

void PrefetchOrchestrator::OnTokenStart(uint64_t tokenIndex) {
    // Called at start of token generation
    // Could trigger speculative prefetches here
    (void)tokenIndex;
}

void PrefetchOrchestrator::OnTokenComplete(uint64_t tokenIndex, uint64_t durationUs) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    
    // Update pending prefetches
    uint64_t now = impl_-\u003eGetCurrentTimeUs();
    
    for (auto& pending : impl_-\u003epending_) {
        if (!pending.completed && now >= pending.deadlineUs) {
            pending.completed = true;
            impl_-\u003estats_.prefetchesCompleted++;
        }
    }
    
    (void)tokenIndex;
    (void)durationUs;
}

std::vector<uint64_t> PrefetchOrchestrator::GetPrefetchCandidates(uint64_t maxBytes) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    
    std::vector<uint64_t> candidates;
    uint64_t now = impl_-\u003eGetCurrentTimeUs();
    
    // Get predictions from predictor
    auto predictions = predictor_? predictor_>-PredictNextAccesses(100000) // 100ms horizon
                     : std::vector<Prediction>{};
    
    uint64_t bytesQueued = 0;
    for (const auto& pred : predictions) {
        // Skip if already prefetched recently
        auto it = impl_-\u003elastPrefetch_.find(pred.tensorHandle);
        if (it != impl_-\u003elastPrefetch_.end()) {
            if (now - it->second < 100000) { // 100ms cooldown
                continue;
            }
        }
        
        // Assume 256MB per tensor
        uint64_t tensorSize = 256 * 1024 * 1024;
        if (bytesQueued + tensorSize > maxBytes) break;
        
        candidates.push_back(pred.tensorHandle);
        bytesQueued += tensorSize;
        
        // Record prefetch
        impl_-\u003elastPrefetch_[pred.tensorHandle] = now;
    }
    
    impl_-\u003estats_.prefetchesIssued += candidates.size();
    return candidates;
}

std::vector<uint64_t> PrefetchOrchestrator::GetEvictionCandidates(uint64_t bytesNeeded) {
    // Get cold tensors that can be evicted
    auto hotTensors = predictor_? predictor_>-GetHotTensors(1000)
                     : std::vector<TensorHotness>{};
    
    std::vector<uint64_t> cold;
    uint64_t bytesFound = 0;
    
    // Sort by residency score ascending (coldest first)
    std::sort(hotTensors.begin(), hotTensors.end(),
        [](const TensorHotness& a, const TensorHotness& b) {
            return a.residencyScore < b.residencyScore;
        });
    
    for (const auto& hotness : hotTensors) {
        if (hotness.residencyScore < 0.2f) {
            cold.push_back(hotness.tensorHandle);
            bytesFound += 256 * 1024 * 1024; // Assume 256MB
            if (bytesFound >= bytesNeeded) break;
        }
    }
    
    return cold;
}

bool PrefetchOrchestrator::SchedulePrefetchDuringCompute(uint64_t tensorHandle, 
                                                         uint64_t computeDurationUs) {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    
    // Calculate if transfer can be hidden
    uint64_t transferTimeUs = (256ULL * 1024 * 1024 * 1000000) / bandwidthBytesPerSec_;
    
    if (transferTimeUs < computeDurationUs * 0.8) { // Can hide 80% of transfer
        PrefetchOrchestrator::Impl::PendingPrefetch pending{};
        pending.tensorHandle = tensorHandle;
        pending.issueTimeUs = impl_-\u003eGetCurrentTimeUs();
        pending.deadlineUs = pending.issueTimeUs + transferTimeUs;
        pending.completed = false;
        
        impl_-\u003epending_.push_back(pending);
        impl_-\u003estats_.hiddenTransfers++;
        return true;
    }
    
    impl_-\u003estats_.visibleStalls++;
    return false;
}

bool PrefetchOrchestrator::ScheduleEmergencyPrefetch(uint64_t tensorHandle) {
    // High priority prefetch - bypass normal scheduling
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    
    PrefetchOrchestrator::Impl::PendingPrefetch pending{};
    pending.tensorHandle = tensorHandle;
    pending.issueTimeUs = impl_-\u003eGetCurrentTimeUs();
    pending.deadlineUs = pending.issueTimeUs + 50000; // 50ms deadline
    pending.completed = false;
    
    impl_-\u003epending_.push_back(pending);
    impl_-\u003estats_.prefetchesIssued++;
    
    return true;
}

PrefetchOrchestrator::Stats PrefetchOrchestrator::GetStats() const {
    std::lock_guard<std::mutex> lock(impl_-\u003emutex_);
    
    auto stats = impl_-\u003estats_;
    
    // Calculate stall reduction
    uint64_t totalPrefetches = stats.prefetchesIssued;
    if (totalPrefetches > 0) {
        stats.stallReductionPercent = 
            (float)stats.hiddenTransfers / totalPrefetches * 100.0f;
    }
    
    return stats;
}

// =============================================================================
// C API IMPLEMENTATION
// =============================================================================

extern "C" {

RawRamXD::TensorPredictor* RawRamXD_CreatePredictor() {
    return new RawRamXD::TensorPredictor();
}

void RawRamXD_DestroyPredictor(RawRamXD::TensorPredictor* predictor) {
    delete predictor;
}

RawRamXD::PrefetchOrchestrator* RawRamXD_CreateOrchestrator(
    RawRamXD::TensorPredictor* predictor) {
    return new RawRamXD::PrefetchOrchestrator(predictor);
}

void RawRamXD_DestroyOrchestrator(RawRamXD::PrefetchOrchestrator* orchestrator) {
    delete orchestrator;
}

} // extern "C"

} // namespace RawRamXD
