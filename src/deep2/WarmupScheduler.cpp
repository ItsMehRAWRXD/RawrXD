// ============================================================================
// WarmupScheduler.cpp - Predictive Expert Prefetch Implementation
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 3
// ============================================================================

#include "WarmupScheduler.hpp"
#include <algorithm>

namespace Deep2 {

WarmupScheduler::WarmupScheduler() {}
WarmupScheduler::~WarmupScheduler() {}

bool WarmupScheduler::initialize(const WarmupConfig& config) {
    config_ = config;
    stats_ = WarmupStats{};
    accessHistory_.clear();
    transitionCounts_.clear();
    totalTransitions_.clear();
    lastExpert_.clear();
    pendingPrefetches_.clear();

    printf("[WarmupScheduler] Initialized: depth=%zu, history=%zu, threshold=%.2f\n",
           config.prefetchDepth, config.historyWindow, config.prefetchThreshold);
    return true;
}

void WarmupScheduler::recordAccess(int layerId, int expertId, float routingWeight) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now().time_since_epoch().count();

    // Record access
    ExpertAccess access{layerId, expertId, (uint64_t)now, routingWeight};
    accessHistory_[layerId].push_back(access);

    // Trim history
    if (accessHistory_[layerId].size() > config_.historyWindow) {
        accessHistory_[layerId].erase(accessHistory_[layerId].begin());
    }

    // Update transition matrix
    auto it = lastExpert_.find(layerId);
    if (it != lastExpert_.end()) {
        updateTransition(layerId, it->second, expertId);
    }
    lastExpert_[layerId] = expertId;
}

void WarmupScheduler::updateTransition(int layerId, int fromExpert, int toExpert) {
    transitionCounts_[layerId][fromExpert * config_.transitionMatrixSize + toExpert]++;
    totalTransitions_[layerId]++;
}

float WarmupScheduler::getTransitionProbability(int layerId, int fromExpert, int toExpert) {
    auto layerIt = transitionCounts_.find(layerId);
    if (layerIt == transitionCounts_.end()) return 0.0f;

    auto totalIt = totalTransitions_.find(layerId);
    if (totalIt == totalTransitions_.end() || totalIt->second == 0) return 0.0f;

    auto transIt = layerIt->second.find(fromExpert * config_.transitionMatrixSize + toExpert);
    if (transIt == layerIt->second.end()) return 0.0f;

    return (float)transIt->second / (float)totalIt->second;
}

std::vector<WarmupPrefetchRequest> WarmupScheduler::predictNextExperts(int layerId, int currentExpert) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<WarmupPrefetchRequest> predictions;

    if (currentExpert < 0) {
        auto it = lastExpert_.find(layerId);
        if (it != lastExpert_.end()) {
            currentExpert = it->second;
        } else {
            // No history - use frequency-based prediction
            auto histIt = accessHistory_.find(layerId);
            if (histIt == accessHistory_.end()) return predictions;

            // Count expert frequencies
            std::unordered_map<int, uint64_t> freq;
            for (const auto& a : histIt->second) {
                freq[a.expertId]++;
            }

            // Sort by frequency
            std::vector<std::pair<int, uint64_t>> sortedFreq(freq.begin(), freq.end());
            std::partial_sort(sortedFreq.begin(),
                              sortedFreq.begin() + std::min(config_.prefetchDepth, sortedFreq.size()),
                              sortedFreq.end(),
                              [](const auto& a, const auto& b) { return a.second > b.second; });

            for (size_t i = 0; i < std::min(config_.prefetchDepth, sortedFreq.size()); i++) {
                float prob = (float)sortedFreq[i].second / histIt->second.size();
                if (prob >= config_.prefetchThreshold) {
                    predictions.push_back({layerId, sortedFreq[i].first, prob, (int)i});
                }
            }
            return predictions;
        }
    }

    // Transition-based prediction
    auto layerIt = transitionCounts_.find(layerId);
    if (layerIt == transitionCounts_.end()) return predictions;

    // Find all transitions from currentExpert
    std::vector<std::pair<int, float>> candidates;
    for (int e = 0; e < (int)config_.transitionMatrixSize; e++) {
        float prob = getTransitionProbability(layerId, currentExpert, e);
        if (prob >= config_.prefetchThreshold) {
            candidates.push_back({e, prob});
        }
    }

    // Sort by probability
    std::partial_sort(candidates.begin(),
                      candidates.begin() + std::min(config_.prefetchDepth, candidates.size()),
                      candidates.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });

    for (size_t i = 0; i < std::min(config_.prefetchDepth, candidates.size()); i++) {
        predictions.push_back({layerId, candidates[i].first, candidates[i].second, (int)i});
    }

    return predictions;
}

std::vector<WarmupPrefetchRequest> WarmupScheduler::getPrefetchRequests() {
    std::vector<WarmupPrefetchRequest> allRequests;

    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& [layerId, _] : accessHistory_) {
        auto preds = predictNextExperts(layerId);
        allRequests.insert(allRequests.end(), preds.begin(), preds.end());
    }

    // Track pending prefetches
    pendingPrefetches_.clear();
    for (const auto& req : allRequests) {
        pendingPrefetches_.push_back({req.layerId, req.expertId});
    }

    return allRequests;
}

void WarmupScheduler::markPrefetchHit(int layerId, int expertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.updatePrefetch(true);

    // Remove from pending
    auto it = std::find(pendingPrefetches_.begin(), pendingPrefetches_.end(),
                        std::make_pair(layerId, expertId));
    if (it != pendingPrefetches_.end()) {
        pendingPrefetches_.erase(it);
    }
}

void WarmupScheduler::markPrefetchWasted(int layerId, int expertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.updatePrefetch(false);
}

void WarmupScheduler::warmPageCache(const uint8_t* expertData, size_t sizeBytes) {
    if (!config_.enableSequentialPrefetch || !expertData || sizeBytes == 0) return;

    // Touch pages to warm the OS page cache
    // Read one byte per page to trigger page-in
    size_t pageSize = config_.sequentialReadSize;
    volatile uint8_t dummy = 0;
    for (size_t offset = 0; offset < sizeBytes; offset += pageSize) {
        dummy = expertData[offset];
    }
    (void)dummy;
}

void WarmupScheduler::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    accessHistory_.clear();
    transitionCounts_.clear();
    totalTransitions_.clear();
    lastExpert_.clear();
    pendingPrefetches_.clear();
    stats_ = WarmupStats{};
}

} // namespace Deep2
