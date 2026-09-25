// ============================================================================
// StreamRouter.cpp — Per-layer streaming router with prefetch / eviction
// ============================================================================
#include "StreamRouter.h"
#include "VramStreamingController.hpp"
#include "StreamEngine.h"
#include "ElasticResidencyManager.hpp"
#include <cstdio>

namespace Deep2 {

StreamRouter::StreamRouter() = default;
StreamRouter::~StreamRouter() = default;

void StreamRouter::initialize(VramStreamingController* controller,
                               StreamEngine* engine,
                               ElasticResidencyManager* elasticMgr) {
    controller_ = controller;
    engine_     = engine;
    elasticMgr_ = elasticMgr;
}

StreamRouterPlan StreamRouter::planForLayer(uint32_t layer,
                                             const std::vector<std::string>& neededTensors) {
    StreamRouterPlan plan;
    if (!controller_) return plan;

    {
        std::lock_guard<std::mutex> lock(mtx_);
        layerTensorMap_[layer] = neededTensors;
    }

    // Prefetch tensors for this layer that are not yet resident
    for (const auto& name : neededTensors) {
        if (!controller_->isResident(name)) {
            plan.prefetch.push_back(name);
        }
    }

    // Lookahead: prefetch next N layers if enabled
    if (cfg_.lookaheadLayers > 0) {
        for (uint32_t la = 1; la <= cfg_.lookaheadLayers; ++la) {
            uint32_t nextLayer = layer + la;
            std::lock_guard<std::mutex> lock(mtx_);
            auto it = layerTensorMap_.find(nextLayer);
            if (it != layerTensorMap_.end()) {
                for (const auto& name : it->second) {
                    if (!controller_->isResident(name)) {
                        plan.prefetch.push_back(name);
                    }
                }
            }
        }
    }

    // Eviction: if enabled, evict tensors from layers far behind
    if (cfg_.enableEviction && layer > cfg_.lookaheadLayers + 1) {
        uint32_t evictUpTo = layer - cfg_.lookaheadLayers - 1;
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = layerTensorMap_.begin(); it != layerTensorMap_.end(); ++it) {
            if (it->first <= evictUpTo) {
                for (const auto& name : it->second) {
                    if (controller_->isResident(name)) {
                        plan.evict.push_back(name);
                    }
                }
            }
        }
    }

    // Deduplicate
    {
        std::vector<std::string> uniq;
        uniq.reserve(plan.prefetch.size());
        std::unordered_map<std::string, bool> seen;
        for (const auto& n : plan.prefetch) {
            if (!seen[n]) { seen[n] = true; uniq.push_back(n); }
        }
        plan.prefetch.swap(uniq);
    }
    {
        std::vector<std::string> uniq;
        uniq.reserve(plan.evict.size());
        std::unordered_map<std::string, bool> seen;
        for (const auto& n : plan.evict) {
            if (!seen[n]) { seen[n] = true; uniq.push_back(n); }
        }
        plan.evict.swap(uniq);
    }

    return plan;
}

bool StreamRouter::executePlan(const StreamRouterPlan& plan) {
    if (!controller_ || !engine_) return false;

    // Note: actual prefetch requires file offsets / buffers from the caller.
    // This method marks logical residency requests and triggers evictions.
    bool ok = true;
    for (const auto& name : plan.prefetch) {
        if (!controller_->requestResident(name)) {
            ok = false;
        }
    }
    for (const auto& name : plan.evict) {
        controller_->isResident(name);
        // Actual eviction is deferred to the controller's budget enforcement.
    }
    return ok;
}

void StreamRouter::onLayerComplete(uint32_t layer, uint64_t tokenIndex) {
    (void)layer;
    (void)tokenIndex;
    // Future: trigger background prefetch for next layers here.
}

void StreamRouter::setLookaheadLayers(uint32_t n) {
    std::lock_guard<std::mutex> lock(mtx_);
    cfg_.lookaheadLayers = n;
}

uint32_t StreamRouter::lookaheadLayers() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return cfg_.lookaheadLayers;
}

void StreamRouter::setConfig(const StreamRouterConfig& cfg) {
    std::lock_guard<std::mutex> lock(mtx_);
    cfg_ = cfg;
}

const StreamRouterConfig& StreamRouter::config() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return cfg_;
}

} // namespace Deep2

