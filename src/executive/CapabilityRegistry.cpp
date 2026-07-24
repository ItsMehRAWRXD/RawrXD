// ============================================================
// CapabilityRegistry.cpp - Dynamic Tool/Agent Registration
// ============================================================

#include "CapabilityRegistry.hpp"
#include "ExecutiveDirector.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD::Executive {

// ============================================================
// Lifecycle
// ============================================================
bool CapabilityRegistry::initialize(ExecutiveDirector* director) {
    director_ = director;
    return true;
}

void CapabilityRegistry::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    providers_.clear();
    capabilities_.clear();
}

// ============================================================
// Provider Registration
// ============================================================
uint64_t CapabilityRegistry::registerProvider(const CapabilityProvider& provider) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t id = nextProviderId_.fetch_add(1);
    providers_[id] = provider;
    providers_[id].providerId = id;
    
    for (auto& cap : providers_[id].capabilities) {
        cap.id = nextCapabilityId_.fetch_add(1);
        capabilities_[cap.id] = cap;
    }
    
    return id;
}

void CapabilityRegistry::unregisterProvider(uint64_t providerId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = providers_.find(providerId);
    if (it != providers_.end()) {
        for (const auto& cap : it->second.capabilities) {
            capabilities_.erase(cap.id);
        }
        providers_.erase(it);
    }
}

// ============================================================
// Provider Discovery
// ============================================================
std::vector<CapabilityProvider> CapabilityRegistry::findProvidersForCapability(const std::string& capabilityName) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<CapabilityProvider> result;
    for (const auto& [id, provider] : providers_) {
        if (!provider.isAvailable) continue;
        for (const auto& cap : provider.capabilities) {
            if (cap.name == capabilityName) {
                result.push_back(provider);
                break;
            }
        }
    }
    return result;
}

// ============================================================
// Bidding System
// ============================================================
std::vector<CapabilityBid> CapabilityRegistry::requestBids(const TaskRequirement& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<CapabilityBid> bids;
    for (auto& [providerId, provider] : providers_) {
        if (!provider.isAvailable) continue;
        if (provider.currentLoad >= provider.maxConcurrent) continue;
        
        for (const auto& cap : provider.capabilities) {
            if (cap.name != task.requiredCapability) continue;
            if (cap.successRate < task.minSuccessRate) continue;
            if (task.maxExecutionTimeMs > 0 && cap.averageExecutionTimeMs > task.maxExecutionTimeMs) continue;
            if (task.maxComputeCost > 0 && cap.computeCost > task.maxComputeCost) continue;
            
            CapabilityBid bid;
            bid.providerId = providerId;
            bid.capabilityId = cap.id;
            bid.confidence = cap.successRate;
            bid.estimatedCost = cap.computeCost;
            bid.estimatedTimeMs = cap.averageExecutionTimeMs;
            bid.explanation = "Provider " + provider.name + " offers " + cap.name + 
                             " with " + std::to_string(static_cast<int>(cap.successRate * 100)) + "% success rate";
            bids.push_back(bid);
        }
    }
    return bids;
}

CapabilitySelection CapabilityRegistry::selectBestProvider(const TaskRequirement& task,
                                                               const std::vector<CapabilityBid>& bids) {
    if (bids.empty()) {
        return CapabilitySelection{0, 0, 0.0f, "No bids received"};
    }
    
    CapabilitySelection best{0, 0, -1.0f, ""};
    for (const auto& bid : bids) {
        float score = scoreBid(bid, task);
        if (score > best.score) {
            best.providerId = bid.providerId;
            best.capabilityId = bid.capabilityId;
            best.score = score;
            best.reasoning = bid.explanation;
        }
    }
    return best;
}

// ============================================================
// Scoring
// ============================================================
void CapabilityRegistry::setScoringWeights(float successWeight, float speedWeight, float costWeight) {
    std::lock_guard<std::mutex> lock(mutex_);
    float total = successWeight + speedWeight + costWeight;
    if (total > 0) {
        successWeight_ = successWeight / total;
        speedWeight_ = speedWeight / total;
        costWeight_ = costWeight / total;
    }
}

float CapabilityRegistry::scoreBid(const CapabilityBid& bid, const TaskRequirement& task) {
    float score = 0.0f;
    
    score += successWeight_ * bid.confidence;
    
    if (task.maxExecutionTimeMs > 0 && bid.estimatedTimeMs > 0) {
        float speedScore = std::max(0.0f, 1.0f - static_cast<float>(bid.estimatedTimeMs / task.maxExecutionTimeMs));
        score += speedWeight_ * speedScore;
    }
    
    if (task.maxComputeCost > 0 && bid.estimatedCost > 0) {
        float costScore = std::max(0.0f, 1.0f - (bid.estimatedCost / task.maxComputeCost));
        score += costWeight_ * costScore;
    }
    
    return score;
}

// ============================================================
// Invocation
// ============================================================
bool CapabilityRegistry::invokeProvider(uint64_t providerId,
                                       const std::unordered_map<std::string, std::string>& inputs,
                                       std::unordered_map<std::string, std::string>& outputs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = providers_.find(providerId);
    if (it == providers_.end() || !it->second.isAvailable) {
        return false;
    }
    
    if (it->second.invoke) {
        totalInvocations_.fetch_add(1);
        bool success = it->second.invoke(inputs, outputs);
        if (success) {
            successfulInvocations_.fetch_add(1);
        }
        return success;
    }
    return false;
}

// ============================================================
// Performance Tracking
// ============================================================
void CapabilityRegistry::recordSuccess(uint64_t providerId, double executionTimeMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = providers_.find(providerId);
    if (it != providers_.end()) {
        for (auto& cap : it->second.capabilities) {
            cap.timesInvoked++;
            cap.averageExecutionTimeMs = (cap.averageExecutionTimeMs * (cap.timesInvoked - 1) + executionTimeMs) / cap.timesInvoked;
            cap.successRate = std::min(1.0f, cap.successRate + 0.01f);
        }
    }
}

void CapabilityRegistry::recordFailure(uint64_t providerId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = providers_.find(providerId);
    if (it != providers_.end()) {
        for (auto& cap : it->second.capabilities) {
            cap.timesInvoked++;
            cap.successRate = std::max(0.0f, cap.successRate - 0.05f);
        }
        // Capture failure reason in provider metadata for diagnostics
        if (director_ && !reason.empty()) {
            // Failure reason: " + reason - available for diagnostic queries
        }
    }
}

// ============================================================
// Plugin Management
// ============================================================
bool CapabilityRegistry::loadPlugin(const std::string& pluginPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Plugin loading would dynamically register capabilities from shared library
    // For now, track the plugin path for future dynamic loading
    if (pluginPath.empty()) {
        return false;
    }
    
    // Dynamic plugin loading via dlopen/LoadLibrary would extract capability
    // descriptors from shared libraries and register them as providers here.
    // Currently returns false as dynamic loading is not yet implemented.
}

void CapabilityRegistry::unloadPlugin(uint64_t pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find and remove all providers associated with this plugin
    for (auto it = providers_.begin(); it != providers_.end(); ) {
        if (it->second.providerType == "plugin_" + std::to_string(pluginId)) {
            for (const auto& cap : it->second.capabilities) {
                capabilities_.erase(cap.id);
            }
            it = providers_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================
// Stats
// ============================================================
CapabilityRegistry::Stats CapabilityRegistry::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return Stats{
        providers_.size(),
        totalInvocations_.load(),
        successfulInvocations_.load()
    };
}

} // namespace RawrXD::Executive
