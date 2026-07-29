// ============================================================================
// CapabilityRegistry.cpp - Implementation
// ============================================================================

#include "CapabilityRegistry.hpp"

namespace RawrXD {
namespace Executive {

struct CapabilityRegistry::Impl {
    std::unordered_map<std::string, CapabilityProvider> providers;
    std::unordered_map<std::string, Capability> capabilities;
    float successWeight = 0.4f;
    float speedWeight = 0.3f;
    float costWeight = 0.3f;
    size_t totalInvocations = 0;
    size_t successfulInvocations = 0;
};

CapabilityRegistry::CapabilityRegistry() : pImpl_(std::make_unique<Impl>()) {}
CapabilityRegistry::~CapabilityRegistry() = default;

bool CapabilityRegistry::Initialize(ExecutiveDirector* director) { return true; }
void CapabilityRegistry::Shutdown() {}

std::string CapabilityRegistry::RegisterProvider(const CapabilityProvider& provider) {
    pImpl_->providers[provider.providerId] = provider;
    return provider.providerId;
}

void CapabilityRegistry::UnregisterProvider(const std::string& providerId) {
    pImpl_->providers.erase(providerId);
}

std::vector<CapabilityProvider> CapabilityRegistry::FindProvidersForCapability(const std::string& capabilityName) {
    std::vector<CapabilityProvider> results;
    for (const auto& [id, provider] : pImpl_->providers) {
        for (const auto& cap : provider.capabilities) {
            if (cap.name == capabilityName) {
                results.push_back(provider);
                break;
            }
        }
    }
    return results;
}

std::vector<CapabilityBid> CapabilityRegistry::RequestBids(const TaskRequirement& task) {
    return {};  // Stub
}

CapabilitySelection CapabilityRegistry::SelectBestProvider(const TaskRequirement& task, 
                                                              const std::vector<CapabilityBid>& bids) {
    CapabilitySelection selection;
    if (!bids.empty()) {
        selection.providerId = bids[0].providerId;
        selection.capabilityId = bids[0].capabilityId;
        selection.score = bids[0].confidence;
    }
    return selection;
}

void CapabilityRegistry::SetScoringWeights(float successWeight, float speedWeight, float costWeight) {
    pImpl_->successWeight = successWeight;
    pImpl_->speedWeight = speedWeight;
    pImpl_->costWeight = costWeight;
}

float CapabilityRegistry::ScoreBid(const CapabilityBid& bid, const TaskRequirement& task) {
    return bid.confidence;
}

bool CapabilityRegistry::InvokeProvider(const std::string& providerId, 
                                          const std::unordered_map<std::string, std::string>& inputs,
                                          std::unordered_map<std::string, std::string>& outputs) {
    auto it = pImpl_->providers.find(providerId);
    if (it != pImpl_->providers.end() && it->second.invoke) {
        pImpl_->totalInvocations++;
        bool success = it->second.invoke(inputs, outputs);
        if (success) pImpl_->successfulInvocations++;
        return success;
    }
    return false;
}

void CapabilityRegistry::RecordSuccess(const std::string& providerId, double executionTimeMs) {}
void CapabilityRegistry::RecordFailure(const std::string& providerId, const std::string& reason) {}
bool CapabilityRegistry::LoadPlugin(const std::string& pluginPath) { return true; }
void CapabilityRegistry::UnloadPlugin(const std::string& pluginId) {}

CapabilityRegistry::Stats CapabilityRegistry::GetStats() const {
    Stats s;
    s.registeredProviders = pImpl_->providers.size();
    s.totalInvocations = pImpl_->totalInvocations;
    s.successfulInvocations = pImpl_->successfulInvocations;
    return s;
}

} // namespace Executive
} // namespace RawrXD
