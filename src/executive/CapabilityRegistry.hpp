// ============================================================
// CapabilityRegistry.hpp - Dynamic Tool/Agent Registration
// Agents bid for tasks; planner scores and selects
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <optional>
#include <mutex>
#include <atomic>

namespace RawrXD::Executive {

class ExecutiveDirector;

// ============================================================
// Capability Definition
// ============================================================
struct Capability {
    uint64_t id;
    std::string name;
    std::string description;
    std::string domain;
    
    std::vector<std::string> requiredInputs;
    std::vector<std::string> providedOutputs;
    
    float successRate = 0.0f;
    double averageExecutionTimeMs = 0.0;
    size_t timesInvoked = 0;
    
    size_t maxInputSize = 0;
    size_t maxOutputSize = 0;
    std::vector<std::string> supportedFormats;
    
    float computeCost = 1.0f;
    float memoryCost = 1.0f;
};

// ============================================================
// Capability Provider
// ============================================================
struct CapabilityProvider {
    uint64_t providerId;
    std::string providerType;
    std::string name;
    std::string version;
    std::vector<Capability> capabilities;
    
    bool isAvailable = true;
    int currentLoad = 0;
    int maxConcurrent = 1;
    
    std::function<bool(const std::unordered_map<std::string, std::string>& inputs,
                       std::unordered_map<std::string, std::string>& outputs)> invoke;
};

// ============================================================
// Task Requirement
// ============================================================
struct TaskRequirement {
    std::string requiredCapability;
    std::unordered_map<std::string, std::string> inputs;
    float minSuccessRate = 0.0f;
    double maxExecutionTimeMs = 0.0;
    float maxComputeCost = 0.0f;
};

// ============================================================
// Bid
// ============================================================
struct CapabilityBid {
    uint64_t providerId;
    uint64_t capabilityId;
    float confidence = 0.0f;
    float estimatedCost = 0.0f;
    double estimatedTimeMs = 0.0;
    std::string explanation;
};

// ============================================================
// Selection Result
// ============================================================
struct CapabilitySelection {
    uint64_t providerId;
    uint64_t capabilityId;
    float score = 0.0f;
    std::string reasoning;
};

// ============================================================
// Capability Registry
// ============================================================
class CapabilityRegistry {
public:
    CapabilityRegistry() = default;
    ~CapabilityRegistry() = default;

    bool initialize(ExecutiveDirector* director);
    void shutdown();
    
    uint64_t registerProvider(const CapabilityProvider& provider);
    void unregisterProvider(uint64_t providerId);
    
    std::vector<CapabilityProvider> findProvidersForCapability(const std::string& capabilityName);
    std::vector<CapabilityBid> requestBids(const TaskRequirement& task);
    CapabilitySelection selectBestProvider(const TaskRequirement& task, 
                                            const std::vector<CapabilityBid>& bids);
    
    void setScoringWeights(float successWeight, float speedWeight, float costWeight);
    float scoreBid(const CapabilityBid& bid, const TaskRequirement& task);
    
    bool invokeProvider(uint64_t providerId, 
                        const std::unordered_map<std::string, std::string>& inputs,
                        std::unordered_map<std::string, std::string>& outputs);
    
    void recordSuccess(uint64_t providerId, double executionTimeMs);
    void recordFailure(uint64_t providerId, const std::string& reason);
    
    bool loadPlugin(const std::string& pluginPath);
    void unloadPlugin(uint64_t pluginId);
    
    struct Stats {
        size_t registeredProviders = 0;
        size_t totalInvocations = 0;
        size_t successfulInvocations = 0;
    };
    Stats getStats() const;

private:
    ExecutiveDirector* director_ = nullptr;
    std::unordered_map<uint64_t, CapabilityProvider> providers_;
    std::unordered_map<uint64_t, Capability> capabilities_;
    
    float successWeight_ = 0.4f;
    float speedWeight_ = 0.3f;
    float costWeight_ = 0.3f;
    
    std::atomic<size_t> totalInvocations_{0};
    std::atomic<size_t> successfulInvocations_{0};
    std::atomic<uint64_t> nextProviderId_{1};
    std::atomic<uint64_t> nextCapabilityId_{1};
    
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Executive
