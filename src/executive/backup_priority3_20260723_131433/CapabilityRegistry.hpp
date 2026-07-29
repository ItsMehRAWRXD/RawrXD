// ============================================================================
// CapabilityRegistry.hpp - Dynamic Tool/Agent Registration
// Agents bid for tasks; planner scores and selects
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Executive {

// Forward declarations
class ExecutiveDirector;

// ============================================================================
// Capability Definition
// ============================================================================
struct Capability {
    std::string capabilityId;
    std::string name;
    std::string description;
    std::string domain;              // "reverse_engineering", "code_generation", etc.
    
    // Requirements
    std::vector<std::string> requiredInputs;
    std::vector<std::string> providedOutputs;
    
    // Performance metrics (updated over time)
    float successRate = 0.0f;
    double averageExecutionTimeMs = 0.0;
    size_t timesInvoked = 0;
    
    // Constraints
    size_t maxInputSize = 0;
    size_t maxOutputSize = 0;
    std::vector<std::string> supportedFormats;
    
    // Cost model
    float computeCost = 1.0f;        // Arbitrary units
    float memoryCost = 1.0f;
};

// ============================================================================
// Capability Provider (Agent or Tool)
// ============================================================================
struct CapabilityProvider {
    std::string providerId;
    std::string providerType;        // "agent", "tool", "function", "plugin"
    std::string name;
    std::string version;
    
    // What it can do
    std::vector<Capability> capabilities;
    
    // Current state
    bool isAvailable = true;
    int currentLoad = 0;
    int maxConcurrent = 1;
    
    // Invocation
    std::function<bool(const std::unordered_map<std::string, std::string>& inputs,
                       std::unordered_map<std::string, std::string>& outputs)> invoke;
};

// ============================================================================
// Task Requirement
// ============================================================================
struct TaskRequirement {
    std::string requiredCapability;
    std::unordered_map<std::string, std::string> inputs;
    float minSuccessRate = 0.0f;
    double maxExecutionTimeMs = 0.0;  // 0 = no limit
    float maxComputeCost = 0.0f;      // 0 = no limit
};

// ============================================================================
// Bid from a provider for a task
// ============================================================================
struct CapabilityBid {
    std::string providerId;
    std::string capabilityId;
    float confidence = 0.0f;         // How confident they are they can do it
    float estimatedCost = 0.0f;
    double estimatedTimeMs = 0.0;
    std::string explanation;           // Why they think they're good for this
};

// ============================================================================
// Selection Result
// ============================================================================
struct CapabilitySelection {
    std::string providerId;
    std::string capabilityId;
    float score = 0.0f;
    std::vector<CapabilityBid> allBids;
    std::string selectionReason;
};

// ============================================================================
// Capability Registry - Dynamic Tool/Agent Registration System
// ============================================================================
class CapabilityRegistry {
public:
    CapabilityRegistry();
    ~CapabilityRegistry();

    bool Initialize(ExecutiveDirector* director);
    void Shutdown();
    
    // Registration
    std::string RegisterProvider(const CapabilityProvider& provider);
    void UnregisterProvider(const std::string& providerId);
    void UpdateProviderCapabilities(const std::string& providerId, const std::vector<Capability>& capabilities);
    
    // Discovery
    std::vector<CapabilityProvider> FindProvidersForCapability(const std::string& capabilityName);
    std::vector<CapabilityProvider> FindProvidersForDomain(const std::string& domain);
    std::optional<CapabilityProvider> GetProvider(const std::string& providerId);
    std::vector<std::string> GetAllCapabilityNames();
    std::vector<std::string> GetAllDomains();
    
    // Bidding system
    std::vector<CapabilityBid> RequestBids(const TaskRequirement& task);
    CapabilitySelection SelectBestProvider(const TaskRequirement& task, 
                                            const std::vector<CapabilityBid>& bids);
    
    // Scoring functions
    void SetScoringWeights(float successWeight, float speedWeight, float costWeight);
    float ScoreBid(const CapabilityBid& bid, const TaskRequirement& task);
    
    // Invocation
    bool InvokeProvider(const std::string& providerId, 
                        const std::unordered_map<std::string, std::string>& inputs,
                        std::unordered_map<std::string, std::string>& outputs);
    
    // Performance tracking
    void RecordSuccess(const std::string& providerId, double executionTimeMs);
    void RecordFailure(const std::string& providerId, const std::string& reason);
    
    // Plugin loading
    bool LoadPlugin(const std::string& pluginPath);
    void UnloadPlugin(const std::string& pluginId);
    std::vector<std::string> GetLoadedPlugins();
    
    // Statistics
    struct Stats {
        size_t registeredProviders = 0;
        size_t totalCapabilities = 0;
        size_t totalInvocations = 0;
        size_t successfulInvocations = 0;
        double averageSelectionTimeMs = 0.0;
    };
    Stats GetStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace Executive
} // namespace RawrXD
