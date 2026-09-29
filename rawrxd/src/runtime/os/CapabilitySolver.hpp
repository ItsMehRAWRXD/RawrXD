// ============================================================================
// CapabilitySolver.hpp — Resolve intent → required capabilities → available
// capabilities → negotiation → composition → execution plan
// ============================================================================
#pragma once
#include "UniversalGraph.hpp"
#include <string>
#include <vector>
#include <optional>

namespace rawrxd::graph {

// ---------------------------------------------------------------------------
// Intent — what the user/runtime wants to accomplish
// ---------------------------------------------------------------------------
struct Intent {
    std::string description;        // Human-readable
    std::string category;           // "inference", "build", "edit", "certify"
    std::vector<std::string> requiredCapabilities;  // capability names needed
    std::vector<std::string> preferredProviders;    // preferred subsystems
    std::unordered_map<std::string, std::string> constraints;  // key=value constraints
};

// ---------------------------------------------------------------------------
// Capability descriptor — what a registered capability offers
// ---------------------------------------------------------------------------
struct CapabilityDescriptor {
    std::string name;
    std::string provider;           // which subsystem provides this
    std::vector<std::string> provides;  // what this capability produces
    std::vector<std::string> requires;  // what this capability needs
    int priority = 0;               // higher = preferred
    bool available = true;
    std::string version;
};

// ---------------------------------------------------------------------------
// Execution plan — the result of solving
// ---------------------------------------------------------------------------
struct ExecutionStep {
    std::string capability;
    std::string provider;
    std::vector<std::string> inputs;
    std::vector<std::string> outputs;
    std::vector<size_t> dependsOn;  // indices into the plan
};

struct ExecutionPlan {
    std::vector<ExecutionStep> steps;
    bool valid = false;
    std::string failureReason;
    int totalSteps() const { return static_cast<int>(steps.size()); }
};

// ---------------------------------------------------------------------------
// Capability Solver — the handwritten negotiation + composition engine
// ---------------------------------------------------------------------------
class CapabilitySolver {
public:
    // Register a capability descriptor
    void registerCapability(CapabilityDescriptor desc);

    // Clear all registered capabilities
    void clear();

    // Solve: given an intent, produce an execution plan
    // Fail-closed: returns invalid plan if any required capability is missing
    ExecutionPlan solve(const Intent& intent) const;

    // List all registered capabilities
    std::vector<CapabilityDescriptor> capabilities() const;

    // Query: which capabilities provide a given output?
    std::vector<CapabilityDescriptor> findProviders(const std::string& output) const;

    // Query: which capabilities does a provider offer?
    std::vector<CapabilityDescriptor> fromProvider(const std::string& provider) const;

private:
    std::vector<CapabilityDescriptor> caps_;

    // Check if a capability's requirements are satisfied by available outputs
    bool requirementsMet(const CapabilityDescriptor& cap,
                         const std::set<std::string>& availableOutputs) const;

    // Topologically order the selected capabilities
    bool orderSteps(std::vector<CapabilityDescriptor>& selected,
                    ExecutionPlan& plan) const;
};

} // namespace rawrxd::graph