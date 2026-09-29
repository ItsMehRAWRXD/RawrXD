// ============================================================================
// CapabilitySolver.cpp — Handwritten capability negotiation + composition
// ============================================================================
#include "CapabilitySolver.hpp"
#include <algorithm>
#include <set>

namespace rawrxd::graph {

void CapabilitySolver::registerCapability(CapabilityDescriptor desc) {
    caps_.push_back(std::move(desc));
}

void CapabilitySolver::clear() { caps_.clear(); }

std::vector<CapabilityDescriptor> CapabilitySolver::capabilities() const {
    return caps_;
}

std::vector<CapabilityDescriptor> CapabilitySolver::findProviders(const std::string& output) const {
    std::vector<CapabilityDescriptor> result;
    for (const auto& c : caps_) {
        for (const auto& p : c.provides) {
            if (p == output && c.available) {
                result.push_back(c);
                break;
            }
        }
    }
    // Sort by priority (highest first)
    std::sort(result.begin(), result.end(),
              [](const CapabilityDescriptor& a, const CapabilityDescriptor& b) {
                  return a.priority > b.priority;
              });
    return result;
}

std::vector<CapabilityDescriptor> CapabilitySolver::fromProvider(const std::string& provider) const {
    std::vector<CapabilityDescriptor> result;
    for (const auto& c : caps_) {
        if (c.provider == provider) result.push_back(c);
    }
    return result;
}

bool CapabilitySolver::requirementsMet(const CapabilityDescriptor& cap,
                                       const std::set<std::string>& availableOutputs) const {
    for (const auto& req : cap.requires) {
        if (availableOutputs.find(req) == availableOutputs.end()) return false;
    }
    return true;
}

bool CapabilitySolver::orderSteps(std::vector<CapabilityDescriptor>& selected,
                                  ExecutionPlan& plan) const {
    // Build dependency graph and topologically sort
    // A capability depends on another if it requires something the other provides
    std::set<std::string> satisfied;
    std::vector<bool> used(selected.size(), false);

    // Seed with capabilities that have no requirements
    for (int iter = 0; iter < static_cast<int>(selected.size()) * 2; ++iter) {
        bool progress = false;
        for (size_t i = 0; i < selected.size(); ++i) {
            if (used[i]) continue;
            if (requirementsMet(selected[i], satisfied)) {
                ExecutionStep step;
                step.capability = selected[i].name;
                step.provider = selected[i].provider;
                for (const auto& r : selected[i].requires) step.inputs.push_back(r);
                for (const auto& p : selected[i].provides) step.outputs.push_back(p);
                // Set dependencies: which steps this depends on
                for (size_t j = 0; j < plan.steps.size(); ++j) {
                    for (const auto& out : plan.steps[j].outputs) {
                        for (const auto& in : step.inputs) {
                            if (out == in) {
                                step.dependsOn.push_back(j);
                                break;
                            }
                        }
                    }
                }
                plan.steps.push_back(step);
                for (const auto& p : selected[i].provides) satisfied.insert(p);
                used[i] = true;
                progress = true;
            }
        }
        if (!progress) break;
    }

    // Check all were placed
    for (size_t i = 0; i < selected.size(); ++i) {
        if (!used[i]) {
            plan.valid = false;
            plan.failureReason = "Cannot satisfy requirements for: " + selected[i].name;
            return false;
        }
    }
    plan.valid = true;
    return true;
}

ExecutionPlan CapabilitySolver::solve(const Intent& intent) const {
    ExecutionPlan plan;
    plan.valid = false;

    // Phase 1: Find capabilities that provide each required output
    std::vector<CapabilityDescriptor> selected;
    std::set<std::string> provided;
    std::set<std::string> needed(intent.requiredCapabilities.begin(),
                                  intent.requiredCapabilities.end());

    // Iteratively resolve dependencies
    for (int iter = 0; iter < 20; ++iter) {
        bool progress = false;
        for (const auto& cap : caps_) {
            if (!cap.available) continue;
            // Does this capability provide something we need?
            for (const auto& p : cap.provides) {
                if (needed.count(p) && !provided.count(p)) {
                    selected.push_back(cap);
                    for (const auto& pp : cap.provides) provided.insert(pp);
                    for (const auto& rr : cap.requires) needed.insert(rr);
                    progress = true;
                    break;
                }
            }
        }
        if (!progress) break;
    }

    // Check all needs are satisfied
    for (const auto& n : needed) {
        if (!provided.count(n)) {
            plan.valid = false;
            plan.failureReason = "Unsatisfied capability requirement: " + n;
            return plan;
        }
    }

    // Phase 2: Order into execution plan
    orderSteps(selected, plan);
    return plan;
}

} // namespace rawrxd::graph