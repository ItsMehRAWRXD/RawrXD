// ============================================================================
// WorldModel.cpp - Implementation
// ============================================================================

#include "WorldModel.hpp"

namespace RawrXD {
namespace Executive {

struct WorldModel::Impl {
    CognitiveMemory* memory = nullptr;
    std::unordered_map<std::string, Belief> beliefs;
    std::unordered_map<std::string, Evidence> evidence;
    std::unordered_map<std::string, InferenceRule> inferenceRules;
    std::unordered_map<std::string, Hypothesis> hypotheses;
};

WorldModel::WorldModel() : pImpl_(std::make_unique<Impl>()) {}
WorldModel::~WorldModel() = default;

bool WorldModel::Initialize(CognitiveMemory* memory) {
    pImpl_->memory = memory;
    return true;
}

void WorldModel::Shutdown() {}

std::string WorldModel::AddBelief(const Belief& belief) {
    pImpl_->beliefs[belief.beliefId] = belief;
    return belief.beliefId;
}

void WorldModel::UpdateBeliefConfidence(const std::string& beliefId, float newConfidence, 
                                         const std::string& evidenceId) {
    auto it = pImpl_->beliefs.find(beliefId);
    if (it != pImpl_->beliefs.end()) {
        it->second.priorConfidence = it->second.confidence;
        it->second.confidence = newConfidence;
        it->second.supportingEvidence.push_back(evidenceId);
    }
}

std::optional<Belief> WorldModel::GetBelief(const std::string& beliefId) {
    auto it = pImpl_->beliefs.find(beliefId);
    if (it != pImpl_->beliefs.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Belief> WorldModel::QueryBeliefs(const std::string& subject, float minConfidence) {
    std::vector<Belief> results;
    for (const auto& [id, belief] : pImpl_->beliefs) {
        if (belief.confidence >= minConfidence) {
            results.push_back(belief);
        }
    }
    return results;
}

std::string WorldModel::AddEvidence(const Evidence& evidence) {
    pImpl_->evidence[evidence.evidenceId] = evidence;
    return evidence.evidenceId;
}

void WorldModel::RegisterInferenceRule(const std::string& name, InferenceRule rule) {
    pImpl_->inferenceRules[name] = rule;
}

std::vector<Belief> WorldModel::Infer(const std::vector<std::string>& premiseIds, 
                                          const std::string& ruleName) {
    return {};  // Stub
}

void WorldModel::RunAutomatedInference() {}

WorldModel::WorldState WorldModel::GetWorldState() const {
    WorldState state;
    state.totalBeliefs = pImpl_->beliefs.size();
    state.activeBeliefs = state.totalBeliefs;
    state.totalEvidence = pImpl_->evidence.size();
    return state;
}

} // namespace Executive
} // namespace RawrXD
