// ============================================================================
// WorldModel.hpp - Belief-Based Reasoning System
// Evidence-driven knowledge with confidence, contradictions, and inference
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>
#include <functional>

namespace RawrXD {
namespace Executive {

// Forward declarations
class CognitiveMemory;

// ============================================================================
// Belief - A claim about the world with confidence and evidence
// ============================================================================
struct Belief {
    std::string beliefId;
    std::string statement;           // Natural language claim
    std::string subject;             // What is this about
    std::string predicate;           // What property/relation
    std::string object;              // Value/target
    
    // Confidence system
    float confidence = 0.5f;         // 0-1, starts uncertain
    float priorConfidence = 0.5f;    // Before latest evidence
    
    // Evidence tracking
    std::vector<std::string> supportingEvidence;    // Episode IDs
    std::vector<std::string> contradictingEvidence; // Episode IDs
    
    // Reasoning chain
    std::vector<std::string> inferredFrom;          // Belief IDs this was derived from
    std::string inferenceRule;                     // How it was derived
    
    // Temporal
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    
    // Status
    bool isActive = true;
    bool isContradicted = false;
};

// ============================================================================
// Evidence - An observation that supports or contradicts beliefs
// ============================================================================
struct Evidence {
    std::string evidenceId;
    std::string source;              // "sensor", "inference", "external", etc.
    std::string description;
    float strength = 1.0f;         // How strong is this evidence (0-1)
    bool supports = true;          // true = supports, false = contradicts
    
    // Link to episodic memory
    std::string episodeId;
    
    // What it applies to
    std::vector<std::string> relevantBeliefIds;
};

// ============================================================================
// Inference Rule
// ============================================================================
using InferenceRule = std::function<std::vector<Belief>(
    const std::vector<Belief>& premises,
    CognitiveMemory* memory
)>;

// ============================================================================
// Hypothesis - A testable prediction
// ============================================================================
struct Hypothesis {
    std::string hypothesisId;
    std::string statement;
    std::string derivedFromBeliefId;
    
    // Predictions
    std::vector<std::string> expectedObservations;
    std::vector<std::string> unexpectedObservations;
    
    // Testing
    bool isTested = false;
    bool isConfirmed = false;
    std::vector<std::string> testEpisodeIds;
};

// ============================================================================
// World Model - The System's Understanding of Reality
// ============================================================================
class WorldModel {
public:
    WorldModel();
    ~WorldModel();

    // Initialization
    bool Initialize(CognitiveMemory* memory);
    void Shutdown();
    
    // Belief Management
    std::string AddBelief(const Belief& belief);
    void UpdateBeliefConfidence(const std::string& beliefId, float newConfidence, const std::string& evidenceId);
    void AddEvidenceToBelief(const std::string& beliefId, const Evidence& evidence);
    void MarkBeliefContradicted(const std::string& beliefId, const std::string& contradictingEvidenceId);
    
    std::optional<Belief> GetBelief(const std::string& beliefId);
    std::vector<Belief> QueryBeliefs(const std::string& subject = "", float minConfidence = 0.0f);
    std::vector<Belief> GetRelatedBeliefs(const std::string& beliefId, const std::string& relation = "");
    
    // Evidence Management
    std::string AddEvidence(const Evidence& evidence);
    std::vector<Evidence> GetEvidenceForBelief(const std::string& beliefId);
    
    // Inference
    void RegisterInferenceRule(const std::string& name, InferenceRule rule);
    std::vector<Belief> Infer(const std::vector<std::string>& premiseIds, const std::string& ruleName);
    void RunAutomatedInference();
    
    // Hypothesis Testing
    std::string GenerateHypothesis(const std::string& beliefId);
    void TestHypothesis(const std::string& hypothesisId, const std::vector<std::string>& observations);
    std::vector<Hypothesis> GetUntestedHypotheses();
    
    // Conflict Resolution
    std::vector<std::pair<Belief, Belief>> FindConflicts();
    Belief ResolveConflict(const std::string& beliefId1, const std::string& beliefId2);
    
    // Query with reasoning
    struct ReasonedQuery {
        std::string query;
        std::vector<Belief> directMatches;
        std::vector<Belief> inferredMatches;
        std::vector<std::string> reasoningChain;
        float overallConfidence = 0.0f;
    };
    ReasonedQuery QueryWithReasoning(const std::string& query);
    
    // World state summary
    struct WorldState {
        size_t totalBeliefs = 0;
        size_t activeBeliefs = 0;
        size_t contradictedBeliefs = 0;
        size_t totalEvidence = 0;
        size_t pendingHypotheses = 0;
        float averageConfidence = 0.0f;
        std::vector<std::string> topConfidentBeliefs;
        std::vector<std::string> uncertainBeliefs;  // Below threshold
    };
    WorldState GetWorldState() const;
    
    // Explanation generation
    std::string ExplainBelief(const std::string& beliefId);
    std::string ExplainInference(const std::string& inferredBeliefId);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace Executive
} // namespace RawrXD
