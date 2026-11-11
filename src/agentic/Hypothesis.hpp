// ============================================================================
// Hypothesis.hpp - Interpretation of multiple pieces of evidence
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#pragma once
#include "Evidence.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>

namespace rawrxd::agentic {

// Mission goal types for reverse engineering
enum class MissionGoal {
    EXTRACT_C2,              // Extract command & control endpoints
    IDENTIFY_MALWARE,        // Classify malware family
    REVERSE_PROTOCOL,        // Reverse engineer network protocol
    FIND_VULNERABILITY,        // Discover security vulnerabilities
    UNPACK_BINARY,             // Deobfuscate packed binary
    ANALYZE_CRYPTO,          // Identify cryptographic algorithms
    TRACE_EXECUTION,           // Dynamic execution tracing
    EXFILTRATION_PATTERN,      // Detect data exfiltration patterns
    RECOVER_CONFIG,          // Recover configuration data
    MAP_API_USAGE,           // Map API call patterns
    UNKNOWN                  // Unclassified goal
};

// Hypothesis status
enum class HypothesisStatus {
    UNVERIFIED,              // Initial state
    UNDER_VERIFICATION,      // Being actively tested
    CONFIRMED,               // High confidence, verified
    MUTATED,                 // Modified based on new evidence
    REFUTED,                 // Contradicted by evidence
    SUPERSEDED               // Replaced by better hypothesis
};

// Hypothesis - an interpretation of multiple pieces of evidence
struct Hypothesis {
    std::string id;
    std::string description;
    MissionGoal goal_type{MissionGoal::UNKNOWN};
    HypothesisStatus status{HypothesisStatus::UNVERIFIED};
    
    // Confidence metrics
    float confidence{0.0f};              // Overall confidence [0.0 - 1.0]
    float confidence_threshold{0.7f};      // Threshold to consider confirmed
    float bayesian_prior{0.5f};            // Prior probability
    
    // Evidence relationships
    std::vector<std::string> supporting_evidence;
    std::vector<std::string> contradicting_evidence;
    std::vector<std::string> pending_verification;
    
    // Action planning
    std::string proposed_next_action;
    std::vector<std::string> required_capabilities;
    int priority{50};                      // 0-100, higher = more urgent
    
    // Metadata
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point last_updated;
    std::string created_by_agent;
    int revision{0};                       // Number of times updated
    
    // Alternative hypotheses (competing interpretations)
    std::vector<std::string> alternative_hypotheses;
    std::string superseded_by;             // If status == SUPERSEDED
    
    // Constructors
    Hypothesis() = default;
    Hypothesis(const std::string& desc, MissionGoal goal, float threshold = 0.7f);
    
    // Generate unique ID
    static std::string GenerateId();
    
    // Update confidence based on evidence
    void UpdateConfidence(const std::unordered_map<std::string, Evidence>& evidence_pool);
    
    // Check if hypothesis is actionable (ready for next step)
    bool IsActionable() const;
    
    // Check if hypothesis needs verification
    bool NeedsVerification() const;
    
    // Serialization
    nlohmann::json ToJson() const;
    static Hypothesis FromJson(const nlohmann::json& j);
};

// Hypothesis utilities
class HypothesisUtils {
public:
    // Find competing hypotheses (same goal, different interpretations)
    static std::vector<std::string> FindCompeting(
        const std::string& hypothesis_id,
        const std::unordered_map<std::string, Hypothesis>& pool);
    
    // Select best hypothesis among alternatives
    static std::string SelectBest(
        const std::vector<std::string>& hypothesis_ids,
        const std::unordered_map<std::string, Hypothesis>& pool);
    
    // Calculate consensus confidence across multiple hypotheses
    static float CalculateConsensus(
        const std::vector<std::string>& hypothesis_ids,
        const std::unordered_map<std::string, Hypothesis>& pool);
    
    // Mission goal to string
    static std::string GoalToString(MissionGoal goal);
    static MissionGoal StringToGoal(const std::string& str);
};

} // namespace rawrxd::agentic
