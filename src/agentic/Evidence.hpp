// ============================================================================
// Evidence.hpp - Atomic piece of information discovered by agents
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <nlohmann/json.hpp>

namespace rawrxd::agentic {

// Evidence type classification
enum class EvidenceType {
    OBSERVATION,      // Raw observation (entropy, strings, etc.)
    DERIVED,          // Derived from other evidence
    EXTERNAL,         // External source (YARA rule, threat intel)
    CONTRADICTORY,    // Evidence that contradicts a hypothesis
    SUPPORTING        // Evidence that supports a hypothesis
};

// Evidence - atomic piece of information discovered
struct Evidence {
    std::string id;
    std::string description;
    std::string source_agent;
    EvidenceType type{EvidenceType::OBSERVATION};
    float confidence{0.5f}; // 0.0 - 1.0
    float weight{1.0f};     // +1.0 for supporting, -1.0 for contradicting
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, std::string> metadata;
    
    // Relationships to other evidence
    std::vector<std::string> supports;      // Evidence IDs this supports
    std::vector<std::string> contradicts;   // Evidence IDs this contradicts
    std::vector<std::string> related_to;    // Related evidence (neutral)
    
    // Content - the actual data
    std::variant<
        std::string,                    // Text evidence
        std::vector<uint8_t>,           // Binary evidence
        nlohmann::json,                 // Structured evidence
        double                          // Numeric evidence
    > content;
    
    // Constructors
    Evidence() = default;
    Evidence(const std::string& desc, const std::string& agent, float conf = 0.5f);
    
    // Generate unique ID
    static std::string GenerateId();
    
    // Serialization
    nlohmann::json ToJson() const;
    static Evidence FromJson(const nlohmann::json& j);
    
    // Utility
    bool IsSupporting() const { return weight > 0; }
    bool IsContradictory() const { return weight < 0; }
    std::string GetContentString() const;
};

// Evidence collection utilities
class EvidenceUtils {
public:
    // Aggregate confidence from multiple evidence items
    static float AggregateConfidence(const std::vector<std::string>& evidence_ids,
                                     const std::unordered_map<std::string, Evidence>& pool);
    
    // Find conflicts between evidence
    static std::vector<std::pair<std::string, std::string>> FindConflicts(
        const std::unordered_map<std::string, Evidence>& pool);
    
    // Calculate evidence age
    static std::chrono::seconds GetAge(const Evidence& ev);
};

} // namespace rawrxd::agentic
