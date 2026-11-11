// ============================================================
// WorldModel.hpp - Belief-based reasoning
// The "prefrontal cortex" of the cognitive runtime
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <chrono>
#include <cmath>

namespace RawrXD::Executive {

// ============================================================
// Belief: A statement about the world with confidence
// ============================================================

struct Belief {
    uint64_t id;
    std::string subject;       // What this belief is about
    std::string predicate;     // What we believe about it
    std::string value;        // The belief value
    
    float confidence;         // 0.0-1.0 (how sure we are)
    float prior;              // Prior probability
    std::vector<std::string> evidence;  // Supporting evidence
    std::vector<std::string> counterEvidence;  // Against
    
    uint64_t timestampMs;
    uint64_t lastUpdatedMs;
    
    enum class Status {
        Active,       // Current belief
        Hypothesis,   // Unverified
        Confirmed,    // Verified by multiple sources
        Refuted,      // Proven false
        Deprecated    // No longer relevant
    };
    Status status;
    
    std::string source;      // Who/what created this belief
    size_t confirmationCount; // How many times confirmed
    size_t refutationCount;  // How many times refuted
};

// ============================================================
// Hypothesis: A testable prediction
// ============================================================

struct Hypothesis {
    uint64_t id;
    std::string statement;    // "The binary contains a XOR decryption loop"
    std::string prediction;   // "We will find XOR at 0x402000"
    float confidence;
    
    enum class Status {
        Pending,      // Not yet tested
        Testing,      // Being tested
        Confirmed,    // Prediction was correct
        Refuted,      // Prediction was wrong
        Inconclusive  // Can't determine
    };
    Status status;
    
    std::string testMethod;   // How to test this
    std::string testResult;   // What we found
    uint64_t timestampMs;
};

// ============================================================
// World Model
// ============================================================

class WorldModel {
public:
    bool initialize();
    
    // ============================================================
    // Belief Management
    // ============================================================
    
    uint64_t addBelief(const Belief& belief);
    bool updateBelief(uint64_t beliefId, float newConfidence,
                      const std::string& newEvidence = "",
                      bool isConfirmation = true);
    std::optional<Belief> getBelief(uint64_t id);
    std::vector<Belief> getBeliefsBySubject(const std::string& subject);
    std::vector<Belief> getConfirmedBeliefs();
    
    // ============================================================
    // Hypothesis Management
    // ============================================================
    
    uint64_t createHypothesis(const Hypothesis& hyp);
    bool testHypothesis(uint64_t hypId, const std::string& result,
                        bool confirmed);
    std::vector<Hypothesis> getPendingHypotheses();
    
    // ============================================================
    // Reasoning
    // ============================================================
    
    struct ReasoningResult {
        std::string conclusion;
        float confidence;
        std::vector<std::string> supportingEvidence;
        std::vector<std::string> counterEvidence;
        std::string reasoning;
    };
    
    ReasoningResult reason(const std::string& query);
    
    // ============================================================
    // Statistics
    // ============================================================
    
    size_t getBeliefCount();
    size_t getConfirmedCount();

private:
    std::mutex mutex_;
    std::atomic<uint64_t> nextBeliefId_{1};
    std::atomic<uint64_t> nextHypothesisId_{1};
    
    std::unordered_map<uint64_t, Belief> beliefs_;
    std::unordered_map<uint64_t, Hypothesis> hypotheses_;
    
    void createDefaultBeliefs();
    uint64_t currentTimeMs();
};

} // namespace RawrXD::Executive
