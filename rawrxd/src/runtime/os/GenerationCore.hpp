// ============================================================================
// GenerationCore.hpp — Intent → Goal → Plan → Reason → Execute → Candidate
// → Generation Receipt. Does NOT own certification authority (separation).
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <cstdint>

namespace rawrxd::generation {

// ---------------------------------------------------------------------------
// Intent — what the user wants
// ---------------------------------------------------------------------------
struct Intent {
    std::string description;
    std::string category;           // "code", "text", "analysis", "plan"
    std::vector<std::string> constraints;
    std::unordered_map<std::string, std::string> context;
};

// ---------------------------------------------------------------------------
// Goal — normalized, decomposed intent
// ---------------------------------------------------------------------------
struct Goal {
    std::string id;
    std::string description;
    std::vector<std::string> subGoals;
    int priority = 0;
    bool achievable = false;
};

// ---------------------------------------------------------------------------
// Plan — ordered steps to achieve the goal
// ---------------------------------------------------------------------------
struct PlanStep {
    std::string action;
    std::string input;
    std::string expectedOutput;
    std::vector<size_t> dependsOn;
};

struct Plan {
    std::vector<PlanStep> steps;
    bool valid = false;
    std::string failureReason;
};

// ---------------------------------------------------------------------------
// Candidate — the generation output (before certification)
// ---------------------------------------------------------------------------
struct Candidate {
    std::string id;
    std::string content;            // the generated text/code/analysis
    std::string goalId;
    double confidence = 0.0;
    std::vector<std::string> evidence;  // supporting evidence
    std::chrono::steady_clock::time_point createdAt;
};

// ---------------------------------------------------------------------------
// Generation Receipt — proves the generation pipeline ran (NOT certification)
// ---------------------------------------------------------------------------
struct GenerationReceipt {
    std::string receiptId;
    std::string intentDescription;
    std::string goalId;
    std::string candidateId;
    std::string candidateContent;
    double confidence = 0.0;
    int planSteps = 0;
    uint64_t durationMs = 0;
    std::vector<std::string> evidence;
    std::string timestamp;
    bool valid = false;
};

// ---------------------------------------------------------------------------
// GenerationCore — the handwritten generation pipeline
// Pipeline: Intent → Goal → Plan → Execute → Candidate → Receipt
// FAIL-CLOSED: produces receipt with valid=false if any phase fails
// DOES NOT certify — certification is CertificationCore's job
// ---------------------------------------------------------------------------
class GenerationCore {
public:
    // Phase 1: Ingest intent
    Intent ingestIntent(const std::string& description, const std::string& category);

    // Phase 2: Decompose intent into goals
    Goal decomposeGoal(const Intent& intent);

    // Phase 3: Plan goal into ordered steps
    Plan planGoal(const Goal& goal);

    // Phase 4: Execute plan to produce candidate
    Candidate executePlan(const Plan& plan, const Goal& goal,
                          const std::string& generatedContent);

    // Phase 5: Produce generation receipt (NOT certification)
    GenerationReceipt produceReceipt(const Intent& intent, const Goal& goal,
                                     const Plan& plan, const Candidate& candidate);

    // Full pipeline (convenience)
    GenerationReceipt generate(const std::string& description,
                               const std::string& category,
                               const std::string& generatedContent);

    // Metrics
    int totalGenerations() const { return totalGen_.load(); }
    int successfulGenerations() const { return successGen_.load(); }

private:
    std::atomic<int> totalGen_{0};
    std::atomic<int> successGen_{0};
    std::atomic<int> receiptCounter_{0};

    std::string makeId(const std::string& prefix);
};

} // namespace rawrxd::generation