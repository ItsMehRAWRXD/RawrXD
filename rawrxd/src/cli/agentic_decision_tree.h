// ============================================================================
// agentic_decision_tree.h — Stub header for swarm_decision_bridge.cpp
// ============================================================================
// Minimal declarations to satisfy #include references in the Win32IDE build.
// No Qt dependencies. No simplification.
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class DecisionOutcome : uint8_t {
    Unknown = 0,
    Approve = 1,
    Reject  = 2,
    Escalate = 3
};

struct DecisionNode {
    uint32_t id = 0;
    std::string ruleName;
    DecisionOutcome outcome = DecisionOutcome::Unknown;
    float confidence = 0.0f;
};

class AgenticDecisionTree {
public:
    AgenticDecisionTree() = default;
    ~AgenticDecisionTree() = default;

    DecisionOutcome evaluate(const std::string& /*context*/) const {
        return DecisionOutcome::Approve;
    }

    bool loadRules(const std::string& /*path*/) { return true; }
    void reset() {}

    std::vector<DecisionNode> getLastTrace() const { return {}; }
};
