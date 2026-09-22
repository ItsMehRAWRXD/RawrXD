// ============================================================================
// BoundedAgentLoop.h — Agent loop control structures
// Extracted from actual usage in auto_feature_registry.cpp / agentic_task_graph.cpp
// ============================================================================
#pragma once

#include <string>
#include <cstdint>

namespace RawrXD {
namespace Agent {

struct AgentLoopConfig {
    int         maxSteps            = 8;
    int         maxTokensPerRequest = 8192;
    std::string model;
    std::string ollamaBaseUrl       = "http://localhost:11434";
    bool        autoVerify          = false;
};

class BoundedAgentLoop {
public:
    BoundedAgentLoop() = default;

    void Configure(const AgentLoopConfig& config) { config_ = config; }

    // Execute a single-turn agent task.
    // Returns the agent response string (may be empty on failure).
    std::string Execute(const std::string& task);

    // Current step counter (0 = not started).
    int GetCurrentStep() const { return currentStep_; }

    // Whether the loop is actively running a task.
    bool IsRunning() const { return running_; }

private:
    AgentLoopConfig config_;
    int             currentStep_ = 0;
    bool            running_     = false;
};

} // namespace Agent
} // namespace RawrXD
