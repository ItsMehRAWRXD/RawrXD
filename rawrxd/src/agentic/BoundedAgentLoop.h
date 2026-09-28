// ============================================================================
// BoundedAgentLoop.h — Agent loop control structures
// Extracted from actual usage in auto_feature_registry.cpp / agentic_task_graph.cpp
// ============================================================================
#pragma once

#include <string>
#include <cstdint>
#include <functional>

namespace RawrXD {
namespace Agent {

struct AgentLoopConfig {
    int         maxSteps            = 8;
    int         maxTokensPerRequest = 8192;
    std::string model;
    std::string ollamaBaseUrl       = "http://localhost:11434";
    bool        autoVerify          = false;
    // Session context (agentic_task_graph checkpoint restore).
    std::string workingDirectory;
    std::vector<std::string> openFiles;
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

    // Progress callback: (step, maxSteps, status, detail). Invoked from
    // Execute() at each loop step when set; no-op when empty.
    void SetProgressCallback(
        std::function<void(int, int, const std::string&, const std::string&)> cb) {
        progress_ = std::move(cb);
    }

private:
    AgentLoopConfig config_;
    int             currentStep_ = 0;
    bool            running_     = false;
    std::function<void(int, int, const std::string&, const std::string&)> progress_;
};

} // namespace Agent
} // namespace RawrXD
