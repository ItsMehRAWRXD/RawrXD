// Shared agent controller — the ONE production agent loop used by both the
// CLI (rawr) and the native IDE (RawrXD-Win32IDE-Native).
//
// The controller is I/O-agnostic: callers supply a `completeFn` (one inference
// turn against a model/backend) and callbacks for logging and cancellation.
// It parses the model's tool JSON, dispatches every pending tool through the
// shared ToolRegistry, enforces the grounding gate and no-progress guards, and
// synthesizes a HOST-VERDICT from real receipts (the model describes; the host
// determines).
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "rawr_core.hpp"

namespace rawr {

struct AgentReceipt {
    std::string tool;
    std::string args;
    std::string output;
    bool ok = false;
    bool denied = false;
    int exitCode = 0;
};

struct AgentResult {
    int turns = 0;
    int toolCalls = 0;
    int denied = 0;
    bool completed = false;
    bool canceled = false;
    std::string summary;
    std::string findings;
    std::string nextActions;
    std::vector<AgentReceipt> results;
};

struct AgentConfig {
    std::string goal;
    std::string modeName = "code";
    std::string modeDescription;
    bool sourceEditsAllowed = true;
    bool executeByDefault = true;
    int maxTurns = 12;
    int maxTokensPerTurn = 1024;
};

using AgentLogFn = std::function<void(const std::string&)>;
using AgentCancelFn = std::function<bool()>;

// Run the shared agent loop. `completeFn(messages, budget)` performs one model
// turn and returns the raw content (streaming deltas are the caller's concern).
AgentResult runAgentController(
    const std::function<InferenceResult(const std::vector<json>&, int)>& completeFn,
    ToolRegistry& reg, const Workspace& ws, const AgentConfig& cfg,
    const AgentLogFn& log, const AgentCancelFn& cancel);

}  // namespace rawr