// ============================================================================
// autonomous_subagent.hpp — RAWRXD_W3_BATCH_G2
// Real header for the autonomous subagent layer that the workflow engine's
// BulkFixOrchestrator coordinates. The original header was never committed
// (N2: autonomous_workflow_engine.cpp excluded solely on this missing file);
// the surface here is the real minimal contract used by that orchestration:
// a subagent task description, its outcome, and the dispatch entry point.
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::agent {

struct SubagentTask {
    std::string id;
    std::string description;
    std::vector<std::string> targetFiles;
    uint32_t maxRetries = 3;
    uint32_t timeoutMs = 30000;
};

struct SubagentOutcome {
    std::string taskId;
    bool success = false;
    std::string detail;          // real stdout/stderr or failure reason
    uint64_t elapsedMs = 0;
};

// Dispatch a batch of subagent tasks; outcomes are returned per task in the
// same order. The default runner executes synchronously in-process; callers
// needing parallelism wrap this in their own worker pool.
std::vector<SubagentOutcome> RunSubagentTasks(
    const std::vector<SubagentTask>& tasks);

} // namespace rawrxd::agent
