// ============================================================================
// CEOAgentTypes.hpp — Shared types for CEO Agent module
// Breaks circular dependency between CEOAgent.hpp and ProjectState.hpp
// ============================================================================
#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace CEO {

using json = nlohmann::json;

// ============================================================================
// CEO Agent Configuration
// ============================================================================
struct CEOConfig {
    bool autoPlan = true;
    bool autoExecute = true;
    bool autoRepair = true;
    bool autoCommit = false;
    int maxIterations = 100;
    int maxFilesPerIteration = 10;
    int maxConsecutiveFailures = 5;
    int debounceMs = 100;
    int buildTimeoutSec = 300;
    int testTimeoutSec = 600;
    std::string plannerModel = "deep2-22b-q4";
    std::string coderModel = "deep2-22b-q4";
    std::string reviewerModel = "deep2-22b-q4";
    std::string debuggerModel = "deep2-22b-q4";
    std::string projectRoot = ".";
    std::string memoryPath = ".rawrxd/memory";
    std::string statePath = ".rawrxd/state";
    std::string logPath = ".rawrxd/logs";
};

// ============================================================================
// Goal Structure
// ============================================================================
struct Goal {
    std::string id;
    std::string description;
    std::string criteria;
    std::vector<std::string> dependencies;
    int priority = 5;
    bool completed = false;
    json result;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point completedAt;
};

// ============================================================================
// Task Structure
// ============================================================================
struct Task {
    enum class Type {
        Analyze, Plan, Code, Build, Test, Debug, Review, Commit, Validate, Complete
    };

    enum class Status {
        Pending, Queued, InProgress, Blocked, Failed, Success, Skipped
    };

    std::string id;
    Type type;
    std::string description;
    std::vector<std::string> targetFiles;
    json context;
    Status status = Status::Pending;
    std::string result;
    std::string error;
    int attempts = 0;
    std::chrono::system_clock::time_point started;
    std::chrono::system_clock::time_point completed;
};

// ============================================================================
// Callbacks
// ============================================================================
using ProgressCallback = std::function<void(const std::string& stage,
                                            const std::string& message,
                                            float percent)>;
using TaskCallback = std::function<void(const Task& task)>;
using CompletionCallback = std::function<void(const Goal& goal, bool success)>;

} // namespace CEO
} // namespace RawrXD
