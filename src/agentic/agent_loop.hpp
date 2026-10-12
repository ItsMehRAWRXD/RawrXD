// ============================================================================
// agent_loop.hpp — Autonomous agent execution loop
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <variant>
#include <optional>

namespace rawrxd {

// ---------------------------------------------------------------------------
// Agent loop types
// ---------------------------------------------------------------------------
enum class AgentState : uint8_t {
    Idle         = 0,  // Waiting for task
    Initializing = 1,  // Setting up
    Planning     = 2,  // Planning phase
    Executing    = 3,  // Executing actions
    Waiting      = 4,  // Waiting for external input
    Reflecting   = 5,  // Post-action reflection
    Completed    = 6,  // Task completed
    Failed       = 7,  // Failed
    Paused       = 8   // Paused by user
};

enum class LoopMode : uint8_t {
    SingleShot = 0,  // Run once and stop
    Continuous = 1,  // Run continuously
    Interactive = 2, // Wait for human input
    Batch      = 3   // Process batch of tasks
};

// ---------------------------------------------------------------------------
// Agent context
// ---------------------------------------------------------------------------
struct AgentContext {
    std::string taskId;
    std::string description;
    std::string initialState;
    std::string goal;
    std::unordered_map<std::string, std::string> parameters;
    std::chrono::milliseconds maxDuration{0}; // 0 = no limit
    size_t maxIterations = 100;
    double qualityThreshold = 0.8;
    bool enableReflection = true;
    bool allowHumanIntervention = true;
    std::string workingDirectory;
    std::unordered_map<std::string, std::string> metadata;
};

// ---------------------------------------------------------------------------
// Action result
// ---------------------------------------------------------------------------
struct ActionResult {
    bool success = false;
    std::string output;
    std::string errorMessage;
    std::string nextAction;
    double confidence = 0.0;
    std::chrono::milliseconds duration{0};
    std::unordered_map<std::string, std::string> metadata;
    bool requiresHuman = false;
    std::string humanPrompt;
};

// ---------------------------------------------------------------------------
// Agent step result
// ---------------------------------------------------------------------------
struct StepResult {
    enum class Status : uint8_t {
        Continue = 0,
        Complete = 1,
        Failed = 2,
        Pause = 3,
        Wait = 4
    };

    Status status = Status::Continue;
    std::string action;
    std::string output;
    double confidence = 0.0;
    std::string nextStep;
    std::string reflection;
    std::unordered_map<std::string, std::string> artifacts;
    std::chrono::milliseconds stepTime{0};
    bool requiresHuman = false;
    std::string humanPrompt;
};

// ---------------------------------------------------------------------------
// Agent loop configuration
// ---------------------------------------------------------------------------
struct AgentLoopConfig {
    std::chrono::milliseconds stepTimeout{30000};
    std::chrono::milliseconds totalTimeout{0}; // 0 = no limit
    size_t maxIterations = 100;
    size_t maxRetries = 3;
    double confidenceThreshold = 0.7;
    bool enableReflection = true;
    bool enableRecovery = true;
    bool enableHumanIntervention = true;
    size_t maxReflectionDepth = 3;
    std::chrono::milliseconds stepDelay{0};
    bool verbose = false;
};

// ---------------------------------------------------------------------------
// AgentLoop - autonomous execution loop
// ---------------------------------------------------------------------------
class AgentLoop {
public:
    struct Result {
        bool success = false;
        std::string output;
        std::string errorMessage;
        size_t iterations = 0;
        std::chrono::milliseconds totalTime{0};
        size_t stepsTaken = 0;
        double finalConfidence = 0.0;
        std::string finalState;
    };

    struct StepInfo {
        size_t step = 0;
        std::string action;
        std::string output;
        double confidence = 0.0;
        std::chrono::milliseconds duration;
        std::string reflection;
    };

    using ActionExecutor = std::function<ActionResult(const std::string& action, 
                                                       const std::string& context)>;
    using ReflectionFn = std::function<std::string(const std::string& action, 
                                                    const std::string& output, 
                                                    bool success)>;

    explicit AgentLoop(const Config& config = Config());
    ~AgentLoop();

    // Main execution
    Result run(const Context& context);
    Result run(const std::string& taskDescription);

    // Streaming interface
    struct StepResult {
        std::string action;
        std::string output;
        double confidence = 0.0;
        bool complete = false;
        std::string error;
    };

    // Step-by-step execution
    bool step(const std::string& input, std::string& output);
    bool isComplete() const;
    std::string getCurrentState() const;
    size_t getIterationCount() const;

    // Configuration
    void setConfig(const Config& config);
    const Config& getConfig() const { return m_config; }

    // Callbacks
    void setActionExecutor(std::function<ActionResult(const std::string&, 
                                                      const std::string&)> fn) {
        m_actionExecutor = std::move(fn);
    }
    void setReflectionFn(std::function<std::string(const std::string&, 
                                                    const std::string&, 
                                                    bool)> fn) {
        m_reflectionFn = std::move(fn);
    }
    void setStateCallback(std::function<void(AgentState)> cb) {
        m_stateCallback = std::move(cb);
    }

    // State queries
    AgentState getState() const { return m_state; }
    size_t getIterationCount() const { return m_iteration; }
    std::chrono::milliseconds getElapsedTime() const;
    bool isRunning() const { return m_running; }
    bool isComplete() const { return m_state == State::Completed; }
    bool hasFailed() const { return m_state == State::Failed; }

    // Control
    void pause();
    void resume();
    void stop();
    void reset();

    // Statistics
    struct Stats {
        size_t totalSteps = 0;
        size_t successfulSteps = 0;
        size_t failedSteps = 0;
        std::chrono::milliseconds totalTime{0};
        double avgConfidence = 0.0;
    };
    struct Stats getStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    Config m_config;
};

} // namespace rawrxd