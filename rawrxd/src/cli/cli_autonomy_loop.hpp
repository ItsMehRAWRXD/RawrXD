#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <queue>
#include <chrono>
#include <optional>
#include <atomic>

namespace rawrxd::cli {

// ───────────────────────────────────────────────────────────────
// Autonomy phase states
// ───────────────────────────────────────────────────────────────
enum class AutonomyPhase {
    Idle,
    Perceiving,
    Planning,
    Acting,
    Reflecting,
    WaitingForExternal,
    ShutdownRequested
};

// ───────────────────────────────────────────────────────────────
// Task descriptor for the autonomy loop
// ───────────────────────────────────────────────────────────────
struct AutonomyTask {
    uint64_t task_id = 0;
    std::string name;
    std::string payload;           // JSON or opaque blob
    uint32_t priority = 5;         // 1=lowest, 10=highest
    std::chrono::steady_clock::time_point created_at;
    std::optional<std::chrono::milliseconds> timeout;
    bool requires_user_approval = false;
    std::vector<std::string> required_capabilities;
};

// ───────────────────────────────────────────────────────────────
// Task result from execution
// ───────────────────────────────────────────────────────────────
struct TaskResult {
    uint64_t task_id = 0;
    bool success = false;
    std::string output;
    std::string error_message;
    std::chrono::milliseconds execution_time{0};
    uint32_t retry_count = 0;
};

// ───────────────────────────────────────────────────────────────
// Loop metrics
// ───────────────────────────────────────────────────────────────
struct AutonomyMetrics {
    uint64_t tasks_completed = 0;
    uint64_t tasks_failed = 0;
    uint64_t tasks_retried = 0;
    uint64_t phase_transitions = 0;
    std::chrono::milliseconds total_loop_time{0};
    std::chrono::milliseconds avg_task_time{0};
    AutonomyPhase current_phase = AutonomyPhase::Idle;
    float current_cpu_load = 0.0f;
    size_t queue_depth = 0;
};

// ───────────────────────────────────────────────────────────────
// CLIAutonomyLoop — event-driven agentic execution loop
// ───────────────────────────────────────────────────────────────
class CLIAutonomyLoop {
public:
    CLIAutonomyLoop();
    ~CLIAutonomyLoop();

    // Lifecycle
    bool Initialize(const std::string& config_json);
    void Start();
    void RequestShutdown();
    void WaitForShutdown();
    bool IsRunning() const;

    // Task management
    uint64_t EnqueueTask(const AutonomyTask& task);
    bool CancelTask(uint64_t task_id);
    std::optional<TaskResult> GetTaskResult(uint64_t task_id) const;
    std::vector<AutonomyTask> GetPendingTasks() const;

    // Phase control
    AutonomyPhase GetCurrentPhase() const;
    void ForcePhase(AutonomyPhase phase);  // for testing/emergency

    // Metrics
    AutonomyMetrics GetMetrics() const;
    void ResetMetrics();

    // Callbacks
    using PhaseChangeCallback = std::function<void(AutonomyPhase old_phase, AutonomyPhase new_phase)>;
    using TaskCompleteCallback = std::function<void(const TaskResult&)>;
    using LogCallback = std::function<void(const std::string&)>;

    void SetPhaseChangeCallback(PhaseChangeCallback cb);
    void SetTaskCompleteCallback(TaskCompleteCallback cb);
    void SetLogCallback(LogCallback cb);

    // Static helpers
    static std::string PhaseToString(AutonomyPhase phase);
    static AutonomyPhase StringToPhase(const std::string& s);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::cli
