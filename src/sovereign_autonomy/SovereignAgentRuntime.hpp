/**
 * @file SovereignAgentRuntime.hpp
 * @brief Unified autonomy runtime — the brain of the sovereign agent swarm
 *
 * Owns Blackboard, MissionPlanner, TaskGraph, ReflectionEngine, and Critic.
 * Provides a single entry point for the AgenticAgentCoordinator.
 */

#pragma once

#include "SovereignBlackboard.hpp"
#include "SovereignMissionPlanner.hpp"
#include "SovereignTaskGraph.hpp"
#include "SovereignReflectionEngine.hpp"
#include "SovereignCritic.hpp"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>

namespace RawrXD::Autonomy {

struct RuntimeConfig {
    bool enable_reflection = true;
    bool enable_critic = true;
    bool enable_replanning = true;
    int max_concurrent_missions = 5;
    int tick_interval_ms = 100;
    std::chrono::seconds default_time_budget{300};
};

class SovereignAgentRuntime {
public:
    using StatusCallback = std::function<void(const std::string& status)>;
    using LogCallback = std::function<void(const std::string& msg)>;

    explicit SovereignAgentRuntime(const RuntimeConfig& config = RuntimeConfig{});
    ~SovereignAgentRuntime();

    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const { return running_.load(); }

    // Mission API (high-level)
    std::string LaunchMission(const std::string& name,
                             const std::string& goal_description,
                             SovereignMissionPlanner::DecomposeCallback decomposer = nullptr,
                             SovereignTaskGraph::ExecuteCallback executor = nullptr);

    bool CancelMission(const std::string& mission_id);
    MissionState GetMissionState(const std::string& mission_id) const;
    float GetMissionProgress(const std::string& mission_id) const;
    std::vector<std::string> GetActiveMissions() const;

    // Task API (mid-level)
    std::string SubmitTask(const std::string& mission_id,
                            const std::string& description,
                            const std::string& tool_name,
                            const std::map<std::string, std::any>& params,
                            int priority = 0,
                            const std::vector<std::string>& deps = {});

    bool AssignTaskToAgent(const std::string& task_id, const std::string& agent_id);
    TaskState GetTaskState(const std::string& task_id) const;

    // Blackboard API (low-level)
    std::shared_ptr<SovereignBlackboard> GetBlackboard() { return blackboard_; }

    // Reflection
    void ReflectOnMission(const std::string& mission_id);

    // Critic
    CriticReview ReviewMission(const std::string& mission_id);

    // Executor (required for Tick to actually run tasks)
    void SetExecutor(SovereignTaskGraph::ExecuteCallback executor) { executor_ = std::move(executor); }

    // Background tick (starts automatically on Initialize)
    void Tick();

    // Callbacks
    void SetStatusCallback(StatusCallback cb) { status_cb_ = std::move(cb); }
    void SetLogCallback(LogCallback cb) { log_cb_ = std::move(cb); }

    // Component access (for advanced use)
    std::shared_ptr<SovereignMissionPlanner> GetPlanner() { return planner_; }
    std::shared_ptr<SovereignReflectionEngine> GetReflectionEngine() { return reflection_; }
    std::shared_ptr<SovereignCritic> GetCritic() { return critic_; }

private:
    RuntimeConfig config_;
    std::atomic<bool> running_{false};
    std::thread tick_thread_;

    std::shared_ptr<SovereignBlackboard> blackboard_;
    std::shared_ptr<SovereignMissionPlanner> planner_;
    std::shared_ptr<SovereignReflectionEngine> reflection_;
    std::shared_ptr<SovereignCritic> critic_;

    SovereignTaskGraph::ExecuteCallback executor_;

    StatusCallback status_cb_;
    LogCallback log_cb_;

    void TickLoop();
    void Log(const std::string& msg);
    void Status(const std::string& status);
};

} // namespace RawrXD::Autonomy
