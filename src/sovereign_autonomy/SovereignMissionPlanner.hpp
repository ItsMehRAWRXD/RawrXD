/**
 * @file SovereignMissionPlanner.hpp
 * @brief Hierarchical goal decomposition and mission planning
 *
 * Converts high-level user intent into executable task graphs.
 * Supports iterative refinement, critic feedback, and replanning.
 */

#pragma once

#include "SovereignTaskGraph.hpp"
#include "SovereignBlackboard.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace RawrXD::Autonomy {

enum class MissionPriority {
    Critical = 0,   // Must complete, blocks everything
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4  // Best-effort, preemptable
};

enum class MissionState {
    Planning,       // Decomposing goals into tasks
    Ready,          // Task graph built, awaiting execution
    Executing,      // Tasks running
    Paused,         // Temporarily halted
    Reviewing,      // Critic evaluating results
    Replanning,     // Adjusting plan based on feedback
    Completed,      // All goals achieved
    Failed,         // Unrecoverable failure
    Cancelled       // Aborted by user
};

struct MissionGoal {
    std::string id;
    std::string description;
    std::string success_criteria;   // How do we know it's done?
    std::string failure_criteria;   // When do we give up?
    MissionPriority priority = MissionPriority::Normal;
    std::chrono::seconds time_budget{300};
    std::map<std::string, std::any> context;
    bool achieved = false;
};

struct MissionPlan {
    std::string mission_id;
    std::string name;
    std::vector<MissionGoal> goals;
    std::shared_ptr<SovereignTaskGraph> task_graph;  // shared: allows copy, multiple refs
    MissionState state = MissionState::Planning;
    std::chrono::steady_clock::time_point created_at;
    std::optional<std::chrono::steady_clock::time_point> started_at;
    std::optional<std::chrono::steady_clock::time_point> completed_at;
    int replan_count = 0;
    int max_replans = 3;
};

class SovereignMissionPlanner {
public:
    using PlanCallback = std::function<void(const MissionPlan& plan)>;
    using DecomposeCallback = std::function<std::vector<MissionGoal>(const MissionGoal& goal,
                                                                       SovereignBlackboard& bb)>;
    using CriticCallback = std::function<std::pair<bool, std::string>(const MissionPlan& plan,
                                                                          SovereignBlackboard& bb)>;

    SovereignMissionPlanner(std::shared_ptr<SovereignBlackboard> blackboard);
    ~SovereignMissionPlanner() = default;

    // Mission lifecycle
    std::string CreateMission(const std::string& name,
                               const std::vector<MissionGoal>& goals);
    bool StartMission(const std::string& mission_id);
    bool PauseMission(const std::string& mission_id);
    bool ResumeMission(const std::string& mission_id);
    bool CancelMission(const std::string& mission_id);

    // Planning
    bool PlanMission(const std::string& mission_id, DecomposeCallback decomposer);
    bool ReplanMission(const std::string& mission_id, const std::string& reason);

    // Critic / reflection
    bool ReviewMission(const std::string& mission_id, CriticCallback critic);

    // Execution tick (call periodically)
    bool TickMission(const std::string& mission_id,
                       SovereignTaskGraph::ExecuteCallback executor);

    // Queries
    MissionState GetMissionState(const std::string& mission_id) const;
    std::optional<MissionPlan> GetMission(const std::string& mission_id) const;
    std::vector<std::string> GetActiveMissions() const;
    std::vector<std::string> GetAllMissions() const;
    float GetMissionProgress(const std::string& mission_id) const;

    // Subscriptions
    void OnMissionStateChange(PlanCallback cb) { on_state_change_ = std::move(cb); }

    // High-level convenience
    std::string LaunchGoal(const std::string& goal_description,
                            DecomposeCallback decomposer,
                            CriticCallback critic,
                            SovereignTaskGraph::ExecuteCallback executor);

private:
    std::shared_ptr<SovereignBlackboard> blackboard_;
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<MissionPlan>> missions_;
    PlanCallback on_state_change_;

    static int64_t s_mission_counter;

    void UpdateMissionState(const std::string& mission_id, MissionState new_state);
    bool CheckGoalsAchieved(const std::string& mission_id);
    bool CheckBudgetExceeded(const std::string& mission_id);
    std::vector<MissionGoal> DefaultDecompose(const MissionGoal& goal);
};

} // namespace RawrXD::Autonomy
