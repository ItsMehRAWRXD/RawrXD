/**
 * @file SovereignMissionPlanner.cpp
 * @brief Mission planner implementation
 */

#include "SovereignMissionPlanner.hpp"
#include <sstream>

namespace RawrXD::Autonomy {

int64_t SovereignMissionPlanner::s_mission_counter = 0;

SovereignMissionPlanner::SovereignMissionPlanner(std::shared_ptr<SovereignBlackboard> blackboard)
    : blackboard_(std::move(blackboard)) {}

std::string SovereignMissionPlanner::CreateMission(const std::string& name,
                                                    const std::vector<MissionGoal>& goals) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = "mission_" + std::to_string(++s_mission_counter);
    auto plan = std::make_unique<MissionPlan>();
    plan->mission_id = id;
    plan->name = name;
    plan->goals = goals;
    plan->task_graph = std::make_shared<SovereignTaskGraph>();
    plan->state = MissionState::Planning;
    plan->created_at = std::chrono::steady_clock::now();
    missions_[id] = std::move(plan);

    blackboard_->WriteString("mission." + id + ".name", name, "planner");
    blackboard_->WriteString("mission." + id + ".state", "planning", "planner");
    return id;
}

bool SovereignMissionPlanner::StartMission(const std::string& mission_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return false;
    auto& plan = it->second;
    if (plan->state != MissionState::Ready && plan->state != MissionState::Paused) return false;
    plan->state = MissionState::Executing;
    plan->started_at = std::chrono::steady_clock::now();
    blackboard_->WriteString("mission." + mission_id + ".state", "executing", "planner");
    if (on_state_change_) on_state_change_(*plan);
    return true;
}

bool SovereignMissionPlanner::PauseMission(const std::string& mission_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return false;
    if (it->second->state != MissionState::Executing) return false;
    it->second->state = MissionState::Paused;
    blackboard_->WriteString("mission." + mission_id + ".state", "paused", "planner");
    if (on_state_change_) on_state_change_(*it->second);
    return true;
}

bool SovereignMissionPlanner::ResumeMission(const std::string& mission_id) {
    return StartMission(mission_id); // Same logic: Ready/Paused → Executing
}

bool SovereignMissionPlanner::CancelMission(const std::string& mission_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return false;
    it->second->state = MissionState::Cancelled;
    // Cancel all running tasks
    if (it->second->task_graph) {
        for (const auto& task_id : it->second->task_graph->GetRunningTasks()) {
            it->second->task_graph->MarkCancelled(task_id);
        }
    }
    blackboard_->WriteString("mission." + mission_id + ".state", "cancelled", "planner");
    if (on_state_change_) on_state_change_(*it->second);
    return true;
}

bool SovereignMissionPlanner::PlanMission(const std::string& mission_id,
                                           DecomposeCallback decomposer) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return false;
    auto& plan = it->second;
    if (plan->state != MissionState::Planning) return false;

    // Decompose each goal into tasks
    for (const auto& goal : plan->goals) {
        std::vector<MissionGoal> subgoals;
        if (decomposer) {
            subgoals = decomposer(goal, *blackboard_);
        } else {
            subgoals = DefaultDecompose(goal);
        }
        // Add tasks for each subgoal
        for (const auto& sg : subgoals) {
            std::map<std::string, std::any> params;
            params["description"] = sg.description;
            params["success_criteria"] = sg.success_criteria;
            plan->task_graph->AddTask(
                sg.description,
                "execute_goal",
                params,
                static_cast<int>(sg.priority));
        }
    }

    plan->state = MissionState::Ready;
    blackboard_->WriteString("mission." + mission_id + ".state", "ready", "planner");
    blackboard_->WriteInt("mission." + mission_id + ".task_count",
                             static_cast<int64_t>(plan->task_graph->TaskCount()), "planner");
    if (on_state_change_) on_state_change_(*plan);
    return true;
}

bool SovereignMissionPlanner::ReplanMission(const std::string& mission_id,
                                             const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return false;
    auto& plan = it->second;
    if (plan->replan_count >= plan->max_replans) return false;

    ++plan->replan_count;
    plan->state = MissionState::Replanning;
    blackboard_->WriteString("mission." + mission_id + ".state", "replanning", "planner");
    blackboard_->WriteString("mission." + mission_id + ".replan_reason", reason, "planner");

    // Clear non-completed tasks and rebuild
    if (plan->task_graph) {
        // In a real system, preserve completed tasks, rebuild the rest
        // For now, we keep the graph and let the next Tick handle it
    }

    plan->state = MissionState::Ready;
    blackboard_->WriteString("mission." + mission_id + ".state", "ready", "planner");
    if (on_state_change_) on_state_change_(*plan);
    return true;
}

bool SovereignMissionPlanner::ReviewMission(const std::string& mission_id,
                                             CriticCallback critic) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return false;
    auto& plan = it->second;
    if (plan->state != MissionState::Executing) return false;

    plan->state = MissionState::Reviewing;
    blackboard_->WriteString("mission." + mission_id + ".state", "reviewing", "planner");

    if (critic) {
        auto [passed, feedback] = critic(*plan, *blackboard_);
        blackboard_->WriteString("mission." + mission_id + ".critic_feedback", feedback, "critic");
        if (!passed) {
            return ReplanMission(mission_id, feedback);
        }
    }

    plan->state = MissionState::Executing;
    blackboard_->WriteString("mission." + mission_id + ".state", "executing", "planner");
    if (on_state_change_) on_state_change_(*plan);
    return true;
}

bool SovereignMissionPlanner::TickMission(const std::string& mission_id,
                                           SovereignTaskGraph::ExecuteCallback executor) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return false;
    auto& plan = it->second;
    if (plan->state != MissionState::Executing) return false;

    // Check budget
    if (CheckBudgetExceeded(mission_id)) {
        plan->state = MissionState::Failed;
        blackboard_->WriteString("mission." + mission_id + ".state", "failed", "planner");
        blackboard_->WriteString("mission." + mission_id + ".failure_reason", "time budget exceeded", "planner");
        if (on_state_change_) on_state_change_(*plan);
        return false;
    }

    // Execute ready tasks
    if (plan->task_graph) {
        plan->task_graph->ExecuteReadyTasks(
            executor,
            [this, mission_id](const TaskNode& task) {
                blackboard_->WriteString("mission." + mission_id + ".last_completed",
                                             task.id, "planner");
            },
            [this, mission_id](const TaskNode& task) {
                blackboard_->WriteString("mission." + mission_id + ".last_failed",
                                             task.id + ": " + task.error_message, "planner");
            });
    }

    // Check completion
    if (plan->task_graph && plan->task_graph->IsComplete()) {
        if (plan->task_graph->IsSuccessful()) {
            plan->state = MissionState::Completed;
            plan->completed_at = std::chrono::steady_clock::now();
            blackboard_->WriteString("mission." + mission_id + ".state", "completed", "planner");
        } else {
            plan->state = MissionState::Failed;
            blackboard_->WriteString("mission." + mission_id + ".state", "failed", "planner");
        }
        if (on_state_change_) on_state_change_(*plan);
    }

    return true;
}

MissionState SovereignMissionPlanner::GetMissionState(const std::string& mission_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return MissionState::Failed;
    return it->second->state;
}

std::optional<MissionPlan> SovereignMissionPlanner::GetMission(const std::string& mission_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return std::nullopt;
    return *it->second; // Copy
}

std::vector<std::string> SovereignMissionPlanner::GetActiveMissions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [id, plan] : missions_) {
        if (plan->state == MissionState::Executing ||
            plan->state == MissionState::Planning ||
            plan->state == MissionState::Ready ||
            plan->state == MissionState::Replanning ||
            plan->state == MissionState::Reviewing) {
            result.push_back(id);
        }
    }
    return result;
}

std::vector<std::string> SovereignMissionPlanner::GetAllMissions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [id, plan] : missions_) {
        result.push_back(id);
    }
    return result;
}

float SovereignMissionPlanner::GetMissionProgress(const std::string& mission_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(mission_id);
    if (it == missions_.end() || !it->second->task_graph) return 0.0f;
    return it->second->task_graph->ProgressPercent();
}

std::string SovereignMissionPlanner::LaunchGoal(const std::string& goal_description,
                                                 DecomposeCallback decomposer,
                                                 CriticCallback critic,
                                                 SovereignTaskGraph::ExecuteCallback executor) {
    MissionGoal goal;
    goal.id = "goal_" + std::to_string(++s_mission_counter);
    goal.description = goal_description;
    goal.success_criteria = "Task completed without errors";
    goal.failure_criteria = "Max retries exceeded or budget exhausted";
    goal.priority = MissionPriority::Normal;

    std::string mission_id = CreateMission(goal_description, {goal});
    if (!PlanMission(mission_id, decomposer)) return "";
    if (!StartMission(mission_id)) return "";

    // Run to completion (blocking for simplicity; real system would Tick async)
    while (true) {
        auto state = GetMissionState(mission_id);
        if (state == MissionState::Completed ||
            state == MissionState::Failed ||
            state == MissionState::Cancelled) {
            break;
        }
        TickMission(mission_id, executor);
        // In real system, yield or sleep
    }

    return mission_id;
}

void SovereignMissionPlanner::UpdateMissionState(const std::string& mission_id,
                                                  MissionState new_state) {
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return;
    it->second->state = new_state;
    if (on_state_change_) on_state_change_(*it->second);
}

bool SovereignMissionPlanner::CheckGoalsAchieved(const std::string& mission_id) {
    auto it = missions_.find(mission_id);
    if (it == missions_.end()) return false;
    // Simplified: all tasks complete = goals achieved
    if (!it->second->task_graph) return false;
    return it->second->task_graph->IsSuccessful();
}

bool SovereignMissionPlanner::CheckBudgetExceeded(const std::string& mission_id) {
    auto it = missions_.find(mission_id);
    if (it == missions_.end() || !it->second->started_at.has_value()) return false;
    auto elapsed = std::chrono::steady_clock::now() - it->second->started_at.value();
    return elapsed > it->second->goals[0].time_budget; // Use first goal's budget
}

std::vector<MissionGoal> SovereignMissionPlanner::DefaultDecompose(const MissionGoal& goal) {
    // Minimal default: goal becomes a single task
    return {goal};
}

} // namespace RawrXD::Autonomy
