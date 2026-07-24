/**
 * @file SovereignAgentRuntime.cpp
 * @brief Unified autonomy runtime implementation
 */

#include "SovereignAgentRuntime.hpp"
#include <sstream>
#include <chrono>

namespace RawrXD::Autonomy {

SovereignAgentRuntime::SovereignAgentRuntime(const RuntimeConfig& config)
    : config_(config) {}

SovereignAgentRuntime::~SovereignAgentRuntime() {
    Shutdown();
}

bool SovereignAgentRuntime::Initialize() {
    if (running_.load()) return true;

    blackboard_ = std::make_shared<SovereignBlackboard>();
    planner_ = std::make_shared<SovereignMissionPlanner>(blackboard_);
    reflection_ = std::make_shared<SovereignReflectionEngine>(blackboard_);
    critic_ = std::make_shared<SovereignCritic>(blackboard_);

    running_.store(true);
    tick_thread_ = std::thread(&SovereignAgentRuntime::TickLoop, this);

    Log("SovereignAgentRuntime initialized");
    Status("ready");
    return true;
}

void SovereignAgentRuntime::Shutdown() {
    if (!running_.load()) return;
    running_.store(false);
    if (tick_thread_.joinable()) {
        tick_thread_.join();
    }
    Log("SovereignAgentRuntime shutdown");
}

std::string SovereignAgentRuntime::LaunchMission(const std::string& name,
                                                  const std::string& goal_description,
                                                  SovereignMissionPlanner::DecomposeCallback decomposer,
                                                  SovereignTaskGraph::ExecuteCallback executor) {
    if (!running_.load()) {
        Log("Cannot launch mission: runtime not initialized");
        return "";
    }

    MissionGoal goal;
    goal.id = "goal_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    goal.description = goal_description;
    goal.success_criteria = "Mission completed successfully";
    goal.failure_criteria = "Budget exhausted or max replans reached";
    goal.priority = MissionPriority::Normal;
    goal.time_budget = config_.default_time_budget;

    std::string mission_id = planner_->CreateMission(name, {goal});
    if (mission_id.empty()) {
        Log("Failed to create mission: " + name);
        return "";
    }

    if (!planner_->PlanMission(mission_id, decomposer)) {
        Log("Failed to plan mission: " + mission_id);
        return "";
    }

    if (!planner_->StartMission(mission_id)) {
        Log("Failed to start mission: " + mission_id);
        return "";
    }

    // Store executor for Tick() to use
    if (executor) {
        executor_ = std::move(executor);
    }

    Log("Launched mission: " + mission_id + " (" + name + ")");
    Status("mission_running:" + mission_id);
    return mission_id;
}

bool SovereignAgentRuntime::CancelMission(const std::string& mission_id) {
    if (!running_.load()) return false;
    bool result = planner_->CancelMission(mission_id);
    if (result) {
        Log("Cancelled mission: " + mission_id);
        Status("mission_cancelled:" + mission_id);
    }
    return result;
}

MissionState SovereignAgentRuntime::GetMissionState(const std::string& mission_id) const {
    if (!running_.load()) return MissionState::Failed;
    return planner_->GetMissionState(mission_id);
}

float SovereignAgentRuntime::GetMissionProgress(const std::string& mission_id) const {
    if (!running_.load()) return 0.0f;
    return planner_->GetMissionProgress(mission_id);
}

std::vector<std::string> SovereignAgentRuntime::GetActiveMissions() const {
    if (!running_.load()) return {};
    return planner_->GetActiveMissions();
}

std::string SovereignAgentRuntime::SubmitTask(const std::string& mission_id,
                                               const std::string& description,
                                               const std::string& tool_name,
                                               const std::map<std::string, std::any>& params,
                                               int priority,
                                               const std::vector<std::string>& deps) {
    auto mission = planner_->GetMission(mission_id);
    if (!mission.has_value() || !mission->task_graph) return "";
    return mission->task_graph->AddTask(description, tool_name, params, priority, deps);
}

bool SovereignAgentRuntime::AssignTaskToAgent(const std::string& task_id, const std::string& agent_id) {
    // Find which mission owns this task
    for (const auto& mission_id : planner_->GetAllMissions()) {
        auto mission = planner_->GetMission(mission_id);
        if (mission.has_value() && mission->task_graph) {
            auto task = mission->task_graph->GetTask(task_id);
            if (task.has_value()) {
                return mission->task_graph->SetTaskAgent(task_id, agent_id);
            }
        }
    }
    return false;
}

TaskState SovereignAgentRuntime::GetTaskState(const std::string& task_id) const {
    for (const auto& mission_id : planner_->GetAllMissions()) {
        auto mission = planner_->GetMission(mission_id);
        if (mission.has_value() && mission->task_graph) {
            auto state = mission->task_graph->GetTaskState(task_id);
            if (state != TaskState::Failed) return state; // Failed is default for "not found"
        }
    }
    return TaskState::Failed;
}

void SovereignAgentRuntime::ReflectOnMission(const std::string& mission_id) {
    if (!config_.enable_reflection || !running_.load()) return;

    auto mission = planner_->GetMission(mission_id);
    if (!mission.has_value() || !mission->task_graph) return;

    // Collect all tasks from the task graph
    std::vector<TaskNode> tasks = mission->task_graph->GetAllTasks();

    Log("Reflecting on mission: " + mission_id + " (" + std::to_string(tasks.size()) + " tasks)");
    reflection_->LearnFromMission(mission_id, tasks);
    Status("reflected:" + mission_id);
}

CriticReview SovereignAgentRuntime::ReviewMission(const std::string& mission_id) {
    if (!config_.enable_critic || !running_.load()) return CriticReview{};

    auto mission = planner_->GetMission(mission_id);
    if (!mission.has_value()) return CriticReview{};

    Log("Reviewing mission: " + mission_id);
    auto review = critic_->ReviewPlan(mission.value());
    Status("reviewed:" + mission_id + ":" + std::to_string(review.score));
    return review;
}

void SovereignAgentRuntime::Tick() {
    if (!running_.load()) return;

    // Tick all active missions
    for (const auto& mission_id : planner_->GetActiveMissions()) {
        auto state = planner_->GetMissionState(mission_id);
        if (state == MissionState::Executing && executor_) {
            planner_->TickMission(mission_id, executor_);
        }
    }
}

void SovereignAgentRuntime::TickLoop() {
    while (running_.load()) {
        Tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.tick_interval_ms));
    }
}

void SovereignAgentRuntime::Log(const std::string& msg) {
    if (log_cb_) log_cb_(msg);
}

void SovereignAgentRuntime::Status(const std::string& status) {
    if (status_cb_) status_cb_(status);
}

} // namespace RawrXD::Autonomy
