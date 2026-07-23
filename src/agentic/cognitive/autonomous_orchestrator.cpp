/**
 * @file autonomous_orchestrator.cpp
 * @brief Implementation of AutonomousOrchestrator continuous mission loop
 */

#include "autonomous_orchestrator.hpp"
#include <sstream>
#include <iomanip>

namespace rawrxd::cognitive {

// ============================================================================
// Constructor / Destructor
// ============================================================================

AutonomousOrchestrator::AutonomousOrchestrator() = default;

AutonomousOrchestrator::~AutonomousOrchestrator() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool AutonomousOrchestrator::Initialize(const OrchestratorConfig& config) {
    if (m_initialized.exchange(true)) return true; // Already initialized
    
    m_config = config;
    m_status = Status::INITIALIZING;
    
    // Create components
    m_blackboard = std::make_unique<EnhancedBlackboard>();
    m_director = std::make_unique<MissionDirector>(m_blackboard.get());
    m_planner = std::make_unique<DynamicPlanner>(m_blackboard.get());
    m_reflector = std::make_unique<ReflectionAgent>(
        m_blackboard.get(), m_director.get(), m_planner.get());
    
    // Start background services
    m_planner->Start();
    m_reflector->Start();
    
    m_running = true;
    m_status = Status::IDLE;
    
    return true;
}

// ============================================================================
// Mission Control
// ============================================================================

std::string AutonomousOrchestrator::StartMission(const MissionRequest& request) {
    if (!m_initialized) {
        if (!Initialize(request.config)) {
            return "";
        }
    }
    
    std::string mission_id = "mission_" + GenerateUUID();
    
    std::lock_guard<std::mutex> lock(m_mission_mutex);
    m_active_requests[mission_id] = request;
    m_total_missions++;
    
    // Start mission in background
    m_mission_futures[mission_id] = std::async(std::launch::async, [this, mission_id, request]() {
        MissionLoop(mission_id, request);
    });
    
    return mission_id;
}

void AutonomousOrchestrator::CancelMission(const std::string& mission_id) {
    std::lock_guard<std::mutex> lock(m_mission_mutex);
    
    auto it = m_active_requests.find(mission_id);
    if (it != m_active_requests.end()) {
        m_planner->CancelAllTasks();
        m_cancelled_missions++;
        m_active_requests.erase(it);
    }
}

void AutonomousOrchestrator::CancelAllMissions() {
    std::lock_guard<std::mutex> lock(m_mission_mutex);
    
    m_planner->CancelAllTasks();
    for (auto& [id, req] : m_active_requests) {
        m_cancelled_missions++;
    }
    m_active_requests.clear();
}

// ============================================================================
// Main Mission Loop
// ============================================================================

void AutonomousOrchestrator::MissionLoop(const std::string& mission_id, 
                                            const MissionRequest& request) {
    m_status = Status::PLANNING;
    
    // Initialize mission on blackboard
    m_blackboard->StartMission(mission_id, request.description, request.type);
    NotifyProgress(mission_id, "Mission started: " + request.description);
    
    // Phase 1: Decompose goal into sub-goals
    std::vector<SubGoal> plan = m_director->DecomposeGoal(
        request.description, request.type, request.target_artifact, request.parameters);
    
    if (plan.empty()) {
        NotifyProgress(mission_id, "Failed to decompose goal");
        m_status = Status::FAILED;
        m_failed_missions++;
        return;
    }
    
    NotifyProgress(mission_id, "Goal decomposed into " + std::to_string(plan.size()) + " sub-goals");
    
    // Main execution loop
    int replan_count = 0;
    auto mission_start = std::chrono::system_clock::now();
    
    while (m_running.load()) {
        // Check timeout
        if (IsMissionTimedOut(mission_id)) {
            NotifyProgress(mission_id, "Mission timed out");
            m_status = Status::FAILED;
            m_failed_missions++;
            break;
        }
        
        // Check if complete
        if (IsMissionComplete(plan)) {
            NotifyProgress(mission_id, "Mission complete");
            m_status = Status::COMPLETE;
            m_completed_missions++;
            break;
        }
        
        // Check if failed
        if (IsMissionFailed(plan)) {
            NotifyProgress(mission_id, "Mission failed");
            m_status = Status::FAILED;
            m_failed_missions++;
            break;
        }
        
        // Execution phase
        m_status = Status::EXECUTING;
        ExecutionPhase(mission_id, plan);
        
        // Reflection phase
        m_status = Status::REFLECTING;
        ReflectionPhase(mission_id, plan);
        
        // Replanning phase (if needed)
        if (m_reflector->ShouldReplan(mission_id) && replan_count < m_config.max_replans) {
            NotifyProgress(mission_id, "Replanning triggered");
            if (ReplanningPhase(mission_id, plan)) {
                replan_count++;
                NotifyProgress(mission_id, "Replan complete (iteration " + 
                               std::to_string(replan_count) + ")");
            }
        }
        
        // Update metrics
        UpdateMissionMetrics(mission_id, plan);
        
        // Brief pause to prevent busy-waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Finalize mission
    m_blackboard->CompleteMission(mission_id);
    UpdateMissionMetrics(mission_id, plan);
    
    // Call completion callback
    auto metrics = m_blackboard->GetMissionMetrics(mission_id);
    if (metrics && request.on_complete) {
        request.on_complete(*metrics);
    }
    
    // Cleanup
    std::lock_guard<std::mutex> lock(m_mission_mutex);
    m_active_requests.erase(mission_id);
    m_mission_futures.erase(mission_id);
}

// ============================================================================
// Phase Handlers
// ============================================================================

void AutonomousOrchestrator::PlanningPhase(const std::string& mission_id, 
                                            std::vector<SubGoal>& plan) {
    // Plan is already created in MissionLoop
    // This phase could be used for plan refinement
    
    // Schedule all runnable tasks
    auto runnable = m_director->GetRunnableSubGoals(plan);
    std::vector<Task> tasks;
    
    for (const auto& sg : runnable) {
        Task task;
        task.id = sg.id;
        task.subgoal = sg;
        task.priority = sg.priority;
        task.deadline = sg.timeout;
        tasks.push_back(std::move(task));
    }
    
    m_planner->ScheduleTasks(tasks);
}

void AutonomousOrchestrator::ExecutionPhase(const std::string& mission_id,
                                            std::vector<SubGoal>& plan) {
    // The planner's scheduler thread handles actual execution
    // This phase monitors progress
    
    auto active_tasks = m_blackboard->GetActiveTasks();
    auto completed_tasks = m_blackboard->GetCompletedTasks();
    auto failed_tasks = m_blackboard->GetFailedTasks();
    
    // Update plan statuses from task results
    for (auto& sg : plan) {
        // Check if task completed
        for (const auto& task : completed_tasks) {
            if (task.subgoal.id == sg.id) {
                sg.status = SubGoal::Status::COMPLETE;
                sg.current_confidence = 1.0f;
                break;
            }
        }
        
        // Check if task failed
        for (const auto& task : failed_tasks) {
            if (task.subgoal.id == sg.id) {
                sg.status = SubGoal::Status::FAILED;
                sg.failure_reason = task.failure_reason;
                break;
            }
        }
    }
    
    // Progress update
    float progress = m_director->CalculateMissionProgress(plan);
    if (progress > 0) {
        NotifyProgress(mission_id, "Progress: " + 
                       std::to_string(static_cast<int>(progress * 100)) + "%");
    }
}

void AutonomousOrchestrator::ReflectionPhase(const std::string& mission_id,
                                              std::vector<SubGoal>& plan) {
    // Trigger reflection on current state
    auto result = m_reflector->PeriodicReflection();
    
    if (result.should_replan) {
        NotifyProgress(mission_id, "Reflection suggests replanning: " + result.reason);
    }
    
    // Update hypothesis confidences
    auto hypotheses = m_blackboard->GetActiveHypotheses();
    for (const auto& hyp : hypotheses) {
        m_reflector->ReflectOnHypothesis(hyp.id);
    }
}

bool AutonomousOrchestrator::ReplanningPhase(const std::string& mission_id,
                                              std::vector<SubGoal>& plan) {
    // Gather completed and failed IDs
    std::vector<std::string> completed_ids;
    std::vector<std::string> failed_ids;
    std::unordered_map<std::string, float> confidences;
    
    for (const auto& sg : plan) {
        if (sg.status == SubGoal::Status::COMPLETE) {
            completed_ids.push_back(sg.id);
            confidences[sg.id] = sg.current_confidence;
        } else if (sg.status == SubGoal::Status::FAILED) {
            failed_ids.push_back(sg.id);
        }
    }
    
    // Get new evidence confidences
    auto evidence_map = m_blackboard->GetConfidenceMap();
    for (const auto& [id, conf] : evidence_map) {
        confidences[id] = conf;
    }
    
    // Replan
    auto new_plan = m_director->Replan(plan, completed_ids, failed_ids, confidences);
    
    // Check if plan actually changed
    if (new_plan.size() != plan.size()) {
        plan = std::move(new_plan);
        
        // Reschedule with new plan
        m_planner->Replan(plan);
        
        return true;
    }
    
    return false;
}

// ============================================================================
// Status
// ============================================================================

std::string AutonomousOrchestrator::GetStatusString() const {
    switch (m_status.load()) {
        case Status::IDLE: return "IDLE";
        case Status::INITIALIZING: return "INITIALIZING";
        case Status::PLANNING: return "PLANNING";
        case Status::EXECUTING: return "EXECUTING";
        case Status::REFLECTING: return "REFLECTING";
        case Status::COMPLETE: return "COMPLETE";
        case Status::CANCELLED: return "CANCELLED";
        case Status::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

float AutonomousOrchestrator::GetMissionProgress(const std::string& mission_id) const {
    auto metrics = m_blackboard->GetMissionMetrics(mission_id);
    if (metrics) return metrics->CompletionPercentage();
    return 0.0f;
}

std::string AutonomousOrchestrator::GetCurrentPhase(const std::string& mission_id) const {
    return m_blackboard->GetCurrentPhase();
}

CognitiveState AutonomousOrchestrator::GetCognitiveState() const {
    return m_blackboard->GetCognitiveState();
}

// ============================================================================
// Results
// ============================================================================

std::optional<MissionMetrics> AutonomousOrchestrator::GetMissionMetrics(const std::string& mission_id) const {
    return m_blackboard->GetMissionMetrics(mission_id);
}

std::vector<MissionMetrics> AutonomousOrchestrator::GetAllMissionMetrics() const {
    return m_blackboard->GetAllMissionMetrics();
}

std::string AutonomousOrchestrator::GenerateMissionReport(const std::string& mission_id) const {
    std::ostringstream oss;
    
    auto metrics = GetMissionMetrics(mission_id);
    if (!metrics) {
        oss << "Mission not found: " << mission_id << "\n";
        return oss.str();
    }
    
    oss << "╔══════════════════════════════════════════════════════════════╗\n";
    oss << "║           AUTONOMOUS REVERSE ENGINEERING REPORT              ║\n";
    oss << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    oss << "Mission ID: " << metrics->mission_id << "\n";
    oss << "Description: " << metrics->goal_description << "\n";
    oss << "Type: " << MissionTypeToString(metrics->type) << "\n";
    oss << "Status: " << GetStatusString() << "\n";
    oss << "Progress: " << std::fixed << std::setprecision(1) << metrics->CompletionPercentage() << "%\n";
    oss << "Final Confidence: " << std::fixed << std::setprecision(2) << metrics->final_confidence << "\n";
    oss << "SubGoals: " << metrics->completed_subgoals << "/" << metrics->total_subgoals << " complete\n";
    oss << "Failed: " << metrics->failed_subgoals << "\n";
    oss << "Replans: " << metrics->replans_triggered << "\n";
    
    if (!metrics->key_findings.empty()) {
        oss << "\nKey Findings:\n";
        for (const auto& finding : metrics->key_findings) {
            oss << "  \u2022 " << finding << "\n";
        }
    }
    
    if (!metrics->unresolved_questions.empty()) {
        oss << "\nUnresolved Questions:\n";
        for (const auto& q : metrics->unresolved_questions) {
            oss << "  ? " << q << "\n";
        }
    }
    
    // Add reflection report
    auto reflection_report = m_reflector->GenerateReflectionReport(mission_id);
    oss << "\n" << reflection_report;
    
    // Add blackboard state
    oss << "\n" << m_blackboard->DumpState();
    
    return oss.str();
}

// ============================================================================
// Utility
// ============================================================================

void AutonomousOrchestrator::WaitForMission(const std::string& mission_id) {
    std::future<void> future;
    {
        std::lock_guard<std::mutex> lock(m_mission_mutex);
        auto it = m_mission_futures.find(mission_id);
        if (it != m_mission_futures.end()) {
            future = std::move(it->second);
        }
    }
    
    if (future.valid()) {
        future.wait();
    }
}

void AutonomousOrchestrator::WaitForAllMissions() {
    std::vector<std::future<void>> futures;
    {
        std::lock_guard<std::mutex> lock(m_mission_mutex);
        for (auto& [id, fut] : m_mission_futures) {
            futures.push_back(std::move(fut));
        }
    }
    
    for (auto& future : futures) {
        if (future.valid()) {
            future.wait();
        }
    }
}

void AutonomousOrchestrator::Shutdown() {
    m_running = false;
    
    CancelAllMissions();
    WaitForAllMissions();
    
    if (m_reflector) m_reflector->Stop();
    if (m_planner) m_planner->Stop();
    
    m_initialized = false;
    m_status = Status::IDLE;
}

// ============================================================================
// Internal Helpers
// ============================================================================

bool AutonomousOrchestrator::IsMissionComplete(const std::vector<SubGoal>& plan) const {
    if (plan.empty()) return false;
    
    for (const auto& sg : plan) {
        if (!sg.IsTerminal()) return false;
    }
    
    // Check if overall confidence meets threshold
    float avg_confidence = 0.0f;
    int complete_count = 0;
    for (const auto& sg : plan) {
        if (sg.status == SubGoal::Status::COMPLETE) {
            avg_confidence += sg.current_confidence;
            complete_count++;
        }
    }
    
    if (complete_count == 0) return false;
    
    avg_confidence /= complete_count;
    return avg_confidence >= m_config.mission_success_threshold;
}

bool AutonomousOrchestrator::IsMissionFailed(const std::vector<SubGoal>& plan) const {
    if (plan.empty()) return false;
    
    int failed = 0;
    for (const auto& sg : plan) {
        if (sg.status == SubGoal::Status::FAILED) failed++;
    }
    
    return failed > static_cast<int>(plan.size() * m_config.max_failure_rate);
}

bool AutonomousOrchestrator::IsMissionTimedOut(const std::string& mission_id) const {
    auto metrics = m_blackboard->GetMissionMetrics(mission_id);
    if (!metrics) return false;
    
    auto elapsed = std::chrono::system_clock::now() - metrics->start_time;
    return elapsed > m_config.mission_timeout;
}

void AutonomousOrchestrator::UpdateMissionMetrics(const std::string& mission_id,
                                                     const std::vector<SubGoal>& plan) {
    auto metrics_opt = m_blackboard->GetMissionMetrics(mission_id);
    if (!metrics_opt) return;
    
    auto metrics = *metrics_opt;
    metrics.total_subgoals = static_cast<int>(plan.size());
    metrics.completed_subgoals = 0;
    metrics.failed_subgoals = 0;
    
    float total_confidence = 0.0f;
    int complete_count = 0;
    
    for (const auto& sg : plan) {
        if (sg.status == SubGoal::Status::COMPLETE) {
            metrics.completed_subgoals++;
            total_confidence += sg.current_confidence;
            complete_count++;
        } else if (sg.status == SubGoal::Status::FAILED) {
            metrics.failed_subgoals++;
        }
    }
    
    if (complete_count > 0) {
        metrics.final_confidence = total_confidence / complete_count;
    }
    
    // Update in blackboard
    // Note: This requires a mutable reference, so we'd need to modify the blackboard API
    // For now, the metrics are tracked implicitly through the subgoal statuses
}

void AutonomousOrchestrator::NotifyProgress(const std::string& mission_id, 
                                             const std::string& message) {
    std::lock_guard<std::mutex> lock(m_mission_mutex);
    auto it = m_active_requests.find(mission_id);
    if (it != m_active_requests.end() && it->second.on_progress) {
        it->second.on_progress(message);
    }
}

} // namespace rawrxd::cognitive
