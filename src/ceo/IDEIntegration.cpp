// ============================================================================
// IDEIntegration.cpp — IDE Bridge Implementation
// ============================================================================
#include "IDEIntegration.hpp"
#include <iostream>

namespace RawrXD {
namespace CEO {

// ============================================================================
// Constructor / Destructor
// ============================================================================
IDEIntegration::IDEIntegration() = default;
IDEIntegration::~IDEIntegration() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool IDEIntegration::Initialize() {
    m_initialized = true;
    return true;
}

void IDEIntegration::Shutdown() {
    if (m_agent) {
        m_agent->Shutdown();
        m_agent.reset();
    }
    m_initialized = false;
}

// ============================================================================
// CEO Agent Access
// ============================================================================
void IDEIntegration::SetCEOAgent(std::shared_ptr<CEOAgent> agent) {
    m_agent = agent;
    
    if (m_agent) {
        // Set up callbacks
        m_agent->SetProgressCallback(
            [this](const std::string& stage, const std::string& message, float percent) {
                OnCEOProgress(stage, message, percent);
            }
        );
        
        m_agent->SetTaskCallback(
            [this](const Task& task) {
                OnCEOTask(task);
            }
        );
        
        m_agent->SetCompletionCallback(
            [this](const Goal& goal, bool success) {
                OnCEOComplete(goal, success);
            }
        );
    }
}

std::shared_ptr<CEOAgent> IDEIntegration::GetCEOAgent() const {
    return m_agent;
}

// ============================================================================
// IDE Commands
// ============================================================================
void IDEIntegration::StartAutonomousSession(const std::string& goal) {
    if (!m_agent) {
        NotifyError("CEO Agent not initialized");
        return;
    }
    
    m_agent->ExecuteGoal(goal);
}

void IDEIntegration::ContinueSession() {
    if (!m_agent) {
        NotifyError("CEO Agent not initialized");
        return;
    }
    
    m_agent->ContinueProject();
}

void IDEIntegration::PauseSession() {
    if (!m_agent) {
        return;
    }
    
    m_agent->Pause();
}

void IDEIntegration::CancelSession() {
    if (!m_agent) {
        return;
    }
    
    m_agent->Cancel();
}

// ============================================================================
// UI Updates
// ============================================================================
void IDEIntegration::UpdateProgressBar(float percent, const std::string& message) {
    // This would update the IDE's progress bar
    // For now, just log
    std::cout << "[IDE] Progress: " << int(percent * 100) << "% - " << message << std::endl;
}

void IDEIntegration::UpdateTaskList(const std::vector<Task>& tasks) {
    // This would update the IDE's task list panel
    std::cout << "[IDE] Task list updated (" << tasks.size() << " tasks)\n";
}

void IDEIntegration::ShowCompletionPanel(const std::string& content) {
    // This would show ghost text in the editor
    std::cout << "[IDE] Completion: " << content.substr(0, 50) << "...\n";
}

void IDEIntegration::ShowDiffView(const std::string& original, const std::string& modified) {
    // This would show a diff view in the IDE
    std::cout << "[IDE] Showing diff view\n";
}

void IDEIntegration::ShowAgentChat(const std::string& message) {
    // This would show a chat message in the agent panel
    std::cout << "[Agent] " << message << std::endl;
}

// ============================================================================
// Notifications
// ============================================================================
void IDEIntegration::NotifyTaskComplete(const Task& task) {
    // Show notification in IDE
    std::cout << "[IDE] Task complete: " << task.description << std::endl;
}

void IDEIntegration::NotifyGoalComplete(const Goal& goal, bool success) {
    // Show notification in IDE
    std::cout << "[IDE] Goal " << (success ? "completed" : "failed") << ": " << goal.description << std::endl;
}

void IDEIntegration::NotifyError(const std::string& error) {
    // Show error in IDE
    std::cerr << "[IDE Error] " << error << std::endl;
}

// ============================================================================
// Callback Handlers
// ============================================================================
void IDEIntegration::OnCEOProgress(const std::string& stage, 
                                   const std::string& message, 
                                   float percent) {
    UpdateProgressBar(percent, stage + ": " + message);
}

void IDEIntegration::OnCEOTask(const Task& task) {
    // Update task list
    if (m_agent) {
        UpdateTaskList(m_agent->GetTaskQueue());
    }
    
    // Notify if task is complete
    if (task.status == Task::Status::Success || 
        task.status == Task::Status::Failed) {
        NotifyTaskComplete(task);
    }
}

void IDEIntegration::OnCEOComplete(const Goal& goal, bool success) {
    NotifyGoalComplete(goal, success);
}

// ============================================================================
// State Export
// ============================================================================
json IDEIntegration::GetStateForIDE() const {
    json state;
    
    if (m_agent) {
        state["running"] = m_agent->IsRunning();
        state["paused"] = m_agent->IsPaused();
        
        auto goal = m_agent->GetCurrentGoal();
        state["current_goal"] = goal.description;
        state["goal_completed"] = goal.completed;
        
        auto tasks = m_agent->GetTaskQueue();
        state["pending_tasks"] = tasks.size();
        
        auto projectState = m_agent->GetProjectState();
        state["completed_tasks"] = projectState.GetCompletedTaskCount();
        state["failed_tasks"] = projectState.GetFailedTaskCount();
    }
    
    return state;
}

} // namespace CEO
} // namespace RawrXD
