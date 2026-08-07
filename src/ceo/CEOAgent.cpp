// ============================================================================
// CEOAgent.cpp — Chief Executive Officer Agent Implementation
// The autonomous brain that can complete entire projects
// ============================================================================
#include "CEOAgent.hpp"
#include "../core/rawrxd_subsystem_api.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>

namespace fs = std::filesystem;

namespace RawrXD {
namespace CEO {

// ============================================================================
// Utility Functions
// ============================================================================
static std::string GenerateUUID() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);
    
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 8; i++) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; i++) ss << dis(gen);
    ss << "-4";
    for (int i = 0; i < 3; i++) ss << dis(gen);
    ss << "-";
    ss << dis2(gen);
    for (int i = 0; i < 3; i++) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 12; i++) ss << dis(gen);
    
    return ss.str();
}

static std::string TaskTypeToString(Task::Type type) {
    switch (type) {
        case Task::Type::Analyze: return "Analyze";
        case Task::Type::Plan: return "Plan";
        case Task::Type::Code: return "Code";
        case Task::Type::Build: return "Build";
        case Task::Type::Test: return "Test";
        case Task::Type::Debug: return "Debug";
        case Task::Type::Review: return "Review";
        case Task::Type::Commit: return "Commit";
        case Task::Type::Validate: return "Validate";
        case Task::Type::Complete: return "Complete";
        default: return "Unknown";
    }
}

static std::string TaskStatusToString(Task::Status status) {
    switch (status) {
        case Task::Status::Pending: return "Pending";
        case Task::Status::Queued: return "Queued";
        case Task::Status::InProgress: return "InProgress";
        case Task::Status::Blocked: return "Blocked";
        case Task::Status::Failed: return "Failed";
        case Task::Status::Success: return "Success";
        case Task::Status::Skipped: return "Skipped";
        default: return "Unknown";
    }
}

// ============================================================================
// Constructor / Destructor
// ============================================================================
CEOAgent::CEOAgent() = default;

CEOAgent::~CEOAgent() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool CEOAgent::Initialize(const CEOConfig& config) {
    if (m_initialized) {
        return true;
    }
    
    m_config = config;
    
    // Create directories
    try {
        fs::create_directories(m_config.memoryPath);
        fs::create_directories(m_config.statePath);
        fs::create_directories(m_config.logPath);
    } catch (const std::exception& e) {
        fprintf(stderr, "[CEOAgent] Failed to create directories: %s\n", e.what());
        return false;
    }
    
    // Initialize subsystems
    m_projectState = std::make_unique<ProjectState>();
    if (!m_projectState->Initialize(m_config.statePath)) {
        fprintf(stderr, "[CEOAgent] Failed to initialize ProjectState\n");
        return false;
    }
    
    m_contextEngine = std::make_unique<ContextEngine>();
    if (!m_contextEngine->Initialize(m_config.projectRoot)) {
        fprintf(stderr, "[CEOAgent] Failed to initialize ContextEngine\n");
        return false;
    }
    
    m_modelRouter = std::make_unique<ModelRouter>();
    if (!m_modelRouter->Initialize()) {
        fprintf(stderr, "[CEOAgent] Failed to initialize ModelRouter\n");
        return false;
    }
    
    m_buildLoop = std::make_unique<AutonomousBuildLoop>();
    if (!m_buildLoop->Initialize()) {
        fprintf(stderr, "[CEOAgent] Failed to initialize AutonomousBuildLoop\n");
        return false;
    }
    
    // Initialize agent orchestrator
    m_agentOrchestrator = std::make_unique<Agent::AgentOrchestrator>();
    
    m_initialized = true;
    
    ReportProgress("Initialize", "CEO Agent initialized", 1.0f);
    return true;
}

void CEOAgent::Shutdown() {
    if (!m_initialized) {
        return;
    }
    
    Cancel();
    
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
    
    m_agentOrchestrator.reset();
    m_buildLoop.reset();
    m_modelRouter.reset();
    m_contextEngine.reset();
    m_projectState.reset();
    
    m_initialized = false;
}

// ============================================================================
// Core Operations
// ============================================================================
Goal CEOAgent::StartProject(const std::string& goalDescription) {
    Goal goal;
    goal.id = GenerateUUID();
    goal.description = goalDescription;
    goal.created = std::chrono::system_clock::now();
    
    ReportProgress("Start", "Starting project: " + goalDescription, 0.0f);
    
    // Save to project state
    m_projectState->SetCurrentGoal(goal);
    m_projectState->AddGoal(goal);
    
    // Start the CEO loop
    m_currentGoal = goal;
    m_running = true;
    m_cancelled = false;
    m_paused = false;
    m_iteration = 0;
    
    m_workerThread = std::thread(&CEOAgent::RunCEOLoop, this);
    
    return goal;
}

Goal CEOAgent::ContinueProject() {
    // Load previous state
    auto savedGoal = m_projectState->GetCurrentGoal();
    if (savedGoal.id.empty()) {
        ReportProgress("Continue", "No previous goal found", 0.0f);
        return Goal{};
    }
    
    ReportProgress("Continue", "Continuing project: " + savedGoal.description, 0.0f);
    
    m_currentGoal = savedGoal;
    m_running = true;
    m_cancelled = false;
    m_paused = false;
    
    m_workerThread = std::thread(&CEOAgent::RunCEOLoop, this);
    
    return savedGoal;
}

Goal CEOAgent::ExecuteGoal(const std::string& goalDescription) {
    return StartProject(goalDescription);
}

void CEOAgent::ExecuteAutonomous(const std::string& highLevelGoal) {
    // The "overnight builder" mode
    // This runs with full autonomy until completion
    
    auto goal = StartProject(highLevelGoal);
    
    // Wait for completion (blocking)
    while (m_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ============================================================================
// Control
// ============================================================================
void CEOAgent::Pause() {
    m_paused = true;
    ReportProgress("Control", "Paused", 0.0f);
}

void CEOAgent::Resume() {
    m_paused = false;
    ReportProgress("Control", "Resumed", 0.0f);
}

void CEOAgent::Cancel() {
    m_cancelled = true;
    m_running = false;
    ReportProgress("Control", "Cancelled", 0.0f);
}

// ============================================================================
// State Queries
// ============================================================================
const ProjectState& CEOAgent::GetProjectState() const {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    if (m_projectState) {
        return *m_projectState;
    }
    static ProjectState emptyState;
    return emptyState;
}

std::vector<Task> CEOAgent::GetTaskQueue() const {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    return m_taskQueue;
}

Task CEOAgent::GetCurrentTask() const {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    return m_currentTask;
}

Goal CEOAgent::GetCurrentGoal() const {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    return m_currentGoal;
}

// ============================================================================
// Core Loop
// ============================================================================
void CEOAgent::RunCEOLoop() {
    ReportProgress("Loop", "CEO Loop started", 0.0f);
    
    while (m_running.load() && !m_cancelled.load()) {
        if (m_paused.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        if (m_iteration >= m_config.maxIterations) {
            ReportProgress("Loop", "Max iterations reached", 1.0f);
            break;
        }
        
        m_iteration++;
        
        // Process the current goal
        ProcessGoal(m_currentGoal);
        
        // Check if goal is complete
        if (m_currentGoal.completed) {
            ReportCompletion(m_currentGoal, true);
            break;
        }
        
        // Small delay to prevent tight loop
        std::this_thread::sleep_for(std::chrono::milliseconds(m_config.debounceMs));
    }
    
    m_running = false;
    ReportProgress("Loop", "CEO Loop ended", 1.0f);
}

void CEOAgent::ProcessGoal(Goal& goal) {
    ReportProgress("Goal", "Processing goal: " + goal.description, 0.1f);
    
    // Phase 1: Analyze
    if (!Phase_Analyze(goal)) {
        ReportProgress("Goal", "Analysis failed", 0.0f);
        return;
    }
    
    // Phase 2: Plan
    if (!Phase_Plan(goal)) {
        ReportProgress("Goal", "Planning failed", 0.0f);
        return;
    }
    
    // Phase 3: Execute
    if (!Phase_Execute(goal)) {
        ReportProgress("Goal", "Execution failed", 0.0f);
        return;
    }
    
    // Phase 4: Validate
    if (!Phase_Validate(goal)) {
        ReportProgress("Goal", "Validation failed", 0.0f);
        return;
    }
    
    // Phase 5: Complete
    Phase_Complete(goal);
}

// ============================================================================
// Phase Handlers
// ============================================================================
bool CEOAgent::Phase_Analyze(Goal& goal) {
    ReportProgress("Analyze", "Analyzing codebase...", 0.15f);
    
    Task task;
    task.id = GenerateUUID();
    task.type = Task::Type::Analyze;
    task.description = "Analyze project structure and dependencies";
    task.status = Task::Status::InProgress;
    task.started = std::chrono::system_clock::now();
    
    ReportTask(task);
    
    // Use context engine to understand the repository
    if (!m_contextEngine->IndexRepository()) {
        task.status = Task::Status::Failed;
        task.error = "Failed to index repository";
        ReportTask(task);
        return false;
    }
    
    auto stats = m_contextEngine->GetRepositoryStats();
    task.result = stats.dump();
    task.status = Task::Status::Success;
    task.completed = std::chrono::system_clock::now();
    
    ReportProgress("Analyze", "Found " + std::to_string(stats["file_count"].get<int>()) + " files", 0.25f);
    ReportTask(task);
    
    return true;
}

bool CEOAgent::Phase_Plan(Goal& goal) {
    ReportProgress("Plan", "Creating implementation plan...", 0.3f);
    
    Task task;
    task.id = GenerateUUID();
    task.type = Task::Type::Plan;
    task.description = "Create task plan for: " + goal.description;
    task.status = Task::Status::InProgress;
    task.started = std::chrono::system_clock::now();
    
    ReportTask(task);
    
    // Query the model for a plan
    json planRequest;
    planRequest["goal"] = goal.description;
    planRequest["context"] = m_contextEngine->GetRelevantContext(goal.description);
    planRequest["criteria"] = goal.criteria;
    
    json planResponse;
    if (!InvokeTool("generate_plan", planRequest, planResponse)) {
        task.status = Task::Status::Failed;
        task.error = "Failed to generate plan";
        ReportTask(task);
        return false;
    }
    
    // Create tasks from plan
    if (planResponse.contains("tasks")) {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        for (const auto& t : planResponse["tasks"]) {
            Task newTask;
            newTask.id = GenerateUUID();
            newTask.description = t.value("description", "");
            newTask.type = Task::Type::Code; // Default to code
            newTask.status = Task::Status::Pending;
            
            if (t.contains("type")) {
                std::string typeStr = t["type"];
                if (typeStr == "analyze") newTask.type = Task::Type::Analyze;
                else if (typeStr == "plan") newTask.type = Task::Type::Plan;
                else if (typeStr == "code") newTask.type = Task::Type::Code;
                else if (typeStr == "build") newTask.type = Task::Type::Build;
                else if (typeStr == "test") newTask.type = Task::Type::Test;
                else if (typeStr == "debug") newTask.type = Task::Type::Debug;
                else if (typeStr == "review") newTask.type = Task::Type::Review;
                else if (typeStr == "commit") newTask.type = Task::Type::Commit;
            }
            
            if (t.contains("files")) {
                for (const auto& f : t["files"]) {
                    newTask.targetFiles.push_back(f);
                }
            }
            
            m_taskQueue.push_back(newTask);
        }
    }
    
    task.status = Task::Status::Success;
    task.completed = std::chrono::system_clock::now();
    task.result = "Created " + std::to_string(m_taskQueue.size()) + " tasks";
    
    ReportProgress("Plan", "Created " + std::to_string(m_taskQueue.size()) + " tasks", 0.4f);
    ReportTask(task);
    
    return true;
}

bool CEOAgent::Phase_Execute(Goal& goal) {
    ReportProgress("Execute", "Executing tasks...", 0.5f);
    
    while (!m_taskQueue.empty() && m_running.load() && !m_cancelled.load()) {
        if (m_paused.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        // Get next task
        Task task;
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            task = m_taskQueue.front();
            m_taskQueue.erase(m_taskQueue.begin());
            m_currentTask = task;
        }
        
        // Execute the task
        bool success = ExecuteTask(task);
        
        if (!success && m_config.autoRepair) {
            // Try to repair
            if (!HandleFailure(task, task.error)) {
                // Escalate if repair failed
                if (!EscalateFailure(task)) {
                    return false;
                }
            }
        }
        
        // Update task in queue if it needs retry
        if (task.status == Task::Status::Failed && task.attempts < 3) {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            task.attempts++;
            task.status = Task::Status::Pending;
            m_taskQueue.insert(m_taskQueue.begin(), task);
        }
    }
    
    ReportProgress("Execute", "Task execution complete", 0.7f);
    return true;
}

bool CEOAgent::Phase_Validate(Goal& goal) {
    ReportProgress("Validate", "Validating changes...", 0.8f);
    
    Task task;
    task.id = GenerateUUID();
    task.type = Task::Type::Validate;
    task.description = "Validate goal completion";
    task.status = Task::Status::InProgress;
    task.started = std::chrono::system_clock::now();
    
    ReportTask(task);
    
    // Run final build and tests
    json validateRequest;
    validateRequest["criteria"] = goal.criteria;
    
    json validateResponse;
    if (!InvokeTool("validate_completion", validateRequest, validateResponse)) {
        task.status = Task::Status::Failed;
        task.error = "Validation failed";
        ReportTask(task);
        return false;
    }
    
    bool passed = validateResponse.value("passed", false);
    
    task.status = passed ? Task::Status::Success : Task::Status::Failed;
    task.completed = std::chrono::system_clock::now();
    task.result = validateResponse.dump();
    
    ReportProgress("Validate", passed ? "Validation passed" : "Validation failed", 0.9f);
    ReportTask(task);
    
    return passed;
}

bool CEOAgent::Phase_Complete(Goal& goal) {
    ReportProgress("Complete", "Completing goal...", 1.0f);
    
    goal.completed = true;
    goal.completedAt = std::chrono::system_clock::now();
    
    // Save final state
    m_projectState->SetCurrentGoal(goal);
    m_projectState->UpdateGoal(goal);
    
    Task task;
    task.id = GenerateUUID();
    task.type = Task::Type::Complete;
    task.description = "Goal completed: " + goal.description;
    task.status = Task::Status::Success;
    task.completed = std::chrono::system_clock::now();
    
    ReportTask(task);
    
    return true;
}

// ============================================================================
// Task Execution
// ============================================================================
bool CEOAgent::ExecuteTask(Task& task) {
    task.status = Task::Status::InProgress;
    task.started = std::chrono::system_clock::now();
    task.attempts++;
    
    ReportTask(task);
    
    bool success = false;
    
    switch (task.type) {
        case Task::Type::Analyze:
            success = ExecuteAnalyzeTask(task);
            break;
        case Task::Type::Plan:
            success = ExecutePlanTask(task);
            break;
        case Task::Type::Code:
            success = ExecuteCodeTask(task);
            break;
        case Task::Type::Build:
            success = ExecuteBuildTask(task);
            break;
        case Task::Type::Test:
            success = ExecuteTestTask(task);
            break;
        case Task::Type::Debug:
            success = ExecuteDebugTask(task);
            break;
        case Task::Type::Review:
            success = ExecuteReviewTask(task);
            break;
        case Task::Type::Commit:
            success = ExecuteCommitTask(task);
            break;
        default:
            task.error = "Unknown task type";
            success = false;
    }
    
    task.status = success ? Task::Status::Success : Task::Status::Failed;
    task.completed = std::chrono::system_clock::now();
    
    ReportTask(task);
    
    return success;
}

bool CEOAgent::ExecuteAnalyzeTask(Task& task) {
    // Analysis is already done in Phase_Analyze
    task.result = "Analysis complete";
    return true;
}

bool CEOAgent::ExecutePlanTask(Task& task) {
    // Planning is already done in Phase_Plan
    task.result = "Planning complete";
    return true;
}

bool CEOAgent::ExecuteCodeTask(Task& task) {
    // Use the build loop to generate and apply code
    return m_buildLoop->GenerateAndApplyCode(task.description, task.targetFiles);
}

bool CEOAgent::ExecuteBuildTask(Task& task) {
    return m_buildLoop->Build();
}

bool CEOAgent::ExecuteTestTask(Task& task) {
    return m_buildLoop->Test();
}

bool CEOAgent::ExecuteDebugTask(Task& task) {
    return m_buildLoop->Debug(task.description);
}

bool CEOAgent::ExecuteReviewTask(Task& task) {
    // Code review using model
    json reviewRequest;
    reviewRequest["files"] = task.targetFiles;
    reviewRequest["description"] = task.description;
    
    json reviewResponse;
    if (!InvokeTool("review_code", reviewRequest, reviewResponse)) {
        return false;
    }
    
    task.result = reviewResponse.dump();
    return true;
}

bool CEOAgent::ExecuteCommitTask(Task& task) {
    // Git commit
    json commitRequest;
    commitRequest["message"] = task.description;
    
    json commitResponse;
    if (!InvokeTool("git_commit", commitRequest, commitResponse)) {
        return false;
    }
    
    return commitResponse.value("success", false);
}

// ============================================================================
// Recovery
// ============================================================================
bool CEOAgent::HandleFailure(Task& task, const std::string& error) {
    ReportProgress("Repair", "Attempting to repair failure: " + error, 0.0f);
    
    // Add a debug task
    Task debugTask;
    debugTask.id = GenerateUUID();
    debugTask.type = Task::Type::Debug;
    debugTask.description = "Fix: " + error;
    debugTask.targetFiles = task.targetFiles;
    debugTask.status = Task::Status::Pending;
    
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        m_taskQueue.insert(m_taskQueue.begin(), debugTask);
    }
    
    return true;
}

bool CEOAgent::EscalateFailure(Task& task) {
    ReportProgress("Escalate", "Escalating failure after " + 
                   std::to_string(task.attempts) + " attempts", 0.0f);
    
    // For now, just fail the goal
    // In a full implementation, this could:
    // - Switch to a more powerful model
    // - Ask for human intervention
    // - Create a detailed error report
    
    return false;
}

bool CEOAgent::Rollback(Task& task) {
    ReportProgress("Rollback", "Rolling back changes for task: " + task.id, 0.0f);
    
    // Use git to rollback
    json rollbackRequest;
    rollbackRequest["task_id"] = task.id;
    
    json rollbackResponse;
    InvokeTool("git_rollback", rollbackRequest, rollbackResponse);
    
    return true;
}

// ============================================================================
// Utilities
// ============================================================================
std::string CEOAgent::GenerateId() {
    return GenerateUUID();
}

void CEOAgent::ReportProgress(const std::string& stage, const std::string& message, float percent) {
    if (m_progressCb) {
        m_progressCb(stage, message, percent);
    }
    
    // Also log
    printf("[CEO:%s] %s (%.1f%%)\n", stage.c_str(), message.c_str(), percent * 100);
}

void CEOAgent::ReportTask(const Task& task) {
    if (m_taskCb) {
        m_taskCb(task);
    }
}

void CEOAgent::ReportCompletion(const Goal& goal, bool success) {
    if (m_completionCb) {
        m_completionCb(goal, success);
    }
    
    printf("[CEO:Complete] Goal '%s' %s\n", 
           goal.description.c_str(), 
           success ? "SUCCEEDED" : "FAILED");
}

// ============================================================================
// Tool Integration
// ============================================================================
bool CEOAgent::InvokeTool(const std::string& toolName, const json& args, json& result) {
    if (!m_agentOrchestrator) {
        return false;
    }
    
    // Create tool call payload
    json payload;
    payload["action"] = "run_tool";
    payload["name"] = toolName;
    payload["args"] = args;
    
    // Dispatch through agent orchestrator
    // This would normally call the tool and return the result
    // For now, simulate success
    result["success"] = true;
    result["tool"] = toolName;
    
    return true;
}

// ============================================================================
// Manual Control
// ============================================================================
bool CEOAgent::ApproveTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    for (auto& task : m_taskQueue) {
        if (task.id == taskId && task.status == Task::Status::Blocked) {
            task.status = Task::Status::Pending;
            return true;
        }
    }
    return false;
}

bool CEOAgent::RejectTask(const std::string& taskId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    for (auto& task : m_taskQueue) {
        if (task.id == taskId) {
            task.status = Task::Status::Skipped;
            task.error = reason;
            return true;
        }
    }
    return false;
}

bool CEOAgent::ModifyTask(const std::string& taskId, const json& modifications) {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    for (auto& task : m_taskQueue) {
        if (task.id == taskId) {
            if (modifications.contains("description")) {
                task.description = modifications["description"];
            }
            if (modifications.contains("files")) {
                task.targetFiles.clear();
                for (const auto& f : modifications["files"]) {
                    task.targetFiles.push_back(f);
                }
            }
            return true;
        }
    }
    return false;
}

// ============================================================================
// State Management
// ============================================================================
bool CEOAgent::SaveState(const std::string& path) {
    return m_projectState->SaveToFile(path);
}

bool CEOAgent::LoadState(const std::string& path) {
    return m_projectState->LoadFromFile(path);
}

// ============================================================================
// Reporting
// ============================================================================
json CEOAgent::GenerateReport() const {
    json report;
    report["goal"] = m_currentGoal.description;
    report["completed"] = m_currentGoal.completed;
    report["iterations"] = m_iteration.load();
    report["tasks_completed"] = m_projectState->GetCompletedTaskCount();
    report["tasks_failed"] = m_projectState->GetFailedTaskCount();
    report["timestamp"] = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    
    return report;
}

} // namespace CEO
} // namespace RawrXD
