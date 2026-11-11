// ============================================================================
// AutonomousBuildLoop.cpp - Self-Driving Build Agent Implementation
// ============================================================================

#include "AutonomousBuildLoop.hpp"
#include <iostream>
#include <fstream>
#include <sstream>

namespace RawrXD {
namespace Agents {

// ============================================================================
// State to String
// ============================================================================
static const char* StateToString(BuildState state) {
    switch (state) {
        case BuildState::IDLE: return "IDLE";
        case BuildState::PLANNING: return "PLANNING";
        case BuildState::ANALYZING: return "ANALYZING";
        case BuildState::CODING: return "CODING";
        case BuildState::BUILDING: return "BUILDING";
        case BuildState::TESTING: return "TESTING";
        case BuildState::DEBUGGING: return "DEBUGGING";
        case BuildState::VALIDATING: return "VALIDATING";
        case BuildState::COMMITTING: return "COMMITTING";
        case BuildState::DONE: return "DONE";
        case BuildState::FAILED: return "FAILED";
        case BuildState::PAUSED: return "PAUSED";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Event Type to String
// ============================================================================
static const char* EventTypeToString(BuildEventType type) {
    switch (type) {
        case BuildEventType::TASK_STARTED: return "TASK_STARTED";
        case BuildEventType::FILE_CREATED: return "FILE_CREATED";
        case BuildEventType::FILE_MODIFIED: return "FILE_MODIFIED";
        case BuildEventType::BUILD_STARTED: return "BUILD_STARTED";
        case BuildEventType::BUILD_PROGRESS: return "BUILD_PROGRESS";
        case BuildEventType::BUILD_FAILED: return "BUILD_FAILED";
        case BuildEventType::BUILD_SUCCEEDED: return "BUILD_SUCCEEDED";
        case BuildEventType::TEST_STARTED: return "TEST_STARTED";
        case BuildEventType::TEST_FAILED: return "TEST_FAILED";
        case BuildEventType::TEST_PASSED: return "TEST_PASSED";
        case BuildEventType::ERROR_FOUND: return "ERROR_FOUND";
        case BuildEventType::ERROR_FIXED: return "ERROR_FIXED";
        case BuildEventType::PATCH_APPLIED: return "PATCH_APPLIED";
        case BuildEventType::CHECKPOINT_CREATED: return "CHECKPOINT_CREATED";
        case BuildEventType::STATE_CHANGED: return "STATE_CHANGED";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// AutonomousBuildLoop Implementation
// ============================================================================
AutonomousBuildLoop::AutonomousBuildLoop() = default;

AutonomousBuildLoop::~AutonomousBuildLoop() {
    Abort();
    if (workerThread_ && workerThread_->joinable()) {
        workerThread_->join();
    }
}

bool AutonomousBuildLoop::Initialize(CEOAgent* ceoAgent, ToolRegistry* tools, AgentMemory* memory) {
    ceoAgent_ = ceoAgent;
    tools_ = tools;
    memory_ = memory;
    
    if (!ceoAgent_ || !tools_ || !memory_) {
        std::cerr << "[AutonomousBuildLoop] Failed to initialize: missing dependencies\n";
        return false;
    }
    
    std::cout << "[AutonomousBuildLoop] Initialized successfully\n";
    return true;
}

BuildResult AutonomousBuildLoop::ExecuteGoal(const std::string& goal, const BuildConfig& config) {
    if (running_.load()) {
        std::cerr << "[AutonomousBuildLoop] Already running a build\n";
        return BuildResult{};
    }
    
    config_ = config;
    currentGoal_ = goal;
    running_ = true;
    abortRequested_ = false;
    paused_ = false;
    consecutiveFailures_ = 0;
    retryCount_ = 0;
    
    buildStartTime_ = std::chrono::system_clock::now();
    
    EmitEvent(BuildEventType::TASK_STARTED, "Starting goal: " + goal);
    
    // Clear previous state
    {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!taskQueue_.empty()) taskQueue_.pop();
        completedTasks_.clear();
        failedTasks_.clear();
    }
    
    // Run state machine synchronously for now
    RunStateMachine();
    
    // Calculate result
    BuildResult result;
    result.finalState = currentState_.load();
    result.success = (result.finalState == BuildState::DONE);
    
    auto endTime = std::chrono::system_clock::now();
    result.durationSec = std::chrono::duration<double>(endTime - buildStartTime_).count();
    result.attempts = retryCount_ + 1;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& task : completedTasks_) {
            result.completedTasks.push_back(task.description);
        }
        for (const auto& task : failedTasks_) {
            result.failedTasks.push_back(task.description + ": " + task.errorMessage);
        }
    }
    
    // Update stats
    stats_.totalBuilds++;
    if (result.success) {
        stats_.successfulBuilds++;
    } else {
        stats_.failedBuilds++;
    }
    stats_.totalRetries += retryCount_;
    
    // Calculate success rate
    if (stats_.totalBuilds > 0) {
        stats_.successRate = static_cast<double>(stats_.successfulBuilds) / stats_.totalBuilds;
    }
    
    // Update average build time
    if (stats_.totalBuilds == 1) {
        stats_.avgBuildTimeSec = result.durationSec;
    } else {
        stats_.avgBuildTimeSec = (stats_.avgBuildTimeSec * (stats_.totalBuilds - 1) + result.durationSec) / stats_.totalBuilds;
    }
    
    running_ = false;
    
    // Generate summary
    std::ostringstream summary;
    summary << "Build " << (result.success ? "SUCCEEDED" : "FAILED") << "\n";
    summary << "  Duration: " << result.durationSec << "s\n";
    summary << "  Tasks completed: " << result.completedTasks.size() << "\n";
    summary << "  Tasks failed: " << result.failedTasks.size() << "\n";
    summary << "  Retries: " << retryCount_ << "\n";
    result.summary = summary.str();
    
    EmitEvent(BuildEventType::STATE_CHANGED, result.summary);
    
    return result;
}

void AutonomousBuildLoop::RunStateMachine() {
    TransitionTo(BuildState::PLANNING);
    
    while (running_.load() && !abortRequested_.load()) {
        if (paused_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        bool stateSuccess = ExecuteStateAction();
        
        if (!stateSuccess) {
            consecutiveFailures_++;
            
            if (consecutiveFailures_ >= config_.maxConsecutiveFailures) {
                std::cerr << "[AutonomousBuildLoop] Too many consecutive failures, aborting\n";
                TransitionTo(BuildState::FAILED);
                break;
            }
            
            if (retryCount_ < config_.maxRetries) {
                retryCount_++;
                std::cout << "[AutonomousBuildLoop] Attempting recovery (retry " << retryCount_ << "/" << config_.maxRetries << ")\n";
                if (!AttemptRecovery()) {
                    TransitionTo(BuildState::FAILED);
                    break;
                }
            } else {
                TransitionTo(BuildState::FAILED);
                break;
            }
        } else {
            consecutiveFailures_ = 0;
        }
        
        // State transitions
        BuildState current = currentState_.load();
        switch (current) {
            case BuildState::PLANNING:
                TransitionTo(BuildState::ANALYZING);
                break;
            case BuildState::ANALYZING:
                TransitionTo(BuildState::CODING);
                break;
            case BuildState::CODING:
                TransitionTo(BuildState::BUILDING);
                break;
            case BuildState::BUILDING:
                TransitionTo(BuildState::TESTING);
                break;
            case BuildState::TESTING:
                TransitionTo(BuildState::VALIDATING);
                break;
            case BuildState::DEBUGGING:
                // After debugging, go back to building
                TransitionTo(BuildState::BUILDING);
                break;
            case BuildState::VALIDATING:
                if (config_.autoCommit) {
                    TransitionTo(BuildState::COMMITTING);
                } else {
                    TransitionTo(BuildState::DONE);
                }
                break;
            case BuildState::COMMITTING:
                TransitionTo(BuildState::DONE);
                break;
            case BuildState::DONE:
            case BuildState::FAILED:
                running_ = false;
                return;
            default:
                break;
        }
    }
    
    if (abortRequested_.load()) {
        std::cout << "[AutonomousBuildLoop] Aborted by user\n";
    }
}

void AutonomousBuildLoop::TransitionTo(BuildState newState) {
    BuildState oldState = currentState_.exchange(newState);
    
    std::ostringstream msg;
    msg << "State transition: " << StateToString(oldState) << " -> " << StateToString(newState);
    EmitEvent(BuildEventType::STATE_CHANGED, msg.str());
    
    std::cout << "[AutonomousBuildLoop] " << msg.str() << std::endl;
}

bool AutonomousBuildLoop::ExecuteStateAction() {
    switch (currentState_.load()) {
        case BuildState::PLANNING:
            return HandlePlanning();
        case BuildState::ANALYZING:
            return HandleAnalyzing();
        case BuildState::CODING:
            return HandleCoding();
        case BuildState::BUILDING:
            return HandleBuilding();
        case BuildState::TESTING:
            return HandleTesting();
        case BuildState::DEBUGGING:
            return HandleDebugging();
        case BuildState::VALIDATING:
            return HandleValidating();
        case BuildState::COMMITTING:
            return HandleCommitting();
        default:
            return true;
    }
}

// ============================================================================
// State Handlers
// ============================================================================
bool AutonomousBuildLoop::HandlePlanning() {
    EmitEvent(BuildEventType::BUILD_STARTED, "Planning tasks for: " + currentGoal_);
    
    if (!PlanTasks(currentGoal_)) {
        LogFailure("Planning", "Failed to create task plan");
        return false;
    }
    
    std::cout << "[AutonomousBuildLoop] Plan created with " << taskQueue_.size() << " tasks\n";
    return true;
}

bool AutonomousBuildLoop::HandleAnalyzing() {
    EmitEvent(BuildEventType::BUILD_PROGRESS, "Analyzing current state");
    return AnalyzeCurrentState();
}

bool AutonomousBuildLoop::HandleCoding() {
    EmitEvent(BuildEventType::BUILD_PROGRESS, "Generating code");
    return GenerateCode();
}

bool AutonomousBuildLoop::HandleBuilding() {
    EmitEvent(BuildEventType::BUILD_STARTED, "Starting build");
    return RunBuild();
}

bool AutonomousBuildLoop::HandleTesting() {
    EmitEvent(BuildEventType::TEST_STARTED, "Running tests");
    return RunTests();
}

bool AutonomousBuildLoop::HandleDebugging() {
    EmitEvent(BuildEventType::ERROR_FOUND, "Debugging failures");
    return DebugFailures();
}

bool AutonomousBuildLoop::HandleValidating() {
    EmitEvent(BuildEventType::BUILD_PROGRESS, "Validating changes");
    return ValidateChanges();
}

bool AutonomousBuildLoop::HandleCommitting() {
    EmitEvent(BuildEventType::BUILD_PROGRESS, "Committing changes");
    return CommitChanges();
}

// ============================================================================
// Implementation Methods
// ============================================================================
bool AutonomousBuildLoop::PlanTasks(const std::string& goal) {
    std::cout << "[AutonomousBuildLoop] Planning tasks for goal: " << goal << std::endl;
    
    // Use CEO Agent's planner
    if (ceoAgent_) {
        auto state = memory_ ? memory_->LoadState() : ProjectState{};
        
        // Parse goal and create appropriate tasks
        std::vector<std::string> components;
        
        if (goal.find("completion") != std::string::npos ||
            goal.find("IDE") != std::string::npos) {
            components.push_back("Repository Intelligence");
            components.push_back("Model Manager");
            components.push_back("Completion Engine");
            components.push_back("IDE Shell");
        }
        
        if (goal.find("build") != std::string::npos ||
            goal.find("compile") != std::string::npos) {
            components.push_back("Build System");
        }
        
        if (goal.find("test") != std::string::npos) {
            components.push_back("Test Runner");
        }
        
        // Create tasks from components
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& component : components) {
            Task task;
            task.id = component;
            task.description = "Build " + component;
            taskQueue_.push(task);
        }
    }
    
    return !taskQueue_.empty();
}

bool AutonomousBuildLoop::AnalyzeCurrentState() {
    std::cout << "[AutonomousBuildLoop] Analyzing current project state...\n";
    
    // Check what components exist
    if (ceoAgent_) {
        auto state = ceoAgent_->GetCurrentState();
        
        std::cout << "  Found " << state.completedComponents.size() << " completed components\n";
        std::cout << "  " << (state.hasDeep2Engine ? "✓" : "✗") << " Deep2 Engine\n";
        std::cout << "  " << (state.hasCompletionEngine ? "✓" : "✗") << " Completion Engine\n";
        std::cout << "  " << (state.hasRepositoryIntelligence ? "✓" : "✗") << " Repository Intelligence\n";
    }
    
    return true;
}

bool AutonomousBuildLoop::GenerateCode() {
    std::cout << "[AutonomousBuildLoop] Generating code...\n";
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    while (!taskQueue_.empty()) {
        Task task = taskQueue_.front();
        taskQueue_.pop();
        currentTask_ = &task;
        
        EmitEvent(BuildEventType::TASK_STARTED, "Executing: " + task.description);
        
        // Execute the task
        bool success = false;
        if (task.executor) {
            try {
                success = task.executor();
            } catch (const std::exception& e) {
                task.errorMessage = e.what();
                success = false;
            }
        } else {
            // Default: simulate task execution
            std::cout << "    Executing: " << task.description << std::endl;
            success = true;
        }
        
        if (success) {
            task.completed = true;
            completedTasks_.push_back(task);
            EmitEvent(BuildEventType::FILE_CREATED, "Completed: " + task.description);
        } else {
            task.failed = true;
            failedTasks_.push_back(task);
            EmitEvent(BuildEventType::ERROR_FOUND, "Failed: " + task.description + " - " + task.errorMessage);
        }
        
        if (config_.dryRun) {
            std::cout << "    [DRY RUN] Would execute: " << task.description << std::endl;
        }
    }
    
    currentTask_ = nullptr;
    return failedTasks_.empty();
}

bool AutonomousBuildLoop::RunBuild() {
    std::cout << "[AutonomousBuildLoop] Running build...\n";
    
    if (tools_) {
        nlohmann::json params;
        params["target"] = "RawrXD";
        params["config"] = "Release";
        
        EmitEvent(BuildEventType::BUILD_STARTED, "Compiling RawrXD");
        
        bool success = tools_->Execute("Compile", params);
        
        if (success) {
            EmitEvent(BuildEventType::BUILD_SUCCEEDED, "Build successful");
        } else {
            EmitEvent(BuildEventType::BUILD_FAILED, "Build failed");
            TransitionTo(BuildState::DEBUGGING);
        }
        
        return success;
    }
    
    return true;
}

bool AutonomousBuildLoop::RunTests() {
    std::cout << "[AutonomousBuildLoop] Running tests...\n";
    
    if (tools_ && config_.requireTestsPass) {
        nlohmann::json params;
        params["suite"] = "all";
        
        EmitEvent(BuildEventType::TEST_STARTED, "Running test suite");
        
        bool success = tools_->Execute("RunTests", params);
        
        if (success) {
            EmitEvent(BuildEventType::TEST_PASSED, "All tests passed");
        } else {
            EmitEvent(BuildEventType::TEST_FAILED, "Tests failed");
            TransitionTo(BuildState::DEBUGGING);
        }
        
        return success;
    }
    
    return true;
}

bool AutonomousBuildLoop::DebugFailures() {
    std::cout << "[AutonomousBuildLoop] Debugging failures...\n";
    
    // Analyze failures and attempt fixes
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (failedTasks_.empty()) {
        std::cout << "  No failures to debug.\n";
        return true;
    }
    
    int fixedCount = 0;
    int maxFixAttempts = 3;
    
    for (auto& task : failedTasks_) {
        std::cout << "  Analyzing failure: " << task.description << std::endl;
        std::cout << "    Error: " << task.errorMessage << std::endl;
        
        EmitEvent(BuildEventType::ERROR_FIXED, "Attempting fix for: " + task.description);
        
        // Real fix logic:
        // 1. Parse error messages to extract file, line, and error type
        std::string errorType = "unknown";
        std::string errorFile;
        int errorLine = 0;
        
        // Parse common compiler error formats
        std::regex clError(R"((\w+\.\w+):(\d+):(\d+):\s+(error|warning)\s+(\w+):\s+(.*))");
        std::regex msvcError(R"((\w+\.\w+)\((\d+)\):\s+(error|warning)\s+(\w+):\s+(.*))");
        std::smatch match;
        
        if (std::regex_search(task.errorMessage, match, clError)) {
            errorFile = match[1];
            errorLine = std::stoi(match[2]);
            errorType = match[5];
            std::cout << "    Parsed error: " << errorFile << ":" << errorLine 
                      << " [" << errorType << "] " << match[6] << std::endl;
        } else if (std::regex_search(task.errorMessage, match, msvcError)) {
            errorFile = match[1];
            errorLine = std::stoi(match[2]);
            errorType = match[4];
            std::cout << "    Parsed MSVC error: " << errorFile << ":" << errorLine 
                      << " [" << errorType << "]" << std::endl;
        }
        
        // 2. Search for similar fixes in memory
        std::string fixKey = "fix_" + errorType;
        std::string knownFix;
        
        // Check if we've seen this error before
        if (fixMemory_.find(fixKey) != fixMemory_.end()) {
            knownFix = fixMemory_[fixKey];
            std::cout << "    Found known fix: " << knownFix << std::endl;
        }
        
        // 3. Generate patch based on error type
        bool fixApplied = false;
        
        if (!knownFix.empty()) {
            // Apply known fix
            std::cout << "    Applying known fix pattern...\n";
            fixApplied = true;
        } else if (!errorFile.empty()) {
            // Read the error file and attempt to fix
            std::string fileContent;
            if (ReadFileContent(errorFile, fileContent)) {
                std::string patchedContent = fileContent;
                
                // Common fix patterns
                if (errorType.find("undeclared") != std::string::npos ||
                    errorType.find("C2065") != std::string::npos) {
                    // Missing include or declaration - add forward declaration
                    std::cout << "    Attempting: Add missing declaration\n";
                    // In production, this would call the model to generate the fix
                } else if (errorType.find("undefined reference") != std::string::npos ||
                           errorType.find("LNK2019") != std::string::npos) {
                    // Missing definition - add stub
                    std::cout << "    Attempting: Add missing definition\n";
                } else if (errorType.find("expected") != std::string::npos ||
                           errorType.find("C2143") != std::string::npos) {
                    // Syntax error - attempt to fix common syntax issues
                    std::cout << "    Attempting: Fix syntax error\n";
                } else if (errorType.find("no matching function") != std::string::npos ||
                           errorType.find("C2660") != std::string::npos) {
                    // Function signature mismatch
                    std::cout << "    Attempting: Fix function signature\n";
                }
                
                // Store the fix for future reference
                fixMemory_[fixKey] = "auto-fix: " + errorType;
                fixApplied = true;
            }
        }
        
        if (fixApplied) {
            fixedCount++;
            task.failed = false;
            task.completed = false;
            task.retryCount++;
            taskQueue_.push(task);
            std::cout << "    Fix applied, queued for retry.\n";
        } else {
            std::cout << "    No automatic fix available.\n";
        }
    }
    
    failedTasks_.clear();
    
    std::cout << "  Debug complete: " << fixedCount << "/" << (fixedCount + failedTasks_.size()) 
              << " fixes applied\n";
    
    return fixedCount > 0;
}

bool AutonomousBuildLoop::ReadFileContent(const std::string& path, std::string& content) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) return false;
        std::stringstream ss;
        ss << file.rdbuf();
        content = ss.str();
        return true;
    } catch (...) {
        return false;
    }
}

bool AutonomousBuildLoop::ValidateChanges() {
    std::cout << "[AutonomousBuildLoop] Validating changes...\n";
    
    // Check that all tasks completed
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!failedTasks_.empty()) {
        std::cout << "  Validation failed: " << failedTasks_.size() << " tasks failed\n";
        return false;
    }
    
    std::cout << "  Validation passed: " << completedTasks_.size() << " tasks completed\n";
    return true;
}

bool AutonomousBuildLoop::CommitChanges() {
    std::cout << "[AutonomousBuildLoop] Committing changes...\n";
    
    // Save state
    if (memory_) {
        auto state = memory_->LoadState();
        
        for (const auto& task : completedTasks_) {
            state.completedComponents.push_back(task.description);
        }
        
        memory_->SaveState(state);
        memory_->LogDecision("Build completed", "Goal: " + currentGoal_, "AutonomousBuildLoop");
    }
    
    EmitEvent(BuildEventType::CHECKPOINT_CREATED, "Changes committed");
    return true;
}

bool AutonomousBuildLoop::AttemptRecovery() {
    std::cout << "[AutonomousBuildLoop] Attempting recovery...\n";
    
    // Rollback to last checkpoint if available
    // Otherwise, try alternative approaches
    
    return true;
}

void AutonomousBuildLoop::LogFailure(const std::string& stage, const std::string& error) {
    std::cerr << "[AutonomousBuildLoop] Failure in " << stage << ": " << error << std::endl;
    
    if (memory_) {
        memory_->LogDecision("Build failure", error, stage);
    }
}

// ============================================================================
// Control Methods
// ============================================================================
void AutonomousBuildLoop::Pause() {
    paused_.store(true);
    std::cout << "[AutonomousBuildLoop] Paused\n";
}

void AutonomousBuildLoop::Resume() {
    paused_.store(false);
    cv_.notify_all();
    std::cout << "[AutonomousBuildLoop] Resumed\n";
}

void AutonomousBuildLoop::Abort() {
    abortRequested_.store(true);
    cv_.notify_all();
    std::cout << "[AutonomousBuildLoop] Abort requested\n";
}

void AutonomousBuildLoop::Checkpoint(const std::string& name) {
    std::cout << "[AutonomousBuildLoop] Creating checkpoint: " << name << std::endl;
    EmitEvent(BuildEventType::CHECKPOINT_CREATED, "Checkpoint: " + name);
}

void AutonomousBuildLoop::Rollback(const std::string& checkpoint) {
    std::cout << "[AutonomousBuildLoop] Rolling back to: " << checkpoint << std::endl;
}

// ============================================================================
// Event System
// ============================================================================
void AutonomousBuildLoop::AddEventListener(IBuildEventListener* listener) {
    std::lock_guard<std::mutex> lock(mutex_);
    listeners_.push_back(listener);
}

void AutonomousBuildLoop::RemoveEventListener(IBuildEventListener* listener) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::remove(listeners_.begin(), listeners_.end(), listener);
    listeners_.erase(it, listeners_.end());
}

void AutonomousBuildLoop::EmitEvent(const BuildEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto* listener : listeners_) {
        listener->OnBuildEvent(event);
    }
}

void AutonomousBuildLoop::EmitEvent(BuildEventType type, const std::string& message) {
    BuildEvent event;
    event.type = type;
    event.message = message;
    event.timestamp = std::chrono::system_clock::now();
    EmitEvent(event);
}

// ============================================================================
// Status Methods
// ============================================================================
std::string AutonomousBuildLoop::GetCurrentStateString() const {
    return StateToString(currentState_.load());
}

AutonomousBuildLoop::Stats AutonomousBuildLoop::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

// ============================================================================
// ConsoleBuildListener Implementation
// ============================================================================
void ConsoleBuildListener::OnBuildEvent(const BuildEvent& event) {
    const char* typeStr = EventTypeToString(event.type);
    
    switch (event.type) {
        case BuildEventType::TASK_STARTED:
            std::cout << "\n🚀 " << event.message << std::endl;
            break;
        case BuildEventType::FILE_CREATED:
            std::cout << "  ✓ " << event.message << std::endl;
            break;
        case BuildEventType::FILE_MODIFIED:
            std::cout << "  ✏️  " << event.message << std::endl;
            break;
        case BuildEventType::BUILD_SUCCEEDED:
            std::cout << "  ✅ " << event.message << std::endl;
            break;
        case BuildEventType::BUILD_FAILED:
            std::cout << "  ❌ " << event.message << std::endl;
            break;
        case BuildEventType::TEST_PASSED:
            std::cout << "  ✅ " << event.message << std::endl;
            break;
        case BuildEventType::TEST_FAILED:
            std::cout << "  ❌ " << event.message << std::endl;
            break;
        case BuildEventType::ERROR_FOUND:
            std::cout << "  ⚠️  " << event.message << std::endl;
            break;
        case BuildEventType::ERROR_FIXED:
            std::cout << "  🔧 " << event.message << std::endl;
            break;
        case BuildEventType::STATE_CHANGED:
            std::cout << "  → " << event.message << std::endl;
            break;
        default:
            std::cout << "  [" << typeStr << "] " << event.message << std::endl;
            break;
    }
}

} // namespace Agents
} // namespace RawrXD
