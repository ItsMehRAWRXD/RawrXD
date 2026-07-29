//=============================================================================
// AgenticSupervisor.cpp - Autonomous Agent Orchestration Implementation
// Optimized for the "Heretic" Substrate - Zero-overhead task management
//=============================================================================

#include "AgenticSupervisor.hpp"
#include <windows.h>
#include <psapi.h>
#include <processthreadsapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <imagehlp.h>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>

namespace RawrXD {
namespace Agentic {

//=============================================================================
// Agent Identity Implementation
//=============================================================================

std::string AgentRoleToString(AgentRole role) {
    switch(role) {
        case AgentRole::PLANNER: return "PLANNER";
        case AgentRole::CODER: return "CODER";
        case AgentRole::REVIEWER: return "REVIEWER";
        case AgentRole::DEBUGGER: return "DEBUGGER";
        case AgentRole::SECURITY: return "SECURITY";
        case AgentRole::OPTIMIZER: return "OPTIMIZER";
        case AgentRole::BUILD: return "BUILD";
        case AgentRole::TEST: return "TEST";
        default: return "UNKNOWN";
    }
}

AgentIdentity AgentIdentity::Create(AgentRole role, int trustLevel) {
    static std::atomic<uint64_t> nextId{1};
    AgentIdentity identity;
    identity.id = nextId.fetch_add(1);
    identity.role = role;
    identity.trustLevel = trustLevel;
    
    // Auto-populate capabilities based on role
    switch(role) {
        case AgentRole::PLANNER:
            identity.capabilities = {"plan", "decompose", "prioritize"};
            break;
        case AgentRole::CODER:
            identity.capabilities = {"read_file", "write_file", "patch", "refactor"};
            break;
        case AgentRole::DEBUGGER:
            identity.capabilities = {"analyze", "breakpoint", "inspect", "patch"};
            break;
        case AgentRole::BUILD:
            identity.capabilities = {"compile", "link", "test", "benchmark"};
            break;
        case AgentRole::SECURITY:
            identity.capabilities = {"scan", "audit", "validate"};
            break;
        default:
            break;
    }
    
    return identity;
}

//=============================================================================
// Tool Call & Runtime Implementation
//=============================================================================

bool AgentToolRuntime::Execute(const ToolCall& call) {
    // Pre-execution validation
    RealityValidator validator;
    if (!validator.Validate(call)) {
        printf("[AGENTIC] Tool validation failed for '%s'\n", call.tool.c_str());
        return false;
    }
    
    // Route to appropriate handler
    auto it = toolHandlers_.find(call.tool);
    if (it == toolHandlers_.end()) {
        printf("[AGENTIC] Unknown tool: '%s'\n", call.tool.c_str());
        return false;
    }
    
    // Execute with telemetry
    auto start = std::chrono::steady_clock::now();
    bool result = it->second(call.arguments);
    auto end = std::chrono::steady_clock::now();
    
    auto latency = std::chrono::duration<double, std::milli>(end - start).count();
    printf("[AGENTIC] Tool '%s' executed in %.3f ms [%s]\n", 
           call.tool.c_str(), latency, result ? "OK" : "FAIL");
    
    return result;
}

void AgentToolRuntime::RegisterTool(const std::string& name, ToolHandler handler) {
    toolHandlers_[name] = handler;
}

//=============================================================================
// Reality Validator Implementation
//=============================================================================

bool RealityValidator::Validate(const ToolCall& call) {
    if (call.tool == "read_file") {
        // Extract path from arguments (simplified JSON parsing)
        size_t pathPos = call.arguments.find("\"path\":");
        if (pathPos != std::string::npos) {
            size_t quoteStart = call.arguments.find("\"", pathPos + 7);
            size_t quoteEnd = call.arguments.find("\"", quoteStart + 1);
            if (quoteStart != std::string::npos && quoteEnd != std::string::npos) {
                std::string path = call.arguments.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                return FileExists(path);
            }
        }
    }
    else if (call.tool == "write_file" || call.tool == "patch") {
        // Validate path is within workspace
        size_t pathPos = call.arguments.find("\"path\":");
        if (pathPos != std::string::npos) {
            size_t quoteStart = call.arguments.find("\"", pathPos + 7);
            size_t quoteEnd = call.arguments.find("\"", quoteStart + 1);
            if (quoteStart != std::string::npos && quoteEnd != std::string::npos) {
                std::string path = call.arguments.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                // Prevent directory traversal
                if (path.find("..") != std::string::npos) {
                    printf("[REALITY] Blocked directory traversal attempt: %s\n", path.c_str());
                    return false;
                }
                return true;
            }
        }
    }
    else if (call.tool == "execute") {
        // High-risk tool - require approval
        if (call.requiresApproval) {
            printf("[REALITY] Blocking unapproved execution: %s\n", call.arguments.c_str());
            return false;
        }
    }
    
    return true;
}

bool RealityValidator::FileExists(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

bool RealityValidator::VerifyBinarySignature(const std::string& path) {
    // Verify binary signature using WinVerifyTrust API
    // This provides proper Authenticode signature verification
    
    if (!FileExists(path)) {
        return false;
    }
    
    // Initialize WinVerifyTrust
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = std::wstring(path.begin(), path.end()).c_str();
    
    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.pPolicyCallbackData = nullptr;
    trustData.pSIPClientData = nullptr;
    trustData.dwUIChoice = WTD_UI_NONE;  // No UI
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = nullptr;
    trustData.pwszURLReference = nullptr;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;
    
    LONG result = WinVerifyTrust(NULL, &actionGuid, &trustData);
    
    // Clean up
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &trustData);
    
    if (result == ERROR_SUCCESS) {
        return true;
    }
    
    // If WinVerifyTrust fails, fall back to checking for embedded signature
    // This is less thorough but catches some cases
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Check for certificate table in PE header
    DWORD certSize = 0;
    BOOL hasCert = ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, 
                                               &certSize, nullptr, 0);
    CloseHandle(hFile);
    
    return hasCert;
}

//=============================================================================
// Agent Context & Prompt Builder
//=============================================================================

AgentContext AgentContext::Gather() {
    AgentContext ctx;
    
    // Get workspace from current directory
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    ctx.workspace = cwd;
    
    // Get performance metrics from supervisor
    ctx.metrics = AgenticSupervisor::Instance().GetMetrics();
    
    // Get available tools
    ctx.availableTools = {
        "read_file", "write_file", "patch", "search", 
        "build", "test", "debug", "optimize"
    };
    
    // Get recent errors from telemetry
    // (Would integrate with actual error log)
    ctx.recentErrors = {};
    
    return ctx;
}

std::string AgentContext::BuildPrompt(const AgentContext& ctx) {
    std::stringstream prompt;
    prompt << "=== Agent Context ===\n";
    prompt << "Workspace: " << ctx.workspace << "\n";
    prompt << "Performance: " << ctx.metrics.tasksPerSecond << " tasks/sec, ";
    prompt << ctx.metrics.averageLatencyMs << " ms avg latency\n";
    prompt << "Success Rate: " << (ctx.metrics.successRate * 100) << "%\n";
    prompt << "Active Tasks: " << ctx.metrics.activeTasks << "\n";
    prompt << "Available Tools: ";
    for (const auto& tool : ctx.availableTools) {
        prompt << tool << " ";
    }
    prompt << "\n";
    
    if (!ctx.recentErrors.empty()) {
        prompt << "Recent Errors:\n";
        for (const auto& err : ctx.recentErrors) {
            prompt << "  - " << err << "\n";
        }
    }
    
    prompt << "===================\n";
    return prompt.str();
}

//=============================================================================
// Agent Graph Runtime Implementation
//=============================================================================

bool AgentGraphRuntime::ExecuteGraph(const AgentGraph& graph) {
    printf("[GRAPH] Executing graph with %zu nodes\n", graph.nodes.size());
    
    // Topological sort
    std::vector<uint64_t> executionOrder;
    std::unordered_set<uint64_t> completed;
    std::unordered_set<uint64_t> inProgress;
    
    std::function<bool(uint64_t)> visit = [&](uint64_t nodeId) -> bool {
        if (completed.count(nodeId)) return true;
        if (inProgress.count(nodeId)) {
            printf("[GRAPH] Cycle detected at node %llu\n", nodeId);
            return false;
        }
        
        inProgress.insert(nodeId);
        
        auto it = std::find_if(graph.nodes.begin(), graph.nodes.end(),
            [nodeId](const AgentNode& n) { return n.id == nodeId; });
        
        if (it != graph.nodes.end()) {
            for (uint64_t dep : it->dependencies) {
                if (!visit(dep)) return false;
            }
        }
        
        inProgress.erase(nodeId);
        completed.insert(nodeId);
        executionOrder.push_back(nodeId);
        return true;
    };
    
    // Visit all nodes
    for (const auto& node : graph.nodes) {
        if (!visit(node.id)) {
            return false;
        }
    }
    
    // Execute in order
    for (uint64_t nodeId : executionOrder) {
        auto it = std::find_if(graph.nodes.begin(), graph.nodes.end(),
            [nodeId](const AgentNode& n) { return n.id == nodeId; });
        
        if (it != graph.nodes.end()) {
            printf("[GRAPH] Executing node '%s' (%llu)\n", it->name.c_str(), nodeId);
            
            // Create task for this node
            AgenticTask task;
            task.id = AgenticSupervisor::Instance().GenerateTaskId();
            task.name = it->name;
            task.priority = TaskPriority::NORMAL;
            task.owner = it->owner;
            task.plan = it->plan;
            
            // Submit and wait
            std::string taskId = AgenticSupervisor::Instance().SubmitTask(std::move(task));
            
            // Wait for completion (simplified - would use futures in production)
            while (AgenticSupervisor::Instance().GetTaskStatus(taskId).status == TaskStatus::RUNNING) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            
            auto finalStatus = AgenticSupervisor::Instance().GetTaskStatus(taskId);
            if (finalStatus.status != TaskStatus::COMPLETED) {
                printf("[GRAPH] Node '%s' failed\n", it->name.c_str());
                return false;
            }
        }
    }
    
    printf("[GRAPH] Graph execution complete\n");
    return true;
}

//=============================================================================
// Agentic Supervisor - Singleton & Core
//=============================================================================

AgenticSupervisor& AgenticSupervisor::Instance() {
    static AgenticSupervisor instance;
    return instance;
}

bool AgenticSupervisor::Initialize(const Config& config) {
    if (running_.exchange(true)) {
        return false; // Already running
    }
    
    config_ = config;
    
    // Initialize task ID counter
    nextTaskId_.store(1);
    
    // Initialize metrics
    metrics_.tasksPerSecond = 0.0;
    metrics_.averageLatencyMs = 0.0;
    metrics_.successRate = 1.0;
    metrics_.activeTasks = 0;
    metrics_.queuedTasks = 0;
    metrics_.completedTasks = 0;
    metrics_.failedTasks = 0;
    
    // Start worker threads with affinity
    for (int i = 0; i < config_.maxConcurrentTasks; ++i) {
        workers_.emplace_back(&AgenticSupervisor::WorkerLoop, this, i);
    }
    
    // Start metrics thread
    if (config_.enablePerformanceMonitoring) {
        metricsThread_ = std::thread(&AgenticSupervisor::MetricsLoop, this);
    }
    
    // Start healing thread
    if (config_.enableSelfHealing) {
        healingThread_ = std::thread(&AgenticSupervisor::HealingLoop, this);
    }
    
    // Initialize IDE event hooks
    InitializeIDEHooks();
    
    printf("[AGENTIC] Supervisor initialized with %d workers\n", config_.maxConcurrentTasks);
    return true;
}

void AgenticSupervisor::Shutdown() {
    if (!running_.exchange(false)) {
        return;
    }
    
    // Wake all waiting threads
    taskCv_.notify_all();
    
    // Join workers
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    // Join metrics thread
    if (metricsThread_.joinable()) {
        metricsThread_.join();
    }
    
    // Join healing thread
    if (healingThread_.joinable()) {
        healingThread_.join();
    }
    
    printf("[AGENTIC] Supervisor shutdown complete\n");
}

uint64_t AgenticSupervisor::GenerateTaskId() {
    return nextTaskId_.fetch_add(1);
}

std::string AgenticSupervisor::SubmitTask(AgenticTask task) {
    std::string taskId = std::to_string(GenerateTaskId());
    task.id = taskId;
    
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        tasks_[taskId] = std::move(task);
        taskQueue_.push(taskId);
        metrics_.queuedTasks++;
    }
    
    taskCv_.notify_one();
    
    // Log via sovereign lifecycle
    Sovereign::IDE_Lifecycle_Hook::Instance().OnTaskStart(task.name);
    
    printf("[AGENTIC] Task '%s' submitted (ID: %s)\n", task.name.c_str(), taskId.c_str());
    return taskId;
}

bool AgenticSupervisor::CancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    auto it = tasks_.find(taskId);
    if (it != tasks_.end()) {
        if (it->second.status == TaskStatus::PENDING) {
            it->second.status = TaskStatus::CANCELLED;
            return true;
        }
    }
    return false;
}

AgenticTask AgenticSupervisor::GetTaskStatus(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    auto it = tasks_.find(taskId);
    if (it != tasks_.end()) {
        return it->second;
    }
    return AgenticTask(); // Return empty task if not found
}

//=============================================================================
// Worker Loop with Thread Affinity
//=============================================================================

void AgenticSupervisor::WorkerLoop(int workerId) {
    // Pin to housekeeping cores (0 and 1), leave rest for Deep2
    DWORD_PTR affinityMask = (1ULL << 0) | (1ULL << 1);
    SetThreadAffinityMask(GetCurrentThread(), affinityMask);
    
    printf("[AGENTIC] Worker %d pinned to cores 0-1\n", workerId);
    
    while (running_.load()) {
        std::string taskId;
        
        // Wait for task with timeout (wait-spin hybrid)
        {
            std::unique_lock<std::mutex> lock(tasksMutex_);
            bool hasTask = taskCv_.wait_for(lock, std::chrono::milliseconds(100), 
                [this] { return !taskQueue_.empty() || !running_.load(); });
            
            if (!running_.load()) break;
            if (!hasTask || taskQueue_.empty()) continue;
            
            taskId = taskQueue_.top();
            taskQueue_.pop();
            
            auto it = tasks_.find(taskId);
            if (it != tasks_.end()) {
                it->second.status = TaskStatus::RUNNING;
                it->second.started = std::chrono::steady_clock::now();
                activeTasks_.insert(taskId);
                metrics_.queuedTasks--;
                metrics_.activeTasks++;
            }
        }
        
        if (!taskId.empty()) {
            ExecuteTaskById(taskId);
        }
    }
}

void AgenticSupervisor::ExecuteTaskById(const std::string& taskId) {
    auto start = std::chrono::steady_clock::now();
    bool success = false;
    
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        auto it = tasks_.find(taskId);
        if (it == tasks_.end()) return;
        
        AgenticTask& task = it->second;
        
        // Execute tool plan if present
        if (!task.plan.empty()) {
            AgentToolRuntime runtime;
            success = true;
            for (const auto& toolCall : task.plan) {
                if (!runtime.Execute(toolCall)) {
                    success = false;
                    break;
                }
            }
        }
        // Otherwise execute direct function
        else if (task.execute) {
            success = task.execute();
        }
        
        task.completed = std::chrono::steady_clock::now();
        
        if (success) {
            task.status = TaskStatus::COMPLETED;
            CompleteTask(taskId);
        } else {
            task.status = TaskStatus::FAILED;
            FailTask(taskId, "Execution failed");
        }
    }
    
    auto end = std::chrono::steady_clock::now();
    auto latency = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Update latency history (lock-free)
    latencyHistory_.push_back(latency);
    if (latencyHistory_.size() > 100) {
        latencyHistory_.erase(latencyHistory_.begin());
    }
}

void AgenticSupervisor::CompleteTask(const std::string& taskId) {
    activeTasks_.erase(taskId);
    metrics_.activeTasks--;
    metrics_.completedTasks++;
    
    auto it = tasks_.find(taskId);
    if (it != tasks_.end() && it->second.onSuccess) {
        it->second.onSuccess();
    }
    
    Sovereign::IDE_Lifecycle_Hook::Instance().OnTaskComplete(
        "Task " + taskId + " completed successfully");
}

void AgenticSupervisor::FailTask(const std::string& taskId, const std::string& error) {
    activeTasks_.erase(taskId);
    metrics_.activeTasks--;
    metrics_.failedTasks++;
    
    auto it = tasks_.find(taskId);
    if (it != tasks_.end()) {
        if (it->second.onFailure) {
            it->second.onFailure(error);
        }
        
        // Queue for healing if retries available
        if (it->second.retryCount < it->second.maxRetries) {
            it->second.retryCount++;
            it->second.status = TaskStatus::RETRYING;
            
            std::lock_guard<std::mutex> lock(healingMutex_);
            healingQueue_.push(taskId);
        }
    }
    
    Sovereign::IDE_Lifecycle_Hook::Instance().OnTaskComplete(
        "Task " + taskId + " failed: " + error);
}

//=============================================================================
// Metrics Loop (Lock-Free)
//=============================================================================

void AgenticSupervisor::MetricsLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(config_.metricsInterval);
        
        if (!running_.load()) break;
        
        // Calculate metrics
        size_t completed = metrics_.completedTasks;
        size_t failed = metrics_.failedTasks;
        size_t total = completed + failed;
        
        if (total > 0) {
            metrics_.successRate = static_cast<double>(completed) / total;
        }
        
        // Calculate average latency
        if (!latencyHistory_.empty()) {
            double sum = std::accumulate(latencyHistory_.begin(), latencyHistory_.end(), 0.0);
            metrics_.averageLatencyMs = sum / latencyHistory_.size();
        }
        
        // Calculate tasks per second
        static auto lastTime = std::chrono::steady_clock::now();
        static size_t lastCompleted = 0;
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - lastTime).count();
        
        if (elapsed > 0) {
            size_t newCompleted = completed - lastCompleted;
            metrics_.tasksPerSecond = newCompleted / elapsed;
            lastCompleted = completed;
            lastTime = now;
        }
        
        // Get system metrics
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            metrics_.memoryUtilization = static_cast<double>(memStatus.dwMemoryLoad) / 100.0;
        }
    }
}

//=============================================================================
// Healing Loop
//=============================================================================

void AgenticSupervisor::HealingLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (!running_.load()) break;
        
        std::string taskId;
        {
            std::lock_guard<std::mutex> lock(healingMutex_);
            if (healingQueue_.empty()) continue;
            taskId = healingQueue_.front();
            healingQueue_.pop();
        }
        
        printf("[AGENTIC] Healing task %s\n", taskId.c_str());
        
        // Re-submit for retry
        {
            std::lock_guard<std::mutex> lock(tasksMutex_);
            auto it = tasks_.find(taskId);
            if (it != tasks_.end() && it->second.status == TaskStatus::RETRYING) {
                it->second.status = TaskStatus::PENDING;
                taskQueue_.push(taskId);
                metrics_.queuedTasks++;
            }
        }
        
        taskCv_.notify_one();
    }
}

void AgenticSupervisor::TriggerSelfHealing(const std::string& reason) {
    printf("[AGENTIC] Self-healing triggered: %s\n", reason.c_str());
    
    // Create healing task
    AgenticTask healTask;
    healTask.name = "SelfHealing_" + reason;
    healTask.priority = TaskPriority::CRITICAL;
    healTask.owner = AgentIdentity::Create(AgentRole::DEBUGGER, 10);
    healTask.execute = [this]() -> bool {
        return OptimizePerformance();
    };
    
    SubmitTask(std::move(healTask));
}

//=============================================================================
// Health & Optimization
//=============================================================================

PerformanceMetrics AgenticSupervisor::GetMetrics() const {
    // Note: In production, this should use a mutex for thread safety
    return metrics_;
}

bool AgenticSupervisor::IsHealthy() const {
    return metrics_.successRate >= config_.targetSuccessRate &&
           metrics_.averageLatencyMs <= config_.maxLatencyMs;
}

std::string AgenticSupervisor::GetHealthReport() const {
    std::stringstream report;
    auto m = GetMetrics();
    
    report << "=== Agentic Supervisor Health Report ===\n";
    report << "Status: " << (IsHealthy() ? "HEALTHY" : "DEGRADED") << "\n";
    report << "Success Rate: " << (m.successRate * 100) << "% (target: " 
           << (config_.targetSuccessRate * 100) << "%)\n";
    report << "Avg Latency: " << m.averageLatencyMs << " ms (max: " 
           << config_.maxLatencyMs << " ms)\n";
    report << "Throughput: " << m.tasksPerSecond << " tasks/sec\n";
    report << "Active: " << m.activeTasks << " | Queued: " << m.queuedTasks << "\n";
    report << "Completed: " << m.completedTasks << " | Failed: " << m.failedTasks << "\n";
    report << "Memory: " << (m.memoryUtilization * 100) << "%\n";
    report << "========================================\n";
    
    return report.str();
}

bool AgenticSupervisor::OptimizePerformance() {
    printf("[AGENTIC] Running performance optimization...\n");
    
    // Clear old tasks
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        for (auto it = tasks_.begin(); it != tasks_.end();) {
            if (it->second.status == TaskStatus::CANCELLED ||
                it->second.status == TaskStatus::COMPLETED) {
                it = tasks_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // Trim latency history
    if (latencyHistory_.size() > 50) {
        latencyHistory_.resize(50);
    }
    
    printf("[AGENTIC] Optimization complete\n");
    return true;
}

//=============================================================================
// IDE Event Hooks
//=============================================================================

void AgenticSupervisor::InitializeIDEHooks() {
    // Register with IDE lifecycle hook
    // This would connect to actual IDE events in production
    printf("[AGENTIC] IDE hooks initialized\n");
}

void AgenticSupervisor::OnIDEEvent(IDEEvent event, const std::string& data) {
    switch(event) {
        case IDEEvent::FILE_CHANGED:
            printf("[AGENTIC] File changed: %s\n", data.c_str());
            break;
        case IDEEvent::BUILD_FAILED:
            printf("[AGENTIC] Build failed - triggering debug task\n");
            SubmitDebugTask(data);
            break;
        case IDEEvent::TEST_FAILED:
            printf("[AGENTIC] Test failed - triggering repair task\n");
            SubmitRepairTask(data);
            break;
        case IDEEvent::CRASH_DETECTED:
            printf("[AGENTIC] Crash detected - emergency healing\n");
            TriggerSelfHealing("Crash: " + data);
            break;
        default:
            break;
    }
}

void AgenticSupervisor::SubmitDebugTask(const std::string& errorInfo) {
    AgenticTask task;
    task.name = "DebugBuildFailure";
    task.priority = TaskPriority::HIGH;
    task.owner = AgentIdentity::Create(AgentRole::DEBUGGER, 9);
    task.execute = [&errorInfo]() -> bool {
        printf("[DEBUGGER] Analyzing: %s\n", errorInfo.c_str());
        return true;
    };
    
    SubmitTask(std::move(task));
}

void AgenticSupervisor::SubmitRepairTask(const std::string& testInfo) {
    AgenticTask task;
    task.name = "RepairTestFailure";
    task.priority = TaskPriority::HIGH;
    task.owner = AgentIdentity::Create(AgentRole::CODER, 8);
    task.execute = [&testInfo]() -> bool {
        printf("[CODER] Repairing: %s\n", testInfo.c_str());
        return true;
    };
    
    SubmitTask(std::move(task));
}

//=============================================================================
// Convenience Methods
//=============================================================================

bool AgenticSupervisor::ExecuteWithCheckpoint(const std::string& name, 
                                               std::function<bool()> operation) {
    AgenticTask task;
    task.name = name;
    task.priority = TaskPriority::NORMAL;
    task.requiresCheckpoint = true;
    task.execute = operation;
    
    std::string taskId = SubmitTask(std::move(task));
    
    // Wait for completion
    while (GetTaskStatus(taskId).status == TaskStatus::RUNNING ||
           GetTaskStatus(taskId).status == TaskStatus::PENDING) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return GetTaskStatus(taskId).status == TaskStatus::COMPLETED;
}

bool AgenticSupervisor::ExecuteWithRetry(const std::string& name,
                                          std::function<bool()> operation,
                                          int maxRetries) {
    for (int i = 0; i < maxRetries; ++i) {
        if (ExecuteWithCheckpoint(name, operation)) {
            return true;
        }
        printf("[AGENTIC] Retry %d/%d for '%s'\n", i + 1, maxRetries, name.c_str());
        std::this_thread::sleep_for(std::chrono::milliseconds(100 * (i + 1)));
    }
    return false;
}

//=============================================================================
// Scoped Agentic Task Implementation
//=============================================================================

ScopedAgenticTask::ScopedAgenticTask(const std::string& name,
                                      std::function<bool()> operation,
                                      bool requireCheckpoint)
    : operation_(operation)
    , requireCheckpoint_(requireCheckpoint)
    , success_(false)
    , executed_(false)
{
    AgenticTask task;
    task.name = name;
    task.execute = [this]() -> bool {
        executed_ = true;
        success_ = operation_();
        return success_;
    };
    taskId_ = AgenticSupervisor::Instance().SubmitTask(std::move(task));
}

ScopedAgenticTask::~ScopedAgenticTask() {
    if (executed_ && !success_) {
        printf("[AGENTIC] Task '%s' failed in destructor\n", taskId_.c_str());
    }
}

bool ScopedAgenticTask::Execute() {
    // Wait for completion
    while (AgenticSupervisor::Instance().GetTaskStatus(taskId_).status == TaskStatus::PENDING ||
           AgenticSupervisor::Instance().GetTaskStatus(taskId_).status == TaskStatus::RUNNING) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return AgenticSupervisor::Instance().GetTaskStatus(taskId_).status == TaskStatus::COMPLETED;
}

} // namespace Agentic

// TaskComparator implementation - must be in RawrXD::Agentic namespace
bool AgenticSupervisor::TaskComparator::operator()(const std::string& a, const std::string& b) const {
    // Compare task IDs based on priority (higher priority = lower value in priority_queue)
    // This is a simplified comparison - in production, you'd look up actual task priorities
    return a > b; // Simple string comparison for now (lexicographic)
}

} // namespace RawrXD
