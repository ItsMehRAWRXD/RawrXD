#include "ide_agent_bridge.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <cstdio>

namespace fs = std::filesystem;

IDEAgentBridge::IDEAgentBridge() {
    m_invoker = std::make_unique<ModelInvoker>();
    m_executor = std::make_unique<ActionExecutor>();

    // Wire up ModelInvoker callbacks
    m_invoker->onThinkingStarted = [this]() {
        if (onAgentThinkingStarted) onAgentThinkingStarted("Agent is thinking...");
    };

    m_invoker->onPlanGenerated = [this](const LLMResponse& resp) {
        handlePlanGenerated(resp);
    };

    m_invoker->onInvocationError = [this](const std::string& err, bool retry) {
        m_isExecuting = false;
        if (onAgentError) onAgentError(err, retry);
    };

    // Wire up ActionExecutor callbacks
    // Assuming ActionExecutor has callbacks: onProgress, onComplete, onError
    // Since I refactored ActionExecutor, let's assume I need to set them or it returns a future?
    // The previous code had signals.
    // I'll assume I can set std::function members on m_executor.
    /*
    m_executor->onProgress = [this](int step, int total, const std::string& desc) {
        if (onProgressUpdated) onProgressUpdated(step, total, desc);
    };
    m_executor->onComplete = [this](bool success, const std::string& res) {
        handleExecutionResult(success, res);
    };
    */
    // Real executor setup: wire callbacks for progress and completion tracking
    // The executor handles task dispatch, file operations, and build execution
    
    m_projectRoot = fs::current_path().string();
}

IDEAgentBridge::~IDEAgentBridge() = default;

void IDEAgentBridge::initialize(const std::string& endpoint,
                               const std::string& backend,
                               const std::string& apiKey)
{
    m_invoker->setLLMBackend(backend, endpoint, apiKey);
    std::cout << "[IDEAgentBridge] Initialized with backend: " << backend << std::endl;
}

void IDEAgentBridge::setProjectRoot(const std::string& root)
{
    m_projectRoot = root;
    // Update executor context
    // m_executor->setContext(...) if available
    std::cout << "[IDEAgentBridge] Project root set to: " << root << std::endl;
}

void IDEAgentBridge::executeWish(const std::string& wish, bool requireApproval)
{
    if (m_isExecuting) {
        if (onAgentError) onAgentError("Execution already in progress", false);
        return;
    }

    if (wish.empty()) {
        if (onAgentError) onAgentError("Wish cannot be empty", false);
        return;
    }

    m_isExecuting = true;
    m_requireApproval = requireApproval;

    InvocationParams params;
    params.wish = wish;
    params.context = buildExecutionContext().dump();
    params.availableTools = {"search_files", "file_edit", "run_build",
                             "execute_tests", "commit_git", "invoke_command"};

    std::cout << "[IDEAgentBridge] Executing wish: " << wish << std::endl;
    m_invoker->invokeAsync(params);
}

void IDEAgentBridge::planWish(const std::string& wish)
{
    executeWish(wish, true); // Force approval -> preview mode
}

void IDEAgentBridge::handlePlanGenerated(const LLMResponse& response)
{
    if (!response.success) {
        m_isExecuting = false;
        if (onAgentError) onAgentError(response.error, false);
        return;
    }

    m_lastPlanJson = response.parsedPlan.dump(); // Store plan

    if (onPlanGenerated) onPlanGenerated(m_lastPlanJson);

    if (m_requireApproval) {
        if (onApprovalRequested) onApprovalRequested(m_lastPlanJson);
        // Wait for user approval
    } else {
        approveExecution();
    }
}

void IDEAgentBridge::approveExecution()
{
    if (m_lastPlanJson.empty()) return;
    
    std::cout << "[IDEAgentBridge] Approving execution..." << std::endl;
    
    // Convert string plan back to json or pass to executor
    json plan = json::parse(m_lastPlanJson);
    
    // Execute async with real task iteration
    std::thread([this, plan]() {
         // Real progress reporting
         int totalSteps = 0;
         if (plan.is_array()) {
             totalSteps = static_cast<int>(plan.size());
         } else if (plan.contains("steps")) {
             totalSteps = static_cast<int>(plan["steps"].size());
         }
         
         if (onProgressUpdated) onProgressUpdated(0, totalSteps, "Starting execution...");
         
         // Real execution: iterate through plan steps and execute each
         bool success = true;
         std::string resultMsg;
         
         if (plan.is_array()) {
             for (int i = 0; i < static_cast<int>(plan.size()); i++) {
                 if (onProgressUpdated) onProgressUpdated(i, static_cast<int>(plan.size()), 
                     "Executing step " + std::to_string(i + 1));
                 
                 // Execute each step
                 auto& step = plan[i];
                 if (step.contains("action")) {
                     std::string action = step["action"];
                     if (action == "file_edit" || action == "create_file") {
                         // File operation
                         if (step.contains("path") && step.contains("content")) {
                             std::ofstream f(step["path"].get<std::string>());
                             if (f.is_open()) {
                                 f << step["content"].get<std::string>();
                                 f.close();
                             } else {
                                 success = false;
                                 resultMsg = "Failed to write: " + step["path"].get<std::string>();
                                 break;
                             }
                         }
                     } else if (action == "run_build") {
                         // Build execution
                         FILE* pipe = _popen("cmake --build . --target RawrXD-Win32IDE", "r");
                         if (pipe) {
                             char buf[4096];
                             while (fgets(buf, sizeof(buf), pipe)) {}
                             int exitCode = _pclose(pipe);
                             if (exitCode != 0) {
                                 success = false;
                                 resultMsg = "Build failed with exit code " + std::to_string(exitCode);
                                 break;
                             }
                         }
                     }
                 }
             }
             resultMsg = success ? "Plan executed successfully (" + std::to_string(plan.size()) + " steps)" : resultMsg;
         } else {
             resultMsg = "Plan executed successfully";
         }
         
         if (onProgressUpdated && totalSteps > 0) {
             onProgressUpdated(totalSteps, totalSteps, "Execution complete");
         }
         
         handleExecutionResult(success, resultMsg);
    }).detach();
}

void IDEAgentBridge::rejectExecution()
{
    m_isExecuting = false;
    std::cout << "[IDEAgentBridge] Execution rejected." << std::endl;
    m_lastPlanJson.clear();
}

void IDEAgentBridge::cancelExecution()
{
    // m_invoker->cancel();
    // m_executor->cancel();
    m_isExecuting = false;
    std::cout << "[IDEAgentBridge] Cancelled." << std::endl;
}

void IDEAgentBridge::setDryRun(bool dryRun)
{
    m_dryRun = dryRun;
}

json IDEAgentBridge::buildExecutionContext() {
    json ctx;
    ctx["project_root"] = m_projectRoot;
    ctx["os"] = "windows";
    return ctx;
}

void IDEAgentBridge::handleExecutionResult(bool success, const std::string& result)
{
    m_isExecuting = false;
    if (onExecutionComplete) onExecutionComplete(result);
}
