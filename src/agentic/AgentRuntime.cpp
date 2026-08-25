// ============================================================================
// AgentRuntime.cpp - Full Implementation
// Autonomous Agent Execution with ToolBudget, State Machine, and Observability
// ============================================================================
#include "AgentRuntime.hpp"
#include <cstdio>
#include <fstream>
#include <thread>
#include <condition_variable>

namespace RawrXD {
namespace Agent {

// ============================================================================
// AgentRun Implementation
// ============================================================================
AgentRun::AgentRun(const std::string& taskDescription) 
    : runId("run_" + std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count())),
      task(taskDescription),
      state(AgentState::IDLE) {}

void AgentRun::Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    state = AgentState::THINKING;
    startTime = std::chrono::steady_clock::now();
    resourceBudget.Start();
    printf("[AgentRun] Started: %s (ID: %s)\n", task.c_str(), runId.c_str());
}

void AgentRun::Complete() {
    std::lock_guard<std::mutex> lock(mutex_);
    state = AgentState::COMPLETED;
    endTime = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    printf("[AgentRun] Completed: %s in %llds (Tools: %u, Turns: %u)\n",
           task.c_str(), elapsed.count(), toolBudget.consumed, turnBudget.consumed);
}

void AgentRun::Fail(const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    state = AgentState::FAILED;
    endTime = std::chrono::steady_clock::now();
    printf("[AgentRun] Failed: %s - %s\n", task.c_str(), reason.c_str());
}

void AgentRun::Cancel() {
    std::lock_guard<std::mutex> lock(mutex_);
    state = AgentState::CANCELLED;
    endTime = std::chrono::steady_clock::now();
    printf("[AgentRun] Cancelled: %s\n", task.c_str());
}

void AgentRun::BudgetExhausted() {
    std::lock_guard<std::mutex> lock(mutex_);
    state = AgentState::BUDGET_EXHAUSTED;
    endTime = std::chrono::steady_clock::now();
    printf("[AgentRun] Budget exhausted: %s (Tools: %u/%u, Turns: %u/%u)\n",
           task.c_str(), toolBudget.consumed, toolBudget.initialLimit,
           turnBudget.consumed, turnBudget.initialLimit);
}

bool AgentRun::CanExecuteTool() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return toolBudget.CanCall() && turnBudget.CanContinue() && CheckResourceBudgets();
}

bool AgentRun::CanContinueTurn() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return turnBudget.CanContinue() && resourceBudget.CheckTimeBudget();
}

bool AgentRun::CheckResourceBudgets() const {
    return resourceBudget.CheckTimeBudget() &&
           resourceBudget.CanSpawnProcess() &&
           resourceBudget.currentMemoryBytes.load() < resourceBudget.maxMemoryBytes;
}

void AgentRun::RecordToolCall(const ToolCall& call) {
    std::lock_guard<std::mutex> lock(mutex_);
    toolHistory.push_back(call);
    toolBudget.Consume();
}

void AgentRun::RecordToolResult(const ToolResult& result) {
    std::lock_guard<std::mutex> lock(mutex_);
    resultHistory.push_back(result);
}

void AgentRun::RecordModelResponse(const nlohmann::json& response) {
    std::lock_guard<std::mutex> lock(mutex_);
    modelResponses.push_back(response);
}

void AgentRun::CompactContext() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Keep only last N tool results to prevent context overflow
    const size_t MAX_HISTORY = 50;
    if (toolHistory.size() > MAX_HISTORY) {
        // Summarize older results
        size_t toRemove = toolHistory.size() - MAX_HISTORY;
        toolHistory.erase(toolHistory.begin(), toolHistory.begin() + toRemove);
        resultHistory.erase(resultHistory.begin(), resultHistory.begin() + toRemove);
    }
    
    // Compact model responses - keep only last 10
    const size_t MAX_RESPONSES = 10;
    if (modelResponses.size() > MAX_RESPONSES) {
        modelResponses.erase(modelResponses.begin(), modelResponses.begin() + 
                            (modelResponses.size() - MAX_RESPONSES));
    }
    
    printf("[AgentRun] Context compacted: %zu tools, %zu responses kept\n",
           toolHistory.size(), modelResponses.size());
}

size_t AgentRun::EstimateContextTokens() const {
    // Rough estimation: ~4 chars per token
    size_t totalChars = 0;
    for (const auto& result : resultHistory) {
        totalChars += result.output.dump().length();
        totalChars += result.error.length();
    }
    for (const auto& resp : modelResponses) {
        totalChars += resp.dump().length();
    }
    return totalChars / 4;
}

nlohmann::json AgentRun::ToJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    nlohmann::json j;
    j["runId"] = runId;
    j["task"] = task;
    j["state"] = AgentStateToString(state);
    j["toolBudget"] = toolBudget.ToJson();
    j["turnBudget"] = turnBudget.ToJson();
    j["resourceBudget"] = resourceBudget.ToJson();
    j["currentTurn"] = currentTurn;
    j["currentSequence"] = currentSequence;
    j["workingDirectory"] = workingDirectory;
    j["changedFiles"] = changedFiles;
    
    // Tool history
    j["toolHistory"] = nlohmann::json::array();
    for (const auto& call : toolHistory) {
        j["toolHistory"].push_back(call.ToJson());
    }
    
    // Result history (last 20)
    j["resultHistory"] = nlohmann::json::array();
    size_t start = resultHistory.size() > 20 ? resultHistory.size() - 20 : 0;
    for (size_t i = start; i < resultHistory.size(); i++) {
        j["resultHistory"].push_back(resultHistory[i].ToJson());
    }
    
    // Timing
    auto elapsed = std::chrono::steady_clock::now() - startTime;
    j["elapsedSeconds"] = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    
    return j;
}

bool AgentRun::SaveCheckpoint(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    file << ToJson().dump(2);
    return true;
}

bool AgentRun::LoadCheckpoint(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    nlohmann::json j;
    file >> j;
    
    auto loaded = FromJson(j);
    if (loaded) {
        *this = *loaded;
        return true;
    }
    return false;
}

std::optional<AgentRun> AgentRun::FromJson(const nlohmann::json& json) {
    try {
        AgentRun run;
        run.runId = json.value("runId", "");
        run.task = json.value("task", "");
        run.state = StringToAgentState(json.value("state", "IDLE"));
        run.currentTurn = json.value("currentTurn", 0);
        run.currentSequence = json.value("currentSequence", 0);
        run.workingDirectory = json.value("workingDirectory", "");
        return run;
    } catch (...) {
        return std::nullopt;
    }
}

// ============================================================================
// ToolDispatcher Implementation
// ============================================================================
ToolDispatcher::ToolDispatcher() = default;
ToolDispatcher::~ToolDispatcher() = default;

void ToolDispatcher::RegisterTool(const ToolRegistryEntry& entry) {
    std::lock_guard<std::mutex> lock(registryMutex_);
    registry_[entry.name] = entry;
    printf("[ToolDispatcher] Registered: %s (permission=%d, timeout=%llds)\n",
           entry.name.c_str(), static_cast<int>(entry.permission), entry.timeout.count());
}

void ToolDispatcher::UnregisterTool(const std::string& name) {
    std::lock_guard<std::mutex> lock(registryMutex_);
    registry_.erase(name);
}

bool ToolDispatcher::HasTool(const std::string& name) const {
    std::lock_guard<std::mutex> lock(registryMutex_);
    return registry_.find(name) != registry_.end();
}

std::vector<std::string> ToolDispatcher::GetToolNames() const {
    std::lock_guard<std::mutex> lock(registryMutex_);
    std::vector<std::string> names;
    for (const auto& [name, _] : registry_) {
        names.push_back(name);
    }
    return names;
}

bool ToolDispatcher::ValidateCall(const ToolCall& call, std::string& error) const {
    std::lock_guard<std::mutex> lock(registryMutex_);
    
    auto it = registry_.find(call.name);
    if (it == registry_.end()) {
        error = "Unknown tool: " + call.name;
        return false;
    }
    
    // Validate against schema
    // TODO: Implement JSON schema validation
    
    return true;
}

bool ToolDispatcher::AuthorizeCall(const ToolCall& call, AgentRun& run, std::string& error) const {
    std::lock_guard<std::mutex> lock(registryMutex_);
    
    auto it = registry_.find(call.name);
    if (it == registry_.end()) {
        error = "Unknown tool: " + call.name;
        return false;
    }
    
    const auto& entry = it->second;
    
    // Check permission level
    if (entry.permission == PermissionLevel::BLOCKED) {
        error = "Tool '" + call.name + "' is blocked";
        {
            std::lock_guard<std::mutex> statsLock(statsMutex_);
            stats_.permissionRejections++;
        }
        return false;
    }
    
    if (entry.permission == PermissionLevel::APPROVAL_REQUIRED) {
        // In a real implementation, this would trigger human approval
        // For now, auto-approve in non-interactive mode
        printf("[ToolDispatcher] Approval required for '%s' - auto-approving\n", call.name.c_str());
    }
    
    return true;
}

bool ToolDispatcher::CheckBudget(const ToolCall& call, AgentRun& run) const {
    if (!run.toolBudget.CanCall()) {
        printf("[ToolDispatcher] Budget exhausted for run %s\n", run.runId.c_str());
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.budgetRejections++;
        }
        return false;
    }
    return true;
}

ToolResult ToolDispatcher::Execute(const ToolCall& call, AgentRun& run) {
    std::string error;
    
    // Validate
    if (!ValidateCall(call, error)) {
        return ToolResult::Failure(call.id, error);
    }
    
    // Authorize
    if (!AuthorizeCall(call, run, error)) {
        return ToolResult::Failure(call.id, error);
    }
    
    // Check budget
    if (!CheckBudget(call, run)) {
        return ToolResult::Failure(call.id, "Tool budget exhausted");
    }
    
    return ExecuteInternal(call, run);
}

std::vector<ToolResult> ToolDispatcher::ExecuteBatch(const std::vector<ToolCall>& calls, AgentRun& run) {
    std::vector<ToolResult> results;
    results.reserve(calls.size());
    
    // Separate parallelizable vs sequential
    std::vector<const ToolCall*> parallelizable;
    std::vector<const ToolCall*> sequential;
    
    {
        std::lock_guard<std::mutex> lock(registryMutex_);
        for (const auto& call : calls) {
            auto it = registry_.find(call.name);
            if (it != registry_.end() && it->second.parallelizable) {
                parallelizable.push_back(&call);
            } else {
                sequential.push_back(&call);
            }
        }
    }
    
    // Execute parallelizable tools concurrently
    std::vector<std::future<ToolResult>> futures;
    for (const auto* call : parallelizable) {
        futures.push_back(ExecuteAsync(*call, run));
    }
    
    // Collect parallel results
    for (auto& future : futures) {
        results.push_back(future.get());
    }
    
    // Execute sequential tools
    for (const auto* call : sequential) {
        results.push_back(Execute(*call, run));
    }
    
    return results;
}

std::future<ToolResult> ToolDispatcher::ExecuteAsync(const ToolCall& call, AgentRun& run) {
    return std::async(std::launch::async, [this, &call, &run]() {
        return Execute(call, run);
    });
}

ToolResult ToolDispatcher::ExecuteInternal(const ToolCall& call, AgentRun& run) {
    std::lock_guard<std::mutex> lock(registryMutex_);
    
    auto it = registry_.find(call.name);
    if (it == registry_.end()) {
        return ToolResult::Failure(call.id, "Tool not found: " + call.name);
    }
    
    const auto& entry = it->second;
    
    // Wait for execution slot
    if (!WaitForExecutionSlot(std::chrono::milliseconds(entry.timeout.count() * 1000))) {
        {
            std::lock_guard<std::mutex> statsLock(statsMutex_);
            stats_.timeoutCount++;
        }
        return ToolResult::Failure(call.id, "Timeout waiting for execution slot");
    }
    
    activeExecutions_++;
    
    auto startTime = std::chrono::steady_clock::now();
    ToolResult result;
    
    try {
        result = entry.handler(call);
        result.callId = call.id;
        {
            std::lock_guard<std::mutex> statsLock(statsMutex_);
            stats_.successfulCalls++;
        }
    } catch (const std::exception& e) {
        result = ToolResult::Failure(call.id, std::string("Exception: ") + e.what());
        {
            std::lock_guard<std::mutex> statsLock(statsMutex_);
            stats_.failedCalls++;
        }
    } catch (...) {
        result = ToolResult::Failure(call.id, "Unknown exception");
        {
            std::lock_guard<std::mutex> statsLock(statsMutex_);
            stats_.failedCalls++;
        }
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    activeExecutions_--;
    
    {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.totalCalls++;
        stats_.totalExecutionTime += result.duration;
    }
    
    // Record in run
    run.RecordToolResult(result);
    
    printf("[ToolDispatcher] Executed '%s' in %lldms (exit=%d, success=%d)\n",
           call.name.c_str(), result.duration.count(), result.exitCode, result.success);
    
    return result;
}

bool ToolDispatcher::WaitForExecutionSlot(std::chrono::milliseconds timeout) {
    auto start = std::chrono::steady_clock::now();
    while (activeExecutions_.load() >= maxConcurrency_) {
        if (std::chrono::steady_clock::now() - start > timeout) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
}

ToolDispatcher::Stats ToolDispatcher::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void ToolDispatcher::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

// ============================================================================
// AgentRuntime Implementation
// ============================================================================
AgentRuntime::AgentRuntime() = default;
AgentRuntime::~AgentRuntime() {
    running_ = false;
    if (processingThread_.joinable()) {
        processingThread_.join();
    }
}

std::string AgentRuntime::StartAgent(const std::string& task) {
    auto run = std::make_unique<AgentRun>(task);
    run->Start();
    
    // Initialize budgets
    run->toolBudget = defaultToolBudget_;
    run->turnBudget = defaultTurnBudget_;
    run->resourceBudget = defaultResourceBudget_;
    
    std::string runId = run->runId;
    
    {
        std::lock_guard<std::mutex> lock(runsMutex_);
        activeRuns_[runId] = std::move(run);
    }
    
    printf("[AgentRuntime] Started agent: %s (ID: %s)\n", task.c_str(), runId.c_str());
    return runId;
}

AgentState AgentRuntime::GetAgentState(const std::string& runId) const {
    std::lock_guard<std::mutex> lock(runsMutex_);
    auto it = activeRuns_.find(runId);
    if (it != activeRuns_.end()) {
        return it->second->state;
    }
    return AgentState::FAILED;
}

bool AgentRuntime::CancelAgent(const std::string& runId) {
    std::lock_guard<std::mutex> lock(runsMutex_);
    auto it = activeRuns_.find(runId);
    if (it != activeRuns_.end()) {
        it->second->Cancel();
        return true;
    }
    return false;
}

bool AgentRuntime::PauseAgent(const std::string& runId) {
    // TODO: Implement pause/resume with state serialization
    printf("[AgentRuntime] Pause not yet implemented for %s\n", runId.c_str());
    return false;
}

bool AgentRuntime::ResumeAgent(const std::string& runId) {
    // TODO: Implement pause/resume with state deserialization
    printf("[AgentRuntime] Resume not yet implemented for %s\n", runId.c_str());
    return false;
}

bool AgentRuntime::ExtendBudget(const std::string& runId, uint32_t additionalTools) {
    std::lock_guard<std::mutex> lock(runsMutex_);
    auto it = activeRuns_.find(runId);
    if (it != activeRuns_.end()) {
        bool extended = it->second->toolBudget.Extend(additionalTools);
        if (extended) {
            printf("[AgentRuntime] Budget extended for %s: +%u tools (now %u remaining)\n",
                   runId.c_str(), additionalTools, it->second->toolBudget.remaining);
        }
        return extended;
    }
    return false;
}

nlohmann::json AgentRuntime::GetAgentStatus(const std::string& runId) const {
    std::lock_guard<std::mutex> lock(runsMutex_);
    auto it = activeRuns_.find(runId);
    if (it != activeRuns_.end()) {
        return it->second->ToJson();
    }
    return nlohmann::json{{"error", "Run not found"}};
}

nlohmann::json AgentRuntime::GetAgentTrace(const std::string& runId) const {
    std::lock_guard<std::mutex> lock(runsMutex_);
    auto it = activeRuns_.find(runId);
    if (it == activeRuns_.end()) {
        return nlohmann::json{{"error", "Run not found"}};
    }
    
    nlohmann::json trace;
    trace["runId"] = runId;
    trace["task"] = it->second->task;
    trace["state"] = AgentStateToString(it->second->state);
    
    // Build execution trace
    trace["trace"] = nlohmann::json::array();
    for (size_t i = 0; i < it->second->toolHistory.size(); i++) {
        nlohmann::json entry;
        entry["turn"] = it->second->toolHistory[i].turnId;
        entry["tool"] = it->second->toolHistory[i].name;
        entry["arguments"] = it->second->toolHistory[i].arguments;
        
        if (i < it->second->resultHistory.size()) {
            entry["success"] = it->second->resultHistory[i].success;
            entry["durationMs"] = it->second->resultHistory[i].duration.count();
            entry["exitCode"] = it->second->resultHistory[i].exitCode;
        }
        
        trace["trace"].push_back(entry);
    }
    
    // Budget timeline
    trace["budget"] = {
        {"toolsUsed", it->second->toolBudget.consumed},
        {"toolsRemaining", it->second->toolBudget.remaining},
        {"turnsUsed", it->second->turnBudget.consumed},
        {"turnsRemaining", it->second->turnBudget.remaining}
    };
    
    return trace;
}

std::vector<std::string> AgentRuntime::GetActiveRuns() const {
    std::lock_guard<std::mutex> lock(runsMutex_);
    std::vector<std::string> runs;
    for (const auto& [id, run] : activeRuns_) {
        if (run->state != AgentState::COMPLETED && 
            run->state != AgentState::FAILED &&
            run->state != AgentState::CANCELLED) {
            runs.push_back(id);
        }
    }
    return runs;
}

bool AgentRuntime::SaveCheckpoint(const std::string& runId, const std::string& path) {
    std::lock_guard<std::mutex> lock(runsMutex_);
    auto it = activeRuns_.find(runId);
    if (it != activeRuns_.end()) {
        return it->second->SaveCheckpoint(path);
    }
    return false;
}

bool AgentRuntime::LoadCheckpoint(const std::string& path) {
    auto run = std::make_unique<AgentRun>();
    if (run->LoadCheckpoint(path)) {
        std::lock_guard<std::mutex> lock(runsMutex_);
        activeRuns_[run->runId] = std::move(run);
        return true;
    }
    return false;
}

// ============================================================================
// State Machine Processing
// ============================================================================
void AgentRuntime::ProcessTurn(AgentRun& run) {
    if (!run.CanContinueTurn()) {
        run.BudgetExhausted();
        return;
    }
    
    run.turnBudget.ConsumeTurn();
    run.currentTurn++;
    
    // Build prompt from history
    std::string prompt = run.task;
    if (!run.resultHistory.empty()) {
        prompt += "\n\nPrevious results:\n";
        for (const auto& result : run.resultHistory) {
            if (result.success) {
                prompt += "- Success: " + result.output.dump() + "\n";
            } else {
                prompt += "- Error: " + result.error + "\n";
            }
        }
    }
    
    // Call model
    auto response = CallModel(prompt, run.resultHistory);
    run.RecordModelResponse(response);
    
    // Parse tool calls
    auto toolCalls = ParseToolCalls(response);
    
    if (toolCalls.empty() || IsTaskComplete(response)) {
        run.Complete();
        return;
    }
    
    // Execute tools
    run.state = AgentState::EXECUTING_TOOLS;
    ExecuteTools(run, toolCalls);
    
    // Continue to next turn
    if (run.state != AgentState::FAILED && 
        run.state != AgentState::CANCELLED &&
        run.state != AgentState::BUDGET_EXHAUSTED) {
        run.state = AgentState::THINKING;
    }
}

void AgentRuntime::ExecuteTools(AgentRun& run, const std::vector<ToolCall>& calls) {
    // Check budget before execution
    if (!run.CanExecuteTool()) {
        run.BudgetExhausted();
        return;
    }
    
    // Record tool calls
    for (const auto& call : calls) {
        run.RecordToolCall(call);
    }
    
    // Execute
    auto results = dispatcher_.ExecuteBatch(calls, run);
    
    // Check for failures
    bool hasFailures = false;
    for (const auto& result : results) {
        if (!result.success) {
            hasFailures = true;
            break;
        }
    }
    
    if (hasFailures) {
        // Retry logic or failure handling
        printf("[AgentRuntime] Some tools failed in turn %u\n", run.currentTurn);
    }
    
    // Compact context if needed
    if (run.EstimateContextTokens() > run.resourceBudget.maxContextTokens * 0.8) {
        run.CompactContext();
    }
}

void AgentRuntime::HandleCompletion(AgentRun& run) {
    run.Complete();
    printf("[AgentRuntime] Agent completed: %s\n", run.runId.c_str());
}

void AgentRuntime::HandleFailure(AgentRun& run, const std::string& reason) {
    run.Fail(reason);
    printf("[AgentRuntime] Agent failed: %s - %s\n", run.runId.c_str(), reason.c_str());
}

// ============================================================================
// Model Interaction (Stubs - replace with actual model integration)
// ============================================================================
nlohmann::json AgentRuntime::CallModel(const std::string& prompt, 
                                        const std::vector<ToolResult>& observations) {
    // TODO: Integrate with actual inference engine
    // This is a stub that returns a mock response
    
    nlohmann::json response;
    response["content"] = "Task analysis complete. No further actions needed.";
    response["tool_calls"] = nlohmann::json::array();
    
    return response;
}

std::vector<ToolCall> AgentRuntime::ParseToolCalls(const nlohmann::json& modelResponse) {
    std::vector<ToolCall> calls;
    
    if (!modelResponse.contains("tool_calls")) {
        return calls;
    }
    
    for (const auto& tc : modelResponse["tool_calls"]) {
        ToolCall call;
        call.name = tc.value("name", "");
        call.arguments = tc.value("arguments", nlohmann::json::object());
        calls.push_back(call);
    }
    
    return calls;
}

bool AgentRuntime::IsTaskComplete(const nlohmann::json& modelResponse) {
    // Check if model indicates task completion
    if (modelResponse.contains("content")) {
        std::string content = modelResponse["content"];
        // Simple heuristic - check for completion indicators
        if (content.find("complete") != std::string::npos ||
            content.find("done") != std::string::npos ||
            content.find("finished") != std::string::npos) {
            return true;
        }
    }
    return false;
}

void AgentRuntime::ProcessingLoop() {
    running_ = true;
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        std::lock_guard<std::mutex> lock(runsMutex_);
        for (auto& [runId, run] : activeRuns_) {
            if (run->state == AgentState::THINKING) {
                ProcessTurn(*run);
            }
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================
std::string AgentStateToString(AgentState state) {
    switch (state) {
        case AgentState::IDLE: return "IDLE";
        case AgentState::THINKING: return "THINKING";
        case AgentState::TOOL_CALLS_READY: return "TOOL_CALLS_READY";
        case AgentState::EXECUTING_TOOLS: return "EXECUTING_TOOLS";
        case AgentState::COLLECTING_RESULTS: return "COLLECTING_RESULTS";
        case AgentState::COMPLETED: return "COMPLETED";
        case AgentState::FAILED: return "FAILED";
        case AgentState::CANCELLED: return "CANCELLED";
        case AgentState::BUDGET_EXHAUSTED: return "BUDGET_EXHAUSTED";
        case AgentState::TIMEOUT: return "TIMEOUT";
        case AgentState::WAITING_APPROVAL: return "WAITING_APPROVAL";
        default: return "UNKNOWN";
    }
}

AgentState StringToAgentState(const std::string& str) {
    if (str == "IDLE") return AgentState::IDLE;
    if (str == "THINKING") return AgentState::THINKING;
    if (str == "TOOL_CALLS_READY") return AgentState::TOOL_CALLS_READY;
    if (str == "EXECUTING_TOOLS") return AgentState::EXECUTING_TOOLS;
    if (str == "COLLECTING_RESULTS") return AgentState::COLLECTING_RESULTS;
    if (str == "COMPLETED") return AgentState::COMPLETED;
    if (str == "FAILED") return AgentState::FAILED;
    if (str == "CANCELLED") return AgentState::CANCELLED;
    if (str == "BUDGET_EXHAUSTED") return AgentState::BUDGET_EXHAUSTED;
    if (str == "TIMEOUT") return AgentState::TIMEOUT;
    if (str == "WAITING_APPROVAL") return AgentState::WAITING_APPROVAL;
    return AgentState::IDLE;
}

} // namespace Agent
} // namespace RawrXD
