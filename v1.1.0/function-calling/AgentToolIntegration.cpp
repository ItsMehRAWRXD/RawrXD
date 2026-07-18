// RawrXD Sovereign v1.1.0 - Function Calling Framework
// AgentToolIntegration.cpp - Implementation

#include "AgentToolIntegration.hpp"
#include <sstream>
#include <algorithm>

namespace RawrXD {
namespace Agent {
namespace FunctionCalling {

// ToolEnabledPlanner::Impl
class ToolEnabledPlanner::Impl {
public:
    ToolRegistry* registry_ = nullptr;
    SchemaValidator* validator_ = nullptr;
};

ToolEnabledPlanner::ToolEnabledPlanner() : pImpl(std::make_unique<Impl>()) {}
ToolEnabledPlanner::~ToolEnabledPlanner() = default;

void ToolEnabledPlanner::Initialize(ToolRegistry* registry, SchemaValidator* validator) {
    pImpl->registry_ = registry;
    pImpl->validator_ = validator;
}

std::string ToolEnabledPlanner::CreateToolAwarePlan(const std::string& user_request,
                                                     const std::vector<ToolDefinitionAPI>& tools) {
    std::stringstream plan;
    plan << "Plan for request: " << user_request << "\n\n";
    plan << "Available tools:\n";
    
    for (const auto& tool : tools) {
        plan << "- " << tool.function.name << ": " << tool.function.description << "\n";
    }
    
    plan << "\nSteps:\n";
    plan << "1. Analyze request and identify required tools\n";
    plan << "2. Validate tool parameters\n";
    plan << "3. Execute tools in sequence\n";
    plan << "4. Process results and generate response\n";
    
    return plan.str();
}

bool ToolEnabledPlanner::AreToolsNeeded(const std::string& user_request,
                                        const std::vector<ToolDefinitionAPI>& tools) {
    // Simple heuristic - check if request mentions tool-related keywords
    std::string lower_request = user_request;
    std::transform(lower_request.begin(), lower_request.end(), lower_request.begin(), ::tolower);
    
    std::vector<std::string> tool_keywords = {
        "file", "read", "write", "compile", "run", "execute",
        "debug", "breakpoint", "benchmark", "profile", "search"
    };
    
    for (const auto& keyword : tool_keywords) {
        if (lower_request.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::vector<ToolDefinitionAPI> ToolEnabledPlanner::SelectTools(const std::string& task,
                                                                const std::vector<ToolDefinitionAPI>& available) {
    std::vector<ToolDefinitionAPI> selected;
    std::string lower_task = task;
    std::transform(lower_task.begin(), lower_task.end(), lower_task.begin(), ::tolower);
    
    for (const auto& tool : available) {
        std::string lower_name = tool.function.name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        // Simple matching - check if tool name appears in task
        if (lower_task.find(lower_name) != std::string::npos) {
            selected.push_back(tool);
        }
    }
    
    return selected;
}

// ToolEnabledCoder::Impl
class ToolEnabledCoder::Impl {
public:
    ToolExecutor* executor_ = nullptr;
    FunctionCallingHandler* handler_ = nullptr;
};

ToolEnabledCoder::ToolEnabledCoder() : pImpl(std::make_unique<Impl>()) {}
ToolEnabledCoder::~ToolEnabledCoder() = default;

void ToolEnabledCoder::Initialize(ToolExecutor* executor, FunctionCallingHandler* handler) {
    pImpl->executor_ = executor;
    pImpl->handler_ = handler;
}

std::string ToolEnabledCoder::GenerateToolUsingCode(const std::string& plan,
                                                     const std::vector<ToolDefinitionAPI>& tools) {
    std::stringstream code;
    code << "// Auto-generated code based on plan\n";
    code << "// Plan: " << plan << "\n\n";
    
    code << "#include <RawrXD/FunctionCalling.hpp>\n\n";
    code << "void execute_plan() {\n";
    code << "    ToolExecutor executor;\n";
    code << "    \n";
    
    for (const auto& tool : tools) {
        code << "    // Execute " << tool.function.name << "\n";
        code << "    ToolCall " << tool.function.name << "_call;\n";
        code << "    " << tool.function.name << "_call.name = \"" << tool.function.name << "\";\n";
        code << "    // TODO: Set arguments based on plan\n";
        code << "    \n";
    }
    
    code << "}\n";
    
    return code.str();
}

bool ToolEnabledCoder::ValidateCode(const std::string& code, std::string& error) {
    // Basic validation - check for required includes
    if (code.find("#include") == std::string::npos) {
        error = "Missing #include statements";
        return false;
    }
    
    // Check for balanced braces
    int brace_count = 0;
    for (char c : code) {
        if (c == '{') brace_count++;
        if (c == '}') brace_count--;
        if (brace_count < 0) {
            error = "Unbalanced braces";
            return false;
        }
    }
    
    if (brace_count != 0) {
        error = "Unbalanced braces";
        return false;
    }
    
    return true;
}

// ToolEnabledReflector::Impl
class ToolEnabledReflector::Impl {
public:
    SchemaValidator* validator_ = nullptr;
};

ToolEnabledReflector::ToolEnabledReflector() : pImpl(std::make_unique<Impl>()) {}
ToolEnabledReflector::~ToolEnabledReflector() = default;

void ToolEnabledReflector::Initialize(SchemaValidator* validator) {
    pImpl->validator_ = validator;
}

std::string ToolEnabledReflector::ReflectOnResults(const std::vector<AgentToolResult>& results,
                                                    const std::string& original_request) {
    std::stringstream reflection;
    reflection << "Reflection on tool execution results:\n\n";
    reflection << "Original request: " << original_request << "\n\n";
    
    int success_count = 0;
    int failure_count = 0;
    
    for (const auto& result : results) {
        if (result.success) {
            success_count++;
            reflection << "✓ " << result.tool_name << " succeeded\n";
        } else {
            failure_count++;
            reflection << "✗ " << result.tool_name << " failed: " << result.error_message << "\n";
        }
    }
    
    reflection << "\nSummary: " << success_count << " succeeded, " << failure_count << " failed\n";
    
    if (failure_count > 0) {
        reflection << "\nRecommendations:\n";
        reflection << "- Review failed tool executions\n";
        reflection << "- Check parameter validity\n";
        reflection << "- Consider alternative approaches\n";
    }
    
    return reflection.str();
}

bool ToolEnabledReflector::NeedMoreTools(const std::vector<AgentToolResult>& results,
                                          const std::string& goal) {
    // Check if any tool failed
    for (const auto& result : results) {
        if (!result.success) {
            return true; // Need to retry or try alternative
        }
    }
    
    // Check if goal is achieved (simplified)
    // In real implementation, this would use LLM to evaluate
    return false;
}

std::string ToolEnabledReflector::GenerateFollowUp(const std::vector<AgentToolResult>& results,
                                                    const std::string& original_request) {
    std::stringstream followup;
    followup << "Based on previous results, the following follow-up is needed:\n\n";
    
    for (const auto& result : results) {
        if (!result.success) {
            followup << "- Retry " << result.tool_name << " with corrected parameters\n";
        }
    }
    
    followup << "\nOriginal request: " << original_request << "\n";
    
    return followup.str();
}

// AgentToolIntegration::Impl
class AgentToolIntegration::Impl {
public:
    ToolRegistry* registry_ = nullptr;
    ToolExecutor* executor_ = nullptr;
    SchemaValidator* validator_ = nullptr;
    FunctionCallingHandler* handler_ = nullptr;
    
    ToolEnabledPlanner planner_;
    ToolEnabledCoder coder_;
    ToolEnabledReflector reflector_;
    
    AgentToolConfig config_;
    std::atomic<size_t> total_executions_{0};
    std::atomic<size_t> successful_executions_{0};
    std::atomic<int64_t> total_execution_time_ms_{0};
    
    bool initialized_ = false;
};

AgentToolIntegration::AgentToolIntegration() : pImpl(std::make_unique<Impl>()) {}
AgentToolIntegration::~AgentToolIntegration() = default;

void AgentToolIntegration::Initialize(ToolRegistry* registry,
                                      ToolExecutor* executor,
                                      SchemaValidator* validator,
                                      FunctionCallingHandler* handler) {
    pImpl->registry_ = registry;
    pImpl->executor_ = executor;
    pImpl->validator_ = validator;
    pImpl->handler_ = handler;
    
    pImpl->planner_.Initialize(registry, validator);
    pImpl->coder_.Initialize(executor, handler);
    pImpl->reflector_.Initialize(validator);
    
    pImpl->initialized_ = true;
}

bool AgentToolIntegration::IsInitialized() const {
    return pImpl->initialized_;
}

void AgentToolIntegration::SetMaxIterations(int max) {
    pImpl->config_.max_iterations = max;
}

void AgentToolIntegration::SetAutoExecute(bool auto_exec) {
    pImpl->config_.auto_execute = auto_exec;
}

void AgentToolIntegration::SetExecutionContext(const ExecutionContext& ctx) {
    pImpl->config_.timeout_seconds = ctx.timeout_seconds;
    pImpl->config_.max_memory_bytes = ctx.max_memory_bytes;
    pImpl->config_.allowed_paths = ctx.allowed_paths;
}

// Placeholder AgentResult - would integrate with actual AgentSubsystem
struct AgentResult {
    bool success;
    std::string response;
    std::vector<AgentToolResult> tool_results;
    int iterations;
    int64_t total_time_ms;
};

AgentResult AgentToolIntegration::ExecuteWithTools(const std::string& user_request,
                                                  void* context) {
    AgentResult result;
    result.success = false;
    result.iterations = 0;
    
    if (!pImpl->initialized_) {
        result.response = "AgentToolIntegration not initialized";
        return result;
    }
    
    auto start = std::chrono::steady_clock::now();
    
    // Get available tools
    auto tools = GetAvailableTools();
    
    // Check if tools are needed
    if (!pImpl->planner_.AreToolsNeeded(user_request, tools)) {
        // No tools needed, return direct response
        result.success = true;
        result.response = "No tools required for this request.";
        return result;
    }
    
    // Main execution loop
    std::vector<AgentToolResult> all_results;
    int iteration = 0;
    
    while (iteration < pImpl->config_.max_iterations) {
        // Plan
        std::string plan = Plan(user_request);
        
        // Identify tool calls
        std::vector<ToolCall> calls = IdentifyToolCalls(plan);
        
        if (calls.empty()) {
            break;
        }
        
        // Execute tools
        std::vector<AgentToolResult> results = ExecuteTools(calls);
        all_results.insert(all_results.end(), results.begin(), results.end());
        
        // Reflect
        std::string reflection = Reflect(results, user_request);
        
        // Check if we need more iterations
        if (!pImpl->reflector_.NeedMoreTools(results, user_request)) {
            break;
        }
        
        iteration++;
    }
    
    // Generate final response
    std::string reflection = Reflect(all_results, user_request);
    result.response = GenerateResponse(reflection, all_results);
    result.tool_results = all_results;
    result.iterations = iteration + 1;
    result.success = true;
    
    auto end = std::chrono::steady_clock::now();
    result.total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    return result;
}

std::string AgentToolIntegration::Plan(const std::string& user_request) {
    auto tools = GetAvailableTools();
    return pImpl->planner_.CreateToolAwarePlan(user_request, tools);
}

std::vector<ToolCall> AgentToolIntegration::IdentifyToolCalls(const std::string& plan) {
    std::vector<ToolCall> calls;
    
    // Parse plan to identify tool calls
    // This is a simplified implementation
    // In production, this would use LLM to extract tool calls
    
    auto tools = GetAvailableTools();
    for (const auto& tool : tools) {
        if (plan.find(tool.function.name) != std::string::npos) {
            ToolCall call;
            call.name = tool.function.name;
            call.arguments = json::object();
            call.call_id = "call_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
            calls.push_back(call);
        }
    }
    
    return calls;
}

std::vector<AgentToolResult> AgentToolIntegration::ExecuteTools(const std::vector<ToolCall>& calls) {
    std::vector<AgentToolResult> results;
    
    if (!pImpl->executor_) {
        return results;
    }
    
    ExecutionContext ctx = pImpl->config_.ToExecutionContext();
    
    for (const auto& call : calls) {
        AgentToolResult agent_result;
        agent_result.tool_name = call.name;
        agent_result.arguments = call.arguments;
        
        auto exec_start = std::chrono::steady_clock::now();
        ExecutedToolResult exec_result = pImpl->executor_->Execute(call, ctx);
        auto exec_end = std::chrono::steady_clock::now();
        
        agent_result.success = exec_result.success;
        agent_result.result_data = exec_result.data;
        agent_result.error_message = exec_result.error_message;
        agent_result.execution_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            exec_end - exec_start).count();
        
        results.push_back(agent_result);
        
        // Update statistics
        pImpl->total_executions_++;
        if (agent_result.success) {
            pImpl->successful_executions_++;
        }
        pImpl->total_execution_time_ms_ += agent_result.execution_time_ms;
    }
    
    return results;
}

std::string AgentToolIntegration::Reflect(const std::vector<AgentToolResult>& results,
                                          const std::string& original_request) {
    return pImpl->reflector_.ReflectOnResults(results, original_request);
}

std::string AgentToolIntegration::GenerateResponse(const std::string& reflection,
                                                    const std::vector<AgentToolResult>& results) {
    std::stringstream response;
    response << "Based on the tool execution results:\n\n";
    
    for (const auto& result : results) {
        if (result.success) {
            response << "✓ " << result.tool_name << " completed successfully\n";
        } else {
            response << "✗ " << result.tool_name << " failed: " << result.error_message << "\n";
        }
    }
    
    response << "\n" << reflection;
    
    return response.str();
}

void AgentToolIntegration::RegisterBuiltInTools() {
    if (pImpl->registry_) {
        pImpl->registry_->RegisterBuiltInTools();
    }
}

std::vector<ToolDefinitionAPI> AgentToolIntegration::GetAvailableTools() const {
    std::vector<ToolDefinitionAPI> tools;
    
    if (pImpl->handler_) {
        return pImpl->handler_->GetAvailableTools();
    }
    
    return tools;
}

void AgentToolIntegration::AddCustomTool(const ToolDefinition& def, ToolFunction func) {
    if (pImpl->registry_) {
        pImpl->registry_->RegisterTool(def, func);
    }
}

size_t AgentToolIntegration::GetTotalToolExecutions() const {
    return pImpl->total_executions_.load();
}

size_t AgentToolIntegration::GetSuccessfulToolExecutions() const {
    return pImpl->successful_executions_.load();
}

double AgentToolIntegration::GetAverageToolExecutionTimeMs() const {
    size_t total = pImpl->total_executions_.load();
    if (total == 0) return 0.0;
    return static_cast<double>(pImpl->total_execution_time_ms_.load()) / total;
}

void AgentToolIntegration::ResetStatistics() {
    pImpl->total_executions_ = 0;
    pImpl->successful_executions_ = 0;
    pImpl->total_execution_time_ms_ = 0;
}

// AsyncToolExecutor::Impl
class AsyncToolExecutor::Impl {
public:
    ToolExecutor* executor_ = nullptr;
    std::vector<std::future<void>> futures_;
    std::mutex mutex_;
};

AsyncToolExecutor::AsyncToolExecutor(ToolExecutor* executor) 
    : pImpl(std::make_unique<Impl>()) {
    pImpl->executor_ = executor;
}

AsyncToolExecutor::~AsyncToolExecutor() {
    WaitForCompletion();
}

void AsyncToolExecutor::ExecuteAsync(const std::vector<ToolCall>& calls,
                                      ToolExecutionCallback callback) {
    if (!pImpl->executor_) return;
    
    for (const auto& call : calls) {
        auto future = std::async(std::launch::async, [this, call, callback]() {
            ExecutionContext ctx;
            ExecutedToolResult result = pImpl->executor_->Execute(call, ctx);
            
            AgentToolResult agent_result;
            agent_result.tool_name = call.name;
            agent_result.arguments = call.arguments;
            agent_result.success = result.success;
            agent_result.result_data = result.data;
            agent_result.error_message = result.error_message;
            agent_result.execution_time_ms = result.execution_time_ms;
            
            callback(agent_result);
        });
        
        std::lock_guard<std::mutex> lock(pImpl->mutex_);
        pImpl->futures_.push_back(std::move(future));
    }
}

void AsyncToolExecutor::WaitForCompletion() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    for (auto& future : pImpl->futures_) {
        if (future.valid()) {
            future.wait();
        }
    }
    pImpl->futures_.clear();
}

void AsyncToolExecutor::CancelAll() {
    // Note: std::future doesn't support cancellation
    // In production, use cancellation tokens
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->futures_.clear();
}

// ToolResultAggregator::Impl
class ToolResultAggregator::Impl {
public:
    std::vector<AgentToolResult> results_;
    mutable std::mutex mutex_;
};

ToolResultAggregator::ToolResultAggregator() : pImpl(std::make_unique<Impl>()) {}
ToolResultAggregator::~ToolResultAggregator() = default;

void ToolResultAggregator::AddResult(const AgentToolResult& result) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->results_.push_back(result);
}

void ToolResultAggregator::AddResults(const std::vector<AgentToolResult>& results) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->results_.insert(pImpl->results_.end(), results.begin(), results.end());
}

std::vector<AgentToolResult> ToolResultAggregator::GetAllResults() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->results_;
}

std::vector<AgentToolResult> ToolResultAggregator::GetSuccessfulResults() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    std::vector<AgentToolResult> successful;
    for (const auto& result : pImpl->results_) {
        if (result.success) {
            successful.push_back(result);
        }
    }
    return successful;
}

std::vector<AgentToolResult> ToolResultAggregator::GetFailedResults() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    std::vector<AgentToolResult> failed;
    for (const auto& result : pImpl->results_) {
        if (!result.success) {
            failed.push_back(result);
        }
    }
    return failed;
}

std::optional<AgentToolResult> ToolResultAggregator::GetResultByToolName(const std::string& name) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    for (const auto& result : pImpl->results_) {
        if (result.tool_name == name) {
            return result;
        }
    }
    return std::nullopt;
}

json ToolResultAggregator::GenerateSummary() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    size_t total = pImpl->results_.size();
    size_t successful = 0;
    int64_t total_time = 0;
    
    for (const auto& result : pImpl->results_) {
        if (result.success) successful++;
        total_time += result.execution_time_ms;
    }
    
    json summary;
    summary["total"] = total;
    summary["successful"] = successful;
    summary["failed"] = total - successful;
    summary["success_rate"] = total > 0 ? static_cast<double>(successful) / total : 0.0;
    summary["total_time_ms"] = total_time;
    summary["average_time_ms"] = total > 0 ? static_cast<double>(total_time) / total : 0.0;
    
    return summary;
}

std::string ToolResultAggregator::GenerateReport() const {
    std::stringstream report;
    json summary = GenerateSummary();
    
    report << "Tool Execution Report\n";
    report << "====================\n\n";
    report << "Total executions: " << summary["total"] << "\n";
    report << "Successful: " << summary["successful"] << "\n";
    report << "Failed: " << summary["failed"] << "\n";
    report << "Success rate: " << (summary["success_rate"].get<double>() * 100) << "%\n";
    report << "Total time: " << summary["total_time_ms"] << "ms\n";
    report << "Average time: " << summary["average_time_ms"] << "ms\n\n";
    
    report << "Detailed Results:\n";
    report << "-----------------\n";
    
    auto results = GetAllResults();
    for (const auto& result : results) {
        report << "\n" << result.tool_name << ":\n";
        report << "  Success: " << (result.success ? "Yes" : "No") << "\n";
        report << "  Time: " << result.execution_time_ms << "ms\n";
        if (!result.success) {
            report << "  Error: " << result.error_message << "\n";
        }
    }
    
    return report.str();
}

void ToolResultAggregator::Clear() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->results_.clear();
}

// AgentToolUtils implementation
namespace AgentToolUtils {

ToolCall AgentRequestToToolCall(const std::string& agent_request) {
    ToolCall call;
    // Parse agent request to extract tool call
    // Simplified implementation
    call.name = "unknown";
    call.arguments = json::object();
    call.call_id = "call_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    return call;
}

std::string ToolResultToAgentResponse(const AgentToolResult& result) {
    std::stringstream response;
    if (result.success) {
        response << "Tool " << result.tool_name << " executed successfully.";
    } else {
        response << "Tool " << result.tool_name << " failed: " << result.error_message;
    }
    return response.str();
}

std::string BuildToolSystemPrompt(const std::vector<ToolDefinitionAPI>& tools) {
    std::stringstream prompt;
    prompt << "You are an AI assistant with access to the following tools:\n\n";
    
    for (const auto& tool : tools) {
        prompt << "Tool: " << tool.function.name << "\n";
        prompt << "Description: " << tool.function.description << "\n";
        prompt << "Parameters: " << tool.function.parameters.dump(2) << "\n\n";
    }
    
    prompt << "When you need to use a tool, respond with a JSON object containing:\n";
    prompt << "- tool: the name of the tool to use\n";
    prompt << "- arguments: the parameters for the tool\n";
    
    return prompt.str();
}

std::string BuildToolExamplePrompt() {
    return R"(
Example tool usage:

User: "Read the file config.json"

Assistant: {
  "tool": "file_read",
  "arguments": {
    "path": "config.json"
  }
}

System: {"content": "{\"setting\": \"value\"}"}

Assistant: The config.json file contains: {"setting": "value"}
)";
}

std::vector<ToolCall> ParseToolCallsFromText(const std::string& text) {
    std::vector<ToolCall> calls;
    
    // Try to find JSON objects in the text
    size_t start = text.find('{');
    while (start != std::string::npos) {
        size_t end = text.find('}', start);
        if (end == std::string::npos) break;
        
        std::string json_str = text.substr(start, end - start + 1);
        try {
            json j = json::parse(json_str);
            if (j.contains("tool") || j.contains("name")) {
                ToolCall call;
                call.name = j.value("tool", j.value("name", ""));
                call.arguments = j.value("arguments", j.value("parameters", json::object()));
                call.call_id = "call_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
                calls.push_back(call);
            }
        } catch (...) {
            // Not valid JSON, continue
        }
        
        start = text.find('{', end);
    }
    
    return calls;
}

std::string FormatToolError(const std::string& tool_name, const std::string& error) {
    return "Tool '" + tool_name + "' failed: " + error;
}

bool IsRetryableError(const std::string& error) {
    std::string lower = error;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    std::vector<std::string> retryable = {
        "timeout", "temporary", "transient", "retry", "unavailable",
        "connection", "network", "rate limit"
    };
    
    for (const auto& keyword : retryable) {
        if (lower.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

} // namespace AgentToolUtils

} // namespace FunctionCalling
} // namespace Agent
} // namespace RawrXD
