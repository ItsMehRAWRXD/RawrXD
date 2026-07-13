// RawrXD Sovereign v1.1.0 - Function Calling Framework
// AgentToolIntegration.hpp - Integration with AgentSubsystem

#pragma once

#include "FunctionCallingAPI.hpp"
#include <memory>
#include <functional>

namespace RawrXD {
namespace Agent {

// Forward declarations from AgentSubsystem
class Planner;
class Coder;
class Reflector;
struct AgentContext;
struct AgentResult;

namespace FunctionCalling {

using namespace RawrXD::FunctionCalling;

// Tool-augmented agent context
struct ToolAugmentedContext {
    AgentContext* base_context;
    ToolRegistry* tool_registry;
    ToolExecutor* tool_executor;
    SchemaValidator* schema_validator;
    FunctionCallingHandler* function_handler;
    std::vector<ToolDefinitionAPI> available_tools;
    ExecutionContext execution_context;
    int max_tool_iterations;
    bool auto_execute_tools;
    
    ToolAugmentedContext() 
        : base_context(nullptr)
        , tool_registry(nullptr)
        , tool_executor(nullptr)
        , schema_validator(nullptr)
        , function_handler(nullptr)
        , max_tool_iterations(10)
        , auto_execute_tools(true) {}
};

// Tool execution result for agents
struct AgentToolResult {
    bool success;
    std::string tool_name;
    json arguments;
    json result_data;
    std::string error_message;
    int64_t execution_time_ms;
    int iteration;
    
    AgentToolResult() : success(false), execution_time_ms(0), iteration(0) {}
};

// Tool-enabled planner
class ToolEnabledPlanner {
public:
    ToolEnabledPlanner();
    ~ToolEnabledPlanner();

    // Initialize with function calling components
    void Initialize(ToolRegistry* registry, SchemaValidator* validator);
    
    // Plan with tool awareness
    std::string CreateToolAwarePlan(const std::string& user_request,
                                     const std::vector<ToolDefinitionAPI>& tools);
    
    // Determine if tools are needed
    bool AreToolsNeeded(const std::string& user_request,
                        const std::vector<ToolDefinitionAPI>& tools);
    
    // Select appropriate tools for a task
    std::vector<ToolDefinitionAPI> SelectTools(const std::string& task,
                                                const std::vector<ToolDefinitionAPI>& available);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Tool-enabled coder
class ToolEnabledCoder {
public:
    ToolEnabledCoder();
    ~ToolEnabledCoder();

    void Initialize(ToolExecutor* executor, FunctionCallingHandler* handler);
    
    // Generate code with tool support
    std::string GenerateToolUsingCode(const std::string& plan,
                                       const std::vector<ToolDefinitionAPI>& tools);
    
    // Validate generated code
    bool ValidateCode(const std::string& code, std::string& error);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Tool-enabled reflector
class ToolEnabledReflector {
public:
    ToolEnabledReflector();
    ~ToolEnabledReflector();

    void Initialize(SchemaValidator* validator);
    
    // Reflect on tool execution results
    std::string ReflectOnResults(const std::vector<AgentToolResult>& results,
                                  const std::string& original_request);
    
    // Determine if more tool calls are needed
    bool NeedMoreTools(const std::vector<AgentToolResult>& results,
                       const std::string& goal);
    
    // Generate follow-up request if needed
    std::string GenerateFollowUp(const std::vector<AgentToolResult>& results,
                                  const std::string& original_request);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Main integration class
class AgentToolIntegration {
public:
    AgentToolIntegration();
    ~AgentToolIntegration();

    // Initialization
    void Initialize(ToolRegistry* registry,
                  ToolExecutor* executor,
                  SchemaValidator* validator,
                  FunctionCallingHandler* handler);
    bool IsInitialized() const;

    // Configure
    void SetMaxIterations(int max);
    void SetAutoExecute(bool auto_exec);
    void SetExecutionContext(const ExecutionContext& ctx);

    // Main execution flow
    AgentResult ExecuteWithTools(const std::string& user_request,
                                  AgentContext* context);

    // Step-by-step execution
    std::string Plan(const std::string& user_request);
    std::vector<ToolCall> IdentifyToolCalls(const std::string& plan);
    std::vector<AgentToolResult> ExecuteTools(const std::vector<ToolCall>& calls);
    std::string Reflect(const std::vector<AgentToolResult>& results,
                        const std::string& original_request);
    std::string GenerateResponse(const std::string& reflection,
                                  const std::vector<AgentToolResult>& results);

    // Tool management
    void RegisterBuiltInTools();
    std::vector<ToolDefinitionAPI> GetAvailableTools() const;
    void AddCustomTool(const ToolDefinition& def, ToolFunction func);

    // Statistics
    size_t GetTotalToolExecutions() const;
    size_t GetSuccessfulToolExecutions() const;
    double GetAverageToolExecutionTimeMs() const;
    void ResetStatistics();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Tool execution callback
using ToolExecutionCallback = std::function<void(const AgentToolResult&)>;

// Async tool execution
class AsyncToolExecutor {
public:
    AsyncToolExecutor(ToolExecutor* executor);
    ~AsyncToolExecutor();

    // Execute tools asynchronously with callbacks
    void ExecuteAsync(const std::vector<ToolCall>& calls,
                      ToolExecutionCallback callback);
    
    // Wait for all executions to complete
    void WaitForCompletion();
    
    // Cancel pending executions
    void CancelAll();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Tool result aggregator
class ToolResultAggregator {
public:
    ToolResultAggregator();
    ~ToolResultAggregator();

    // Add results
    void AddResult(const AgentToolResult& result);
    void AddResults(const std::vector<AgentToolResult>& results);

    // Query results
    std::vector<AgentToolResult> GetAllResults() const;
    std::vector<AgentToolResult> GetSuccessfulResults() const;
    std::vector<AgentToolResult> GetFailedResults() const;
    std::optional<AgentToolResult> GetResultByToolName(const std::string& name) const;
    
    // Summary
    json GenerateSummary() const;
    std::string GenerateReport() const;

    // Clear
    void Clear();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Integration utilities
namespace AgentToolUtils {
    // Convert between agent and function calling types
    ToolCall AgentRequestToToolCall(const std::string& agent_request);
    std::string ToolResultToAgentResponse(const AgentToolResult& result);
    
    // Build system prompts
    std::string BuildToolSystemPrompt(const std::vector<ToolDefinitionAPI>& tools);
    std::string BuildToolExamplePrompt();
    
    // Parse tool calls from model output
    std::vector<ToolCall> ParseToolCallsFromText(const std::string& text);
    
    // Error handling
    std::string FormatToolError(const std::string& tool_name, const std::string& error);
    bool IsRetryableError(const std::string& error);
}

// Configuration
struct AgentToolConfig {
    int max_iterations = 10;
    bool auto_execute = true;
    bool require_confirmation_for_write = true;
    bool require_confirmation_for_execute = true;
    int timeout_seconds = 60;
    size_t max_memory_bytes = 512 * 1024 * 1024;  // 512MB
    std::vector<std::string> allowed_paths;
    std::vector<std::string> blocked_commands;
    
    ExecutionContext ToExecutionContext() const {
        ExecutionContext ctx;
        ctx.timeout_seconds = timeout_seconds;
        ctx.max_memory_bytes = max_memory_bytes;
        ctx.allowed_paths = allowed_paths;
        return ctx;
    }
};

} // namespace FunctionCalling
} // namespace Agent
} // namespace RawrXD
