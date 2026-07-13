// RawrXD Sovereign v1.1.0 - Function Calling Framework
// FunctionCallingAPI.hpp - OpenAI-compatible function calling API

#pragma once

#include "ToolRegistry.hpp"
#include "ToolExecutor.hpp"
#include "SchemaValidator.hpp"
#include <vector>
#include <optional>
#include <memory>

namespace RawrXD {
namespace FunctionCalling {

// OpenAI-compatible function definition
struct FunctionDefinition {
    std::string name;
    std::string description;
    json parameters;
    
    FunctionDefinition() = default;
    FunctionDefinition(const std::string& n, const std::string& d, const json& p)
        : name(n), description(d), parameters(p) {}
    
    static FunctionDefinition FromToolDefinition(const ToolDefinition& tool);
    ToolDefinition ToToolDefinition() const;
};

// OpenAI-compatible tool definition (function type)
struct ToolDefinitionAPI {
    std::string type;  // "function"
    FunctionDefinition function;
    
    ToolDefinitionAPI() : type("function") {}
    explicit ToolDefinitionAPI(const FunctionDefinition& func) 
        : type("function"), function(func) {}
    
    json ToJSON() const;
    static ToolDefinitionAPI FromJSON(const json& j);
};

// OpenAI-compatible function call from model
struct FunctionCall {
    std::string name;
    std::string arguments;  // JSON string
    std::string call_id;
    
    FunctionCall() = default;
    FunctionCall(const std::string& n, const std::string& a, const std::string& id)
        : name(n), arguments(a), call_id(id) {}
    
    json ParseArguments() const;
    bool IsValid() const;
};

// OpenAI-compatible tool call from model
struct ToolCallAPI {
    std::string id;
    std::string type;  // "function"
    FunctionCall function;
    
    ToolCallAPI() : type("function") {}
    
    json ToJSON() const;
    static ToolCallAPI FromJSON(const json& j);
    ToolCall ToToolCall() const;
};

// Function calling choice (for streaming/non-streaming)
struct FunctionCallChoice {
    int index;
    std::optional<FunctionCall> function_call;
    std::string finish_reason;  // "function_call" or "stop"
    
    FunctionCallChoice() : index(0) {}
    
    json ToJSON() const;
    static FunctionCallChoice FromJSON(const json& j);
};

// Tool call choice
struct ToolCallChoice {
    int index;
    std::vector<ToolCallAPI> tool_calls;
    std::string finish_reason;
    
    ToolCallChoice() : index(0) {}
    
    json ToJSON() const;
    static ToolCallChoice FromJSON(const json& j);
};

// Function result for model context
struct FunctionResult {
    std::string role;  // "tool"
    std::string tool_call_id;
    std::string name;
    std::string content;  // JSON string of result
    
    FunctionResult() : role("tool") {}
    FunctionResult(const std::string& id, const std::string& n, const json& result)
        : role("tool"), tool_call_id(id), name(n), content(result.dump()) {}
    
    json ToJSON() const;
    static FunctionResult FromToolResult(const std::string& call_id,
                                          const std::string& name,
                                          const ToolResult& result);
};

// Chat message with function support
struct ChatMessage {
    std::string role;  // "system", "user", "assistant", "tool"
    std::optional<std::string> content;
    std::optional<std::string> name;
    std::optional<FunctionCall> function_call;
    std::optional<std::vector<ToolCallAPI>> tool_calls;
    std::optional<std::string> tool_call_id;
    
    ChatMessage() = default;
    explicit ChatMessage(const std::string& r) : role(r) {}
    
    static ChatMessage System(const std::string& content);
    static ChatMessage User(const std::string& content);
    static ChatMessage Assistant(const std::string& content);
    static ChatMessage AssistantWithFunctionCall(const FunctionCall& call);
    static ChatMessage AssistantWithToolCalls(const std::vector<ToolCallAPI>& calls);
    static ChatMessage Tool(const std::string& tool_call_id, 
                           const std::string& name,
                           const json& result);
    
    json ToJSON() const;
    static ChatMessage FromJSON(const json& j);
};

// Function calling request
struct FunctionCallingRequest {
    std::string model;
    std::vector<ChatMessage> messages;
    std::vector<ToolDefinitionAPI> tools;
    std::optional<std::string> tool_choice;  // "auto", "none", or specific tool
    std::optional<std::vector<FunctionDefinition>> functions;  // Legacy
    std::optional<std::string> function_call;  // Legacy
    int max_tokens;
    float temperature;
    float top_p;
    int n;
    bool stream;
    
    FunctionCallingRequest() 
        : max_tokens(4096)
        , temperature(0.7f)
        , top_p(1.0f)
        , n(1)
        , stream(false) {}
    
    json ToJSON() const;
    static FunctionCallingRequest FromJSON(const json& j);
};

// Function calling response
struct FunctionCallingResponse {
    std::string id;
    std::string object;  // "chat.completion"
    int64_t created;
    std::string model;
    std::vector<ToolCallChoice> choices;
    json usage;
    
    FunctionCallingResponse() : object("chat.completion"), created(0) {}
    
    json ToJSON() const;
    static FunctionCallingResponse FromJSON(const json& j);
    bool HasToolCalls() const;
    std::vector<ToolCall> GetToolCalls() const;
};

// Streaming delta for function calls
struct FunctionCallDelta {
    std::optional<std::string> role;
    std::optional<std::string> content;
    std::optional<FunctionCall> function_call;
    std::optional<std::vector<ToolCallAPI>> tool_calls;
    
    json ToJSON() const;
    static FunctionCallDelta FromJSON(const json& j);
};

// Streaming chunk
struct FunctionCallingChunk {
    std::string id;
    std::string object;  // "chat.completion.chunk"
    int64_t created;
    std::string model;
    std::vector<FunctionCallDelta> choices;
    
    FunctionCallingChunk() : object("chat.completion.chunk"), created(0) {}
    
    json ToJSON() const;
    static FunctionCallingChunk FromJSON(const json& j);
    bool IsComplete() const;
};

// Function calling handler
class FunctionCallingHandler {
public:
    FunctionCallingHandler();
    ~FunctionCallingHandler();

    // Initialize with registry and executor
    void Initialize(ToolRegistry* registry, ToolExecutor* executor);
    bool IsInitialized() const;

    // Request handling
    FunctionCallingResponse HandleRequest(const FunctionCallingRequest& request);
    void HandleStreamingRequest(const FunctionCallingRequest& request,
                                 std::function<void(const FunctionCallingChunk&)> callback);

    // Tool execution from model response
    std::vector<FunctionResult> ExecuteToolCalls(
        const std::vector<ToolCallAPI>& tool_calls,
        const ExecutionContext& ctx);
    
    FunctionResult ExecuteToolCall(const ToolCallAPI& tool_call,
                                    const ExecutionContext& ctx);

    // Response building
    FunctionCallingResponse BuildResponse(
        const std::string& model,
        const std::vector<ChatMessage>& messages,
        const std::vector<FunctionResult>& results);

    // Tool registration helpers
    void RegisterToolsFromRegistry();
    std::vector<ToolDefinitionAPI> GetAvailableTools() const;

    // Configuration
    void SetDefaultExecutionContext(const ExecutionContext& ctx);
    ExecutionContext GetDefaultExecutionContext() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Auto-function calling mode
class AutoFunctionCaller {
public:
    AutoFunctionCaller(FunctionCallingHandler* handler);
    ~AutoFunctionCaller();

    // Single-turn with automatic tool execution
    std::vector<ChatMessage> ChatWithTools(
        const std::string& model,
        const std::vector<ChatMessage>& messages,
        const std::vector<ToolDefinitionAPI>& tools,
        int max_iterations = 10);

    // Configuration
    void SetMaxIterations(int max);
    void SetAutoExecute(bool auto_exec);
    void SetExecutionContext(const ExecutionContext& ctx);

private:
    FunctionCallingHandler* handler_;
    int max_iterations_;
    bool auto_execute_;
    ExecutionContext ctx_;
};

// Utility functions
namespace FunctionCallingUtils {
    // Convert between formats
    json ToolCallToOpenAIFormat(const ToolCall& call);
    json ToolResultToOpenAIFormat(const ToolResult& result);
    
    // Build system messages
    ChatMessage BuildToolSystemMessage(const std::vector<ToolDefinitionAPI>& tools);
    
    // Parse model responses
    std::optional<FunctionCall> ExtractFunctionCall(const json& response);
    std::vector<ToolCallAPI> ExtractToolCalls(const json& response);
    
    // Validation
    bool ValidateToolChoice(const std::string& choice, 
                            const std::vector<ToolDefinitionAPI>& available_tools);
    
    // Error handling
    FunctionResult CreateErrorResult(const std::string& call_id,
                                      const std::string& name,
                                      const std::string& error);
}

} // namespace FunctionCalling
} // namespace RawrXD
