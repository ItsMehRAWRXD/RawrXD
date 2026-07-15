// RawrXD Sovereign v1.1.0 - Function Calling Framework
// FunctionCallingAPI.cpp - Implementation

#include "FunctionCallingAPI.hpp"
#include <chrono>

namespace RawrXD {
namespace FunctionCalling {

// FunctionDefinition implementation
FunctionDefinition FunctionDefinition::FromToolDefinition(const ToolDefinition& tool) {
    FunctionDefinition def;
    def.name = tool.name;
    def.description = tool.description;
    def.parameters = tool.parameters_schema;
    return def;
}

ToolDefinition FunctionDefinition::ToToolDefinition() const {
    ToolDefinition def;
    def.name = name;
    def.description = description;
    def.parameters_schema = parameters;
    return def;
}

// ToolDefinitionAPI implementation
json ToolDefinitionAPI::ToJSON() const {
    json j;
    j["type"] = type;
    j["function"]["name"] = function.name;
    j["function"]["description"] = function.description;
    j["function"]["parameters"] = function.parameters;
    return j;
}

ToolDefinitionAPI ToolDefinitionAPI::FromJSON(const json& j) {
    ToolDefinitionAPI def;
    def.type = j.value("type", "function");
    if (j.contains("function")) {
        const auto& func = j["function"];
        def.function.name = func.value("name", "");
        def.function.description = func.value("description", "");
        def.function.parameters = func.value("parameters", json::object());
    }
    return def;
}

// FunctionCall implementation
json FunctionCall::ParseArguments() const {
    try {
        return json::parse(arguments);
    } catch (const std::exception&) {
        return json::object();
    }
}

bool FunctionCall::IsValid() const {
    return !name.empty() && !arguments.empty();
}

// ToolCallAPI implementation
json ToolCallAPI::ToJSON() const {
    json j;
    j["id"] = id;
    j["type"] = type;
    j["function"]["name"] = function.name;
    j["function"]["arguments"] = function.arguments;
    return j;
}

ToolCallAPI ToolCallAPI::FromJSON(const json& j) {
    ToolCallAPI call;
    call.id = j.value("id", "");
    call.type = j.value("type", "function");
    if (j.contains("function")) {
        const auto& func = j["function"];
        call.function.name = func.value("name", "");
        call.function.arguments = func.value("arguments", "");
    }
    return call;
}

ToolCall ToolCallAPI::ToToolCall() const {
    ToolCall call;
    call.name = function.name;
    call.arguments = function.ParseArguments();
    call.call_id = id;
    // Determine permission based on tool name
    if (function.name.find("execute") != std::string::npos ||
        function.name.find("run") != std::string::npos ||
        function.name.find("compile") != std::string::npos) {
        call.permission = ToolPermission::EXECUTE;
    } else if (function.name.find("write") != std::string::npos) {
        call.permission = ToolPermission::WRITE_SAFE;
    } else {
        call.permission = ToolPermission::READ_ONLY;
    }
    return call;
}

// FunctionCallChoice implementation
json FunctionCallChoice::ToJSON() const {
    json j;
    j["index"] = index;
    if (function_call.has_value()) {
        j["function_call"]["name"] = function_call->name;
        j["function_call"]["arguments"] = function_call->arguments;
    }
    j["finish_reason"] = finish_reason;
    return j;
}

FunctionCallChoice FunctionCallChoice::FromJSON(const json& j) {
    FunctionCallChoice choice;
    choice.index = j.value("index", 0);
    if (j.contains("function_call")) {
        FunctionCall call;
        call.name = j["function_call"].value("name", "");
        call.arguments = j["function_call"].value("arguments", "");
        choice.function_call = call;
    }
    choice.finish_reason = j.value("finish_reason", "");
    return choice;
}

// ToolCallChoice implementation
json ToolCallChoice::ToJSON() const {
    json j;
    j["index"] = index;
    j["tool_calls"] = json::array();
    for (const auto& call : tool_calls) {
        j["tool_calls"].push_back(call.ToJSON());
    }
    j["finish_reason"] = finish_reason;
    return j;
}

ToolCallChoice ToolCallChoice::FromJSON(const json& j) {
    ToolCallChoice choice;
    choice.index = j.value("index", 0);
    if (j.contains("tool_calls")) {
        for (const auto& call_json : j["tool_calls"]) {
            choice.tool_calls.push_back(ToolCallAPI::FromJSON(call_json));
        }
    }
    choice.finish_reason = j.value("finish_reason", "");
    return choice;
}

// FunctionResult implementation
json FunctionResult::ToJSON() const {
    json j;
    j["role"] = role;
    j["tool_call_id"] = tool_call_id;
    j["name"] = name;
    j["content"] = content;
    return j;
}

FunctionResult FunctionResult::FromToolResult(const std::string& call_id,
                                               const std::string& name,
                                               const ToolResult& result) {
    FunctionResult fr;
    fr.role = "tool";
    fr.tool_call_id = call_id;
    fr.name = name;
    
    json content;
    content["success"] = result.success;
    if (result.success) {
        content["data"] = result.data;
    } else {
        content["error"] = result.error_message;
    }
    content["execution_time_ms"] = result.execution_time_ms;
    fr.content = content.dump();
    
    return fr;
}

// ChatMessage implementation
ChatMessage ChatMessage::System(const std::string& content) {
    ChatMessage msg("system");
    msg.content = content;
    return msg;
}

ChatMessage ChatMessage::User(const std::string& content) {
    ChatMessage msg("user");
    msg.content = content;
    return msg;
}

ChatMessage ChatMessage::Assistant(const std::string& content) {
    ChatMessage msg("assistant");
    msg.content = content;
    return msg;
}

ChatMessage ChatMessage::AssistantWithFunctionCall(const FunctionCall& call) {
    ChatMessage msg("assistant");
    msg.function_call = call;
    return msg;
}

ChatMessage ChatMessage::AssistantWithToolCalls(const std::vector<ToolCallAPI>& calls) {
    ChatMessage msg("assistant");
    msg.tool_calls = calls;
    return msg;
}

ChatMessage ChatMessage::Tool(const std::string& tool_call_id, 
                             const std::string& name,
                             const json& result) {
    ChatMessage msg("tool");
    msg.tool_call_id = tool_call_id;
    msg.name = name;
    msg.content = result.dump();
    return msg;
}

json ChatMessage::ToJSON() const {
    json j;
    j["role"] = role;
    if (content.has_value()) {
        j["content"] = *content;
    }
    if (name.has_value()) {
        j["name"] = *name;
    }
    if (function_call.has_value()) {
        j["function_call"]["name"] = function_call->name;
        j["function_call"]["arguments"] = function_call->arguments;
    }
    if (tool_calls.has_value()) {
        j["tool_calls"] = json::array();
        for (const auto& call : *tool_calls) {
            j["tool_calls"].push_back(call.ToJSON());
        }
    }
    if (tool_call_id.has_value()) {
        j["tool_call_id"] = *tool_call_id;
    }
    return j;
}

ChatMessage ChatMessage::FromJSON(const json& j) {
    ChatMessage msg;
    msg.role = j.value("role", "");
    if (j.contains("content")) {
        msg.content = j["content"].get<std::string>();
    }
    if (j.contains("name")) {
        msg.name = j["name"].get<std::string>();
    }
    if (j.contains("function_call")) {
        FunctionCall call;
        call.name = j["function_call"].value("name", "");
        call.arguments = j["function_call"].value("arguments", "");
        msg.function_call = call;
    }
    if (j.contains("tool_calls")) {
        std::vector<ToolCallAPI> calls;
        for (const auto& call_json : j["tool_calls"]) {
            calls.push_back(ToolCallAPI::FromJSON(call_json));
        }
        msg.tool_calls = calls;
    }
    if (j.contains("tool_call_id")) {
        msg.tool_call_id = j["tool_call_id"].get<std::string>();
    }
    return msg;
}

// FunctionCallingRequest implementation
json FunctionCallingRequest::ToJSON() const {
    json j;
    j["model"] = model;
    j["messages"] = json::array();
    for (const auto& msg : messages) {
        j["messages"].push_back(msg.ToJSON());
    }
    j["tools"] = json::array();
    for (const auto& tool : tools) {
        j["tools"].push_back(tool.ToJSON());
    }
    if (tool_choice.has_value()) {
        j["tool_choice"] = *tool_choice;
    }
    j["max_tokens"] = max_tokens;
    j["temperature"] = temperature;
    j["top_p"] = top_p;
    j["n"] = n;
    j["stream"] = stream;
    return j;
}

FunctionCallingRequest FunctionCallingRequest::FromJSON(const json& j) {
    FunctionCallingRequest req;
    req.model = j.value("model", "");
    if (j.contains("messages")) {
        for (const auto& msg_json : j["messages"]) {
            req.messages.push_back(ChatMessage::FromJSON(msg_json));
        }
    }
    if (j.contains("tools")) {
        for (const auto& tool_json : j["tools"]) {
            req.tools.push_back(ToolDefinitionAPI::FromJSON(tool_json));
        }
    }
    if (j.contains("tool_choice")) {
        req.tool_choice = j["tool_choice"].get<std::string>();
    }
    req.max_tokens = j.value("max_tokens", 4096);
    req.temperature = j.value("temperature", 0.7f);
    req.top_p = j.value("top_p", 1.0f);
    req.n = j.value("n", 1);
    req.stream = j.value("stream", false);
    return req;
}

// FunctionCallingResponse implementation
json FunctionCallingResponse::ToJSON() const {
    json j;
    j["id"] = id;
    j["object"] = object;
    j["created"] = created;
    j["model"] = model;
    j["choices"] = json::array();
    for (const auto& choice : choices) {
        j["choices"].push_back(choice.ToJSON());
    }
    j["usage"] = usage;
    return j;
}

FunctionCallingResponse FunctionCallingResponse::FromJSON(const json& j) {
    FunctionCallingResponse resp;
    resp.id = j.value("id", "");
    resp.object = j.value("object", "chat.completion");
    resp.created = j.value("created", 0);
    resp.model = j.value("model", "");
    if (j.contains("choices")) {
        for (const auto& choice_json : j["choices"]) {
            resp.choices.push_back(ToolCallChoice::FromJSON(choice_json));
        }
    }
    resp.usage = j.value("usage", json::object());
    return resp;
}

bool FunctionCallingResponse::HasToolCalls() const {
    for (const auto& choice : choices) {
        if (!choice.tool_calls.empty()) {
            return true;
        }
    }
    return false;
}

std::vector<ToolCall> FunctionCallingResponse::GetToolCalls() const {
    std::vector<ToolCall> calls;
    for (const auto& choice : choices) {
        for (const auto& tool_call : choice.tool_calls) {
            calls.push_back(tool_call.ToToolCall());
        }
    }
    return calls;
}

// FunctionCallDelta implementation
json FunctionCallDelta::ToJSON() const {
    json j;
    if (role.has_value()) {
        j["role"] = *role;
    }
    if (content.has_value()) {
        j["content"] = *content;
    }
    if (function_call.has_value()) {
        j["function_call"]["name"] = function_call->name;
        j["function_call"]["arguments"] = function_call->arguments;
    }
    if (tool_calls.has_value()) {
        j["tool_calls"] = json::array();
        for (const auto& call : *tool_calls) {
            j["tool_calls"].push_back(call.ToJSON());
        }
    }
    return j;
}

FunctionCallDelta FunctionCallDelta::FromJSON(const json& j) {
    FunctionCallDelta delta;
    if (j.contains("role")) {
        delta.role = j["role"].get<std::string>();
    }
    if (j.contains("content")) {
        delta.content = j["content"].get<std::string>();
    }
    if (j.contains("function_call")) {
        FunctionCall call;
        call.name = j["function_call"].value("name", "");
        call.arguments = j["function_call"].value("arguments", "");
        delta.function_call = call;
    }
    if (j.contains("tool_calls")) {
        std::vector<ToolCallAPI> calls;
        for (const auto& call_json : j["tool_calls"]) {
            calls.push_back(ToolCallAPI::FromJSON(call_json));
        }
        delta.tool_calls = calls;
    }
    return delta;
}

// FunctionCallingChunk implementation
json FunctionCallingChunk::ToJSON() const {
    json j;
    j["id"] = id;
    j["object"] = object;
    j["created"] = created;
    j["model"] = model;
    j["choices"] = json::array();
    for (const auto& choice : choices) {
        json choice_json;
        choice_json["delta"] = choice.ToJSON();
        j["choices"].push_back(choice_json);
    }
    return j;
}

FunctionCallingChunk FunctionCallingChunk::FromJSON(const json& j) {
    FunctionCallingChunk chunk;
    chunk.id = j.value("id", "");
    chunk.object = j.value("object", "chat.completion.chunk");
    chunk.created = j.value("created", 0);
    chunk.model = j.value("model", "");
    if (j.contains("choices")) {
        for (const auto& choice_json : j["choices"]) {
            if (choice_json.contains("delta")) {
                chunk.choices.push_back(FunctionCallDelta::FromJSON(choice_json["delta"]));
            }
        }
    }
    return chunk;
}

bool FunctionCallingChunk::IsComplete() const {
    for (const auto& choice : choices) {
        if (choice.role.has_value() && *choice.role == "assistant") {
            // Check if this is the final chunk
        }
    }
    return false;
}

// FunctionCallingHandler implementation
class FunctionCallingHandler::Impl {
public:
    ToolRegistry* registry_ = nullptr;
    ToolExecutor* executor_ = nullptr;
    ExecutionContext default_context_;
    bool initialized_ = false;
};

FunctionCallingHandler::FunctionCallingHandler() : pImpl(std::make_unique<Impl>()) {}
FunctionCallingHandler::~FunctionCallingHandler() = default;

void FunctionCallingHandler::Initialize(ToolRegistry* registry, ToolExecutor* executor) {
    pImpl->registry_ = registry;
    pImpl->executor_ = executor;
    pImpl->initialized_ = true;
}

bool FunctionCallingHandler::IsInitialized() const {
    return pImpl->initialized_;
}

FunctionCallingResponse FunctionCallingHandler::HandleRequest(const FunctionCallingRequest& request) {
    FunctionCallingResponse response;
    response.id = "chatcmpl-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    response.object = "chat.completion";
    response.created = std::chrono::system_clock::now().time_since_epoch().count();
    response.model = request.model;
    
    // In a real implementation, this would call the LLM
    // For now, return a placeholder response
    ToolCallChoice choice;
    choice.index = 0;
    choice.finish_reason = "stop";
    response.choices.push_back(choice);
    
    response.usage = {
        {"prompt_tokens", 0},
        {"completion_tokens", 0},
        {"total_tokens", 0}
    };
    
    return response;
}

void FunctionCallingHandler::HandleStreamingRequest(
    const FunctionCallingRequest& request,
    std::function<void(const FunctionCallingChunk&)> callback) {
    
    // Simulate streaming response
    FunctionCallingChunk chunk;
    chunk.id = "chatcmpl-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    chunk.object = "chat.completion.chunk";
    chunk.created = std::chrono::system_clock::now().time_since_epoch().count();
    chunk.model = request.model;
    
    FunctionCallDelta delta;
    delta.role = "assistant";
    delta.content = "";
    chunk.choices.push_back(delta);
    
    callback(chunk);
}

std::vector<FunctionResult> FunctionCallingHandler::ExecuteToolCalls(
    const std::vector<ToolCallAPI>& tool_calls,
    const ExecutionContext& ctx) {
    
    std::vector<FunctionResult> results;
    
    if (!pImpl->executor_) {
        return results;
    }
    
    for (const auto& tool_call : tool_calls) {
        ToolCall call = tool_call.ToToolCall();
        ExecutedToolResult exec_result = pImpl->executor_->Execute(call, ctx);
        
        ToolResult tool_result;
        tool_result.success = exec_result.success;
        tool_result.data = exec_result.data;
        tool_result.error_message = exec_result.error_message;
        tool_result.execution_time_ms = exec_result.execution_time_ms;
        
        results.push_back(FunctionResult::FromToolResult(
            tool_call.id, tool_call.function.name, tool_result));
    }
    
    return results;
}

FunctionResult FunctionCallingHandler::ExecuteToolCall(const ToolCallAPI& tool_call,
                                                       const ExecutionContext& ctx) {
    auto results = ExecuteToolCalls({tool_call}, ctx);
    if (!results.empty()) {
        return results[0];
    }
    return FunctionResult();
}

FunctionCallingResponse FunctionCallingHandler::BuildResponse(
    const std::string& model,
    const std::vector<ChatMessage>& messages,
    const std::vector<FunctionResult>& results) {
    
    FunctionCallingResponse response;
    response.id = "chatcmpl-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    response.object = "chat.completion";
    response.created = std::chrono::system_clock::now().time_since_epoch().count();
    response.model = model;
    
    // Build response with tool results
    ToolCallChoice choice;
    choice.index = 0;
    choice.finish_reason = "stop";
    response.choices.push_back(choice);
    
    return response;
}

void FunctionCallingHandler::RegisterToolsFromRegistry() {
    if (!pImpl->registry_) {
        return;
    }
    
    // Tools are already registered in the registry
    // This method is for syncing if needed
}

std::vector<ToolDefinitionAPI> FunctionCallingHandler::GetAvailableTools() const {
    std::vector<ToolDefinitionAPI> tools;
    
    if (!pImpl->registry_) {
        return tools;
    }
    
    for (const auto& def : pImpl->registry_->GetAllTools()) {
        tools.push_back(ToolDefinitionAPI(FunctionDefinition::FromToolDefinition(def)));
    }
    
    return tools;
}

void FunctionCallingHandler::SetDefaultExecutionContext(const ExecutionContext& ctx) {
    pImpl->default_context_ = ctx;
}

ExecutionContext FunctionCallingHandler::GetDefaultExecutionContext() const {
    return pImpl->default_context_;
}

// AutoFunctionCaller implementation
AutoFunctionCaller::AutoFunctionCaller(FunctionCallingHandler* handler)
    : handler_(handler)
    , max_iterations_(10)
    , auto_execute_(true) {}

AutoFunctionCaller::~AutoFunctionCaller() = default;

std::vector<ChatMessage> AutoFunctionCaller::ChatWithTools(
    const std::string& model,
    const std::vector<ChatMessage>& messages,
    const std::vector<ToolDefinitionAPI>& tools,
    int max_iterations) {
    
    std::vector<ChatMessage> conversation = messages;
    int iterations = 0;
    
    while (iterations < max_iterations) {
        // Build request
        FunctionCallingRequest request;
        request.model = model;
        request.messages = conversation;
        request.tools = tools;
        request.tool_choice = "auto";
        
        // Get response
        FunctionCallingResponse response = handler_->HandleRequest(request);
        
        // Check if there are tool calls
        if (!response.HasToolCalls()) {
            // No tool calls, we're done
            break;
        }
        
        // Execute tool calls
        auto tool_calls = response.GetToolCalls();
        std::vector<ToolCallAPI> tool_call_apis;
        for (const auto& call : tool_calls) {
            ToolCallAPI api;
            api.id = call.call_id;
            api.type = "function";
            api.function.name = call.name;
            api.function.arguments = call.arguments.dump();
            tool_call_apis.push_back(api);
        }
        
        auto results = handler_->ExecuteToolCalls(tool_call_apis, ctx_);
        
        // Add assistant message with tool calls
        conversation.push_back(ChatMessage::AssistantWithToolCalls(tool_call_apis));
        
        // Add tool results
        for (const auto& result : results) {
            conversation.push_back(ChatMessage::Tool(
                result.tool_call_id, result.name, json::parse(result.content)));
        }
        
        iterations++;
    }
    
    return conversation;
}

void AutoFunctionCaller::SetMaxIterations(int max) {
    max_iterations_ = max;
}

void AutoFunctionCaller::SetAutoExecute(bool auto_exec) {
    auto_execute_ = auto_exec;
}

void AutoFunctionCaller::SetExecutionContext(const ExecutionContext& ctx) {
    ctx_ = ctx;
}

// FunctionCallingUtils implementation
namespace FunctionCallingUtils {

json ToolCallToOpenAIFormat(const ToolCall& call) {
    json j;
    j["id"] = call.call_id;
    j["type"] = "function";
    j["function"]["name"] = call.name;
    j["function"]["arguments"] = call.arguments.dump();
    return j;
}

json ToolResultToOpenAIFormat(const ToolResult& result) {
    json j;
    j["success"] = result.success;
    if (result.success) {
        j["data"] = result.data;
    } else {
        j["error"] = result.error_message;
    }
    j["execution_time_ms"] = result.execution_time_ms;
    return j;
}

ChatMessage BuildToolSystemMessage(const std::vector<ToolDefinitionAPI>& tools) {
    std::string content = "You have access to the following tools:\n\n";
    for (const auto& tool : tools) {
        content += "- " + tool.function.name + ": " + tool.function.description + "\n";
    }
    content += "\nUse the tools to help answer the user's request.";
    return ChatMessage::System(content);
}

std::optional<FunctionCall> ExtractFunctionCall(const json& response) {
    if (response.contains("choices") && !response["choices"].empty()) {
        const auto& choice = response["choices"][0];
        if (choice.contains("function_call")) {
            FunctionCall call;
            call.name = choice["function_call"].value("name", "");
            call.arguments = choice["function_call"].value("arguments", "");
            return call;
        }
    }
    return std::nullopt;
}

std::vector<ToolCallAPI> ExtractToolCalls(const json& response) {
    std::vector<ToolCallAPI> calls;
    if (response.contains("choices") && !response["choices"].empty()) {
        const auto& choice = response["choices"][0];
        if (choice.contains("tool_calls")) {
            for (const auto& call_json : choice["tool_calls"]) {
                calls.push_back(ToolCallAPI::FromJSON(call_json));
            }
        }
    }
    return calls;
}

bool ValidateToolChoice(const std::string& choice, 
                        const std::vector<ToolDefinitionAPI>& available_tools) {
    if (choice == "auto" || choice == "none") {
        return true;
    }
    // Check if it's a specific tool name
    for (const auto& tool : available_tools) {
        if (tool.function.name == choice) {
            return true;
        }
    }
    return false;
}

FunctionResult CreateErrorResult(const std::string& call_id,
                                  const std::string& name,
                                  const std::string& error) {
    ToolResult tool_result = ToolResult::Error(error);
    return FunctionResult::FromToolResult(call_id, name, tool_result);
}

} // namespace FunctionCallingUtils

} // namespace FunctionCalling
} // namespace RawrXD
