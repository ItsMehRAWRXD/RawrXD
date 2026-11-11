// RawrXD Sovereign v1.1.0 - Function Calling Framework
// ToolRegistry.hpp - Central registry for available tools

#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace FunctionCalling {

using json = nlohmann::json;

// Tool permission levels
enum class ToolPermission {
    READ_ONLY,      // Safe operations (read files, list directory)
    WRITE_SAFE,     // Write operations with validation
    WRITE_UNSAFE,   // Potentially destructive operations
    EXECUTE         // Code execution
};

// Tool call structure
struct ToolCall {
    std::string name;
    json arguments;
    ToolPermission permission;
    std::string call_id;
    
    ToolCall() = default;
    ToolCall(const std::string& n, const json& args, ToolPermission perm, const std::string& id)
        : name(n), arguments(args), permission(perm), call_id(id) {}
};

// Tool result structure
struct ToolResult {
    bool success;
    json data;
    std::string error_message;
    int64_t execution_time_ms;
    
    ToolResult() : success(false), execution_time_ms(0) {}
    static ToolResult Success(const json& d, int64_t time_ms = 0) {
        ToolResult r;
        r.success = true;
        r.data = d;
        r.execution_time_ms = time_ms;
        return r;
    }
    static ToolResult Error(const std::string& msg) {
        ToolResult r;
        r.success = false;
        r.error_message = msg;
        return r;
    }
};

// Tool definition
struct ToolDefinition {
    std::string name;
    std::string description;
    json parameters_schema;
    json returns_schema;
    ToolPermission default_permission;
    bool requires_confirmation;
    
    ToolDefinition() : default_permission(ToolPermission::READ_ONLY), requires_confirmation(false) {}
};

// Tool function type
using ToolFunction = std::function<ToolResult(const json& arguments)>;

// ToolRegistry class
class ToolRegistry {
public:
    ToolRegistry();
    ~ToolRegistry();

    // Registration
    bool RegisterTool(const ToolDefinition& definition, ToolFunction function);
    bool UnregisterTool(const std::string& name);
    bool IsToolRegistered(const std::string& name) const;

    // Query
    std::vector<ToolDefinition> GetAllTools() const;
    std::vector<ToolDefinition> GetToolsByPermission(ToolPermission perm) const;
    std::optional<ToolDefinition> GetToolDefinition(const std::string& name) const;

    // Execution
    ToolResult ExecuteTool(const ToolCall& call);
    bool ValidateToolCall(const ToolCall& call, std::string& error) const;

    // Schema generation
    json GenerateOpenAICompatibleSchema() const;
    json GenerateClaudeCompatibleSchema() const;

    // Built-in tools
    void RegisterBuiltInTools();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Built-in tool categories
namespace BuiltInTools {
    // Filesystem tools
    ToolDefinition FileRead();
    ToolDefinition FileWrite();
    ToolDefinition FileList();
    ToolDefinition DirectoryList();

    // Compiler tools
    ToolDefinition CompileCode();
    ToolDefinition RunExecutable();
    ToolDefinition CheckSyntax();

    // Debugger tools
    ToolDefinition SetBreakpoint();
    ToolDefinition GetStackTrace();
    ToolDefinition EvaluateExpression();

    // Benchmark tools
    ToolDefinition RunBenchmark();
    ToolDefinition ProfileCode();
    ToolDefinition MeasureMemory();

    // System tools
    ToolDefinition ExecuteCommand();
    ToolDefinition GetSystemInfo();
    ToolDefinition CheckEnvironment();
}

} // namespace FunctionCalling
} // namespace RawrXD
