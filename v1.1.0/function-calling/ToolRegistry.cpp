// RawrXD Sovereign v1.1.0 - Function Calling Framework
// ToolRegistry.cpp - Implementation

#include "ToolRegistry.hpp"
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace FunctionCalling {

// Implementation class
class ToolRegistry::Impl {
public:
    std::map<std::string, ToolDefinition> definitions_;
    std::map<std::string, ToolFunction> functions_;
    mutable std::mutex mutex_;
};

ToolRegistry::ToolRegistry() : pImpl(std::make_unique<Impl>()) {}
ToolRegistry::~ToolRegistry() = default;

bool ToolRegistry::RegisterTool(const ToolDefinition& definition, ToolFunction function) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    if (definition.name.empty()) {
        return false;
    }
    
    pImpl->definitions_[definition.name] = definition;
    pImpl->functions_[definition.name] = function;
    return true;
}

bool ToolRegistry::UnregisterTool(const std::string& name) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    auto it = pImpl->definitions_.find(name);
    if (it == pImpl->definitions_.end()) {
        return false;
    }
    
    pImpl->definitions_.erase(it);
    pImpl->functions_.erase(name);
    return true;
}

bool ToolRegistry::IsToolRegistered(const std::string& name) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->definitions_.find(name) != pImpl->definitions_.end();
}

std::vector<ToolDefinition> ToolRegistry::GetAllTools() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    std::vector<ToolDefinition> result;
    result.reserve(pImpl->definitions_.size());
    
    for (const auto& [name, def] : pImpl->definitions_) {
        result.push_back(def);
    }
    
    return result;
}

std::vector<ToolDefinition> ToolRegistry::GetToolsByPermission(ToolPermission perm) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    std::vector<ToolDefinition> result;
    for (const auto& [name, def] : pImpl->definitions_) {
        if (def.default_permission == perm) {
            result.push_back(def);
        }
    }
    
    return result;
}

std::optional<ToolDefinition> ToolRegistry::GetToolDefinition(const std::string& name) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    auto it = pImpl->definitions_.find(name);
    if (it == pImpl->definitions_.end()) {
        return std::nullopt;
    }
    
    return it->second;
}

ToolResult ToolRegistry::ExecuteTool(const ToolCall& call) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    auto it = pImpl->functions_.find(call.name);
    if (it == pImpl->functions_.end()) {
        return ToolResult::Error("Tool not found: " + call.name);
    }
    
    auto start = std::chrono::steady_clock::now();
    ToolResult result = it->second(call.arguments);
    auto end = std::chrono::steady_clock::now();
    
    result.execution_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start).count();
    
    return result;
}

bool ToolRegistry::ValidateToolCall(const ToolCall& call, std::string& error) const {
    auto def = GetToolDefinition(call.name);
    if (!def) {
        error = "Tool not found: " + call.name;
        return false;
    }
    
    // Basic validation - check if arguments is an object
    if (!call.arguments.is_object()) {
        error = "Arguments must be a JSON object";
        return false;
    }
    
    return true;
}

json ToolRegistry::GenerateOpenAICompatibleSchema() const {
    json tools = json::array();
    
    for (const auto& def : GetAllTools()) {
        json tool;
        tool["type"] = "function";
        tool["function"]["name"] = def.name;
        tool["function"]["description"] = def.description;
        tool["function"]["parameters"] = def.parameters_schema;
        tools.push_back(tool);
    }
    
    return tools;
}

json ToolRegistry::GenerateClaudeCompatibleSchema() const {
    json tools = json::array();
    
    for (const auto& def : GetAllTools()) {
        json tool;
        tool["name"] = def.name;
        tool["description"] = def.description;
        tool["input_schema"] = def.parameters_schema;
        tools.push_back(tool);
    }
    
    return tools;
}

void ToolRegistry::RegisterBuiltInTools() {
    // Filesystem tools
    RegisterTool(BuiltInTools::FileRead(), [](const json& args) {
        // Implementation placeholder
        return ToolResult::Success(json{{"content", "File content placeholder"}});
    });
    
    RegisterTool(BuiltInTools::FileWrite(), [](const json& args) {
        return ToolResult::Success(json{{"bytes_written", 0}});
    });
    
    RegisterTool(BuiltInTools::FileList(), [](const json& args) {
        return ToolResult::Success(json{{"files", json::array()}});
    });
    
    RegisterTool(BuiltInTools::DirectoryList(), [](const json& args) {
        return ToolResult::Success(json{{"directories", json::array()}});
    });
    
    // Compiler tools
    RegisterTool(BuiltInTools::CompileCode(), [](const json& args) {
        return ToolResult::Success(json{{"success", true}, {"output", ""}});
    });
    
    RegisterTool(BuiltInTools::RunExecutable(), [](const json& args) {
        return ToolResult::Success(json{{"exit_code", 0}, {"output", ""}});
    });
    
    RegisterTool(BuiltInTools::CheckSyntax(), [](const json& args) {
        return ToolResult::Success(json{{"valid", true}, {"errors", json::array()}});
    });
    
    // Debugger tools
    RegisterTool(BuiltInTools::SetBreakpoint(), [](const json& args) {
        return ToolResult::Success(json{{"breakpoint_id", 0}});
    });
    
    RegisterTool(BuiltInTools::GetStackTrace(), [](const json& args) {
        return ToolResult::Success(json{{"frames", json::array()}});
    });
    
    RegisterTool(BuiltInTools::EvaluateExpression(), [](const json& args) {
        return ToolResult::Success(json{{"result", "", "type", "unknown"}});
    });
    
    // Benchmark tools
    RegisterTool(BuiltInTools::RunBenchmark(), [](const json& args) {
        return ToolResult::Success(json{{"score", 0.0}, {"duration_ms", 0}});
    });
    
    RegisterTool(BuiltInTools::ProfileCode(), [](const json& args) {
        return ToolResult::Success(json{{"profile_data", json::object()}});
    });
    
    RegisterTool(BuiltInTools::MeasureMemory(), [](const json& args) {
        return ToolResult::Success(json{{"used_bytes", 0}, {"peak_bytes", 0}});
    });
    
    // System tools
    RegisterTool(BuiltInTools::ExecuteCommand(), [](const json& args) {
        return ToolResult::Success(json{{"exit_code", 0}, {"stdout", ""}, {"stderr", ""}});
    });
    
    RegisterTool(BuiltInTools::GetSystemInfo(), [](const json& args) {
        return ToolResult::Success(json{{"platform", "unknown"}, {"version", ""}});
    });
    
    RegisterTool(BuiltInTools::CheckEnvironment(), [](const json& args) {
        return ToolResult::Success(json{{"variables", json::object()}});
    });
}

// Built-in tool definitions
namespace BuiltInTools {

ToolDefinition FileRead() {
    ToolDefinition def;
    def.name = "file_read";
    def.description = "Read the contents of a file";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"path", {{"type", "string"}, {"description", "Path to the file"}}},
            {"offset", {{"type", "integer"}, {"description", "Byte offset to start reading"}, {"default", 0}}},
            {"limit", {{"type", "integer"}, {"description", "Maximum bytes to read"}, {"default", 10000}}}
        }},
        {"required", json::array({"path"})}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition FileWrite() {
    ToolDefinition def;
    def.name = "file_write";
    def.description = "Write content to a file";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"path", {{"type", "string"}, {"description", "Path to the file"}}},
            {"content", {{"type", "string"}, {"description", "Content to write"}}},
            {"append", {{"type", "boolean"}, {"description", "Append to file"}, {"default", false}}}
        }},
        {"required", json::array({"path", "content"})}
    };
    def.default_permission = ToolPermission::WRITE_SAFE;
    def.requires_confirmation = true;
    return def;
}

ToolDefinition FileList() {
    ToolDefinition def;
    def.name = "file_list";
    def.description = "List files matching a pattern";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"pattern", {{"type", "string"}, {"description", "Glob pattern"}, {"default", "*"}}},
            {"directory", {{"type", "string"}, {"description", "Directory to search"}, {"default", "."}}}
        }}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition DirectoryList() {
    ToolDefinition def;
    def.name = "directory_list";
    def.description = "List directories";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"path", {{"type", "string"}, {"description", "Directory path"}, {"default", "."}}},
            {"recursive", {{"type", "boolean"}, {"description", "List recursively"}, {"default", false}}}
        }}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition CompileCode() {
    ToolDefinition def;
    def.name = "compile_code";
    def.description = "Compile source code";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"source_files", {{"type", "array", "items", {{"type", "string"}}}, {"description", "Source files"}}},
            {"output", {{"type", "string"}, {"description", "Output executable"}}},
            {"flags", {{"type", "array", "items", {{"type", "string"}}}, {"description", "Compiler flags"}}}
        }},
        {"required", json::array({"source_files"})}
    };
    def.default_permission = ToolPermission::EXECUTE;
    def.requires_confirmation = true;
    return def;
}

ToolDefinition RunExecutable() {
    ToolDefinition def;
    def.name = "run_executable";
    def.description = "Run an executable";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"path", {{"type", "string"}, {"description", "Path to executable"}}},
            {"args", {{"type", "array", "items", {{"type", "string"}}}, {"description", "Arguments"}}},
            {"timeout", {{"type", "integer"}, {"description", "Timeout seconds"}, {"default", 30}}}
        }},
        {"required", json::array({"path"})}
    };
    def.default_permission = ToolPermission::EXECUTE;
    def.requires_confirmation = true;
    return def;
}

ToolDefinition CheckSyntax() {
    ToolDefinition def;
    def.name = "check_syntax";
    def.description = "Check code syntax";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"code", {{"type", "string"}, {"description", "Code to check"}}},
            {"language", {{"type", "string"}, {"description", "Programming language"}}}
        }},
        {"required", json::array({"code", "language"})}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition SetBreakpoint() {
    ToolDefinition def;
    def.name = "set_breakpoint";
    def.description = "Set a debugger breakpoint";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"file", {{"type", "string"}, {"description", "Source file"}}},
            {"line", {{"type", "integer"}, {"description", "Line number"}}},
            {"condition", {{"type", "string"}, {"description", "Breakpoint condition"}}}
        }},
        {"required", json::array({"file", "line"})}
    };
    def.default_permission = ToolPermission::WRITE_SAFE;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition GetStackTrace() {
    ToolDefinition def;
    def.name = "get_stack_trace";
    def.description = "Get current stack trace";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"thread_id", {{"type", "integer"}, {"description", "Thread ID"}, {"default", 0}}},
            {"max_frames", {{"type", "integer"}, {"description", "Max frames"}, {"default", 100}}}
        }}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition EvaluateExpression() {
    ToolDefinition def;
    def.name = "evaluate_expression";
    def.description = "Evaluate expression in debugger";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"expression", {{"type", "string"}, {"description", "Expression to evaluate"}}},
            {"frame", {{"type", "integer"}, {"description", "Stack frame"}, {"default", 0}}}
        }},
        {"required", json::array({"expression"})}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition RunBenchmark() {
    ToolDefinition def;
    def.name = "run_benchmark";
    def.description = "Run performance benchmark";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}, {"description", "Benchmark name"}}},
            {"iterations", {{"type", "integer"}, {"description", "Iterations"}, {"default", 100}}},
            {"warmup", {{"type", "integer"}, {"description", "Warmup iterations"}, {"default", 10}}}
        }},
        {"required", json::array({"name"})}
    };
    def.default_permission = ToolPermission::EXECUTE;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition ProfileCode() {
    ToolDefinition def;
    def.name = "profile_code";
    def.description = "Profile code execution";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"target", {{"type", "string"}, {"description", "Code to profile"}}},
            {"duration", {{"type", "integer"}, {"description", "Profile duration seconds"}, {"default", 30}}}
        }},
        {"required", json::array({"target"})}
    };
    def.default_permission = ToolPermission::EXECUTE;
    def.requires_confirmation = true;
    return def;
}

ToolDefinition MeasureMemory() {
    ToolDefinition def;
    def.name = "measure_memory";
    def.description = "Measure memory usage";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"process_id", {{"type", "integer"}, {"description", "Process ID"}, {"default", 0}}}
        }}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition ExecuteCommand() {
    ToolDefinition def;
    def.name = "execute_command";
    def.description = "Execute system command";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"command", {{"type", "string"}, {"description", "Command to execute"}}},
            {"working_dir", {{"type", "string"}, {"description", "Working directory"}, {"default", "."}}},
            {"timeout", {{"type", "integer"}, {"description", "Timeout seconds"}, {"default", 60}}}
        }},
        {"required", json::array({"command"})}
    };
    def.default_permission = ToolPermission::EXECUTE;
    def.requires_confirmation = true;
    return def;
}

ToolDefinition GetSystemInfo() {
    ToolDefinition def;
    def.name = "get_system_info";
    def.description = "Get system information";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"component", {{"type", "string"}, {"description", "Component (cpu, memory, gpu, all)"}, {"default", "all"}}}
        }}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

ToolDefinition CheckEnvironment() {
    ToolDefinition def;
    def.name = "check_environment";
    def.description = "Check environment variables";
    def.parameters_schema = {
        {"type", "object"},
        {"properties", {
            {"variables", {{"type", "array", "items", {{"type", "string"}}}, {"description", "Variables to check"}}}
        }}
    };
    def.default_permission = ToolPermission::READ_ONLY;
    def.requires_confirmation = false;
    return def;
}

} // namespace BuiltInTools

} // namespace FunctionCalling
} // namespace RawrXD
