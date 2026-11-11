// ============================================================================
// AgenticToolIntegration.cpp - Bridge between AgenticSupervisor and ToolExecutor
// ============================================================================
// Provides: Task-to-tool dispatch, result handling, undo management
// ============================================================================

#include "AgenticToolIntegration.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD {
namespace Agentic {

// Tool descriptions for LLM system prompts
const std::unordered_map<std::string, std::string> AgenticToolIntegration::toolDescriptions_ = {
    {"read_file", R"(
read_file: Read the contents of a file.
Parameters:
  - path (required): Absolute path to the file
  - offset (optional): Starting byte offset (default: 0)
  - limit (optional): Maximum bytes to read (default: all)
Usage: {"path": "/path/to/file.cpp", "offset": 0, "limit": 1000})"},

    {"write_file", R"(
write_file: Write or overwrite a file.
Parameters:
  - path (required): Absolute path to the file
  - content (required): Content to write
  - append (optional): Append to existing file (default: false)
  - backup (optional): Create backup before write (default: true)
Usage: {"path": "/path/to/file.cpp", "content": "int main() {}", "backup": true})"},

    {"list_dir", R"(
list_dir: List directory contents.
Parameters:
  - path (required): Absolute path to directory
  - pattern (optional): File pattern filter (e.g., "*.cpp")
  - limit (optional): Maximum entries (default: 100)
  - recursive (optional): Include subdirectories (default: false)
Usage: {"path": "/project/src", "pattern": "*.cpp", "limit": 50})"},

    {"search_code", R"(
search_code: Search for patterns in code files.
Parameters:
  - path (required): Directory to search
  - query (required): Search pattern (regex supported)
  - file_pattern (optional): File pattern (default: "*.cpp")
  - case_sensitive (optional): Case sensitive search (default: false)
  - limit (optional): Maximum matches (default: 100)
Usage: {"path": "/project/src", "query": "class.*Widget", "file_pattern": "*.h"})"},

    {"run_command", R"(
run_command: Execute a shell command.
Parameters:
  - command (required): Command to execute
  - working_dir (optional): Working directory
  - timeout (optional): Timeout in milliseconds (default: 30000)
Usage: {"command": "git status", "working_dir": "/project"})"}
};

// ============================================================================
// Construction/Destruction
// ============================================================================

AgenticToolIntegration::AgenticToolIntegration() = default;

AgenticToolIntegration::~AgenticToolIntegration() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool AgenticToolIntegration::Initialize(const std::vector<std::string>& allowedDirs) {
    if (initialized_) {
        return true;
    }

    toolExecutor_ = std::make_unique<Tools::ToolExecutor>();
    
    Tools::ToolConfig config;
    config.allowedDirectories = allowedDirs;
    config.enableCache = true;
    config.maxCacheSize = 1000;
    config.defaultTimeoutMs = 30000;
    
    toolExecutor_->Initialize(config);
    initialized_ = true;
    
    return true;
}

void AgenticToolIntegration::Shutdown() {
    if (toolExecutor_) {
        toolExecutor_.reset();
    }
    initialized_ = false;
}

// ============================================================================
// Tool Execution
// ============================================================================

AgenticToolResult AgenticToolIntegration::ExecuteTool(
    const std::string& toolName,
    const std::unordered_map<std::string, std::string>& params) {
    
    AgenticToolResult result;
    result.toolName = toolName;
    
    if (!initialized_ || !toolExecutor_) {
        result.success = false;
        result.error = "Tool integration not initialized";
        return result;
    }
    
    // Execute tool
    uint64_t execId = toolExecutor_->Execute(toolName, params);
    result.executionId = execId;
    
    // Get result
    Tools::ToolResult toolResult = toolExecutor_->GetResult(execId);
    
    result.success = toolResult.success;
    result.error = toolResult.error;
    result.canUndo = toolExecutor_->CanUndo(execId);
    
    // Build output string from result data
    if (toolResult.success) {
        std::ostringstream output;
        for (const auto& pair : toolResult.data) {
            if (pair.first != "backup") { // Skip internal fields
                output << pair.first << ": " << pair.second << "\n";
            }
        }
        result.output = output.str();
    }
    
    return result;
}

void AgenticToolIntegration::ExecuteToolAsync(
    const std::string& toolName,
    const std::unordered_map<std::string, std::string>& params,
    ToolCompletionCallback callback) {
    
    if (!initialized_ || !toolExecutor_) {
        if (callback) {
            AgenticToolResult result;
            result.toolName = toolName;
            result.success = false;
            result.error = "Tool integration not initialized";
            callback(result);
        }
        return;
    }
    
    // Execute async with callback
    toolExecutor_->ExecuteAsync(toolName, params, 
        [this, toolName, callback](uint64_t execId, const Tools::ToolResult& toolResult) {
            AgenticToolResult result;
            result.toolName = toolName;
            result.executionId = execId;
            result.success = toolResult.success;
            result.error = toolResult.error;
            result.canUndo = toolExecutor_->CanUndo(execId);
            
            if (toolResult.success) {
                std::ostringstream output;
                for (const auto& pair : toolResult.data) {
                    if (pair.first != "backup") {
                        output << pair.first << ": " << pair.second << "\n";
                    }
                }
                result.output = output.str();
            }
            
            if (callback) {
                callback(result);
            }
        });
}

// ============================================================================
// Undo Support
// ============================================================================

bool AgenticToolIntegration::CanUndo(uint64_t executionId) const {
    if (!initialized_ || !toolExecutor_) {
        return false;
    }
    return toolExecutor_->CanUndo(executionId);
}

bool AgenticToolIntegration::Undo(uint64_t executionId) {
    if (!initialized_ || !toolExecutor_) {
        return false;
    }
    return toolExecutor_->Undo(executionId);
}

// ============================================================================
// Reporting
// ============================================================================

std::string AgenticToolIntegration::GetExecutionReport(uint64_t executionId) const {
    if (!initialized_ || !toolExecutor_) {
        return "{}";
    }
    return toolExecutor_->GetExecutionReport(executionId);
}

// ============================================================================
// LLM Integration
// ============================================================================

bool AgenticToolIntegration::ParseToolCall(const std::string& llmResponse,
                                           std::string& toolName,
                                           std::unordered_map<std::string, std::string>& params) const {
    // Look for tool call pattern: <tool_name>{...params...}
    size_t toolStart = llmResponse.find('<');
    if (toolStart == std::string::npos) {
        return false;
    }
    
    size_t toolEnd = llmResponse.find('>', toolStart);
    if (toolEnd == std::string::npos) {
        return false;
    }
    
    toolName = llmResponse.substr(toolStart + 1, toolEnd - toolStart - 1);
    
    // Check if it's a valid tool
    if (toolDescriptions_.find(toolName) == toolDescriptions_.end()) {
        return false;
    }
    
    // Find JSON params
    size_t jsonStart = llmResponse.find('{', toolEnd);
    if (jsonStart == std::string::npos) {
        return false;
    }
    
    size_t jsonEnd = llmResponse.find('}', jsonStart);
    if (jsonEnd == std::string::npos) {
        return false;
    }
    
    std::string jsonStr = llmResponse.substr(jsonStart, jsonEnd - jsonStart + 1);
    
    // Simple JSON parsing (key-value pairs)
    size_t pos = 0;
    while (pos < jsonStr.size()) {
        // Find key
        size_t keyStart = jsonStr.find('"', pos);
        if (keyStart == std::string::npos) break;
        size_t keyEnd = jsonStr.find('"', keyStart + 1);
        if (keyEnd == std::string::npos) break;
        
        std::string key = jsonStr.substr(keyStart + 1, keyEnd - keyStart - 1);
        
        // Find value
        size_t valStart = jsonStr.find(':', keyEnd) + 1;
        while (valStart < jsonStr.size() && 
               (jsonStr[valStart] == ' ' || jsonStr[valStart] == '\t')) valStart++;
        
        std::string value;
        if (jsonStr[valStart] == '"') {
            size_t valEnd = jsonStr.find('"', valStart + 1);
            value = jsonStr.substr(valStart + 1, valEnd - valStart - 1);
            pos = valEnd + 1;
        } else {
            size_t valEnd = jsonStr.find_first_of(",}", valStart);
            value = jsonStr.substr(valStart, valEnd - valStart);
            // Trim whitespace
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) 
                value.pop_back();
            pos = valEnd;
        }
        
        params[key] = value;
        
        if (pos < jsonStr.size() && jsonStr[pos] == ',') pos++;
    }
    
    return true;
}

std::string AgenticToolIntegration::BuildToolResultPrompt(const AgenticToolResult& result) const {
    std::ostringstream prompt;
    
    prompt << "\n<tool_result>\n";
    prompt << "Tool: " << result.toolName << "\n";
    prompt << "Success: " << (result.success ? "true" : "false") << "\n";
    
    if (!result.success) {
        prompt << "Error: " << result.error << "\n";
    } else {
        prompt << "Output:\n" << result.output << "\n";
        if (result.canUndo) {
            prompt << "Note: This operation can be undone.\n";
        }
    }
    
    prompt << "</tool_result>\n";
    
    return prompt.str();
}

std::string AgenticToolIntegration::GetToolsDescription() const {
    std::ostringstream desc;
    desc << "Available tools:\n\n";
    
    for (const auto& pair : toolDescriptions_) {
        desc << pair.second << "\n\n";
    }
    
    desc << "To use a tool, respond with: <tool_name>{\"param1\": \"value1\", ...}\n";
    desc << "The system will execute the tool and return the result.\n";
    
    return desc.str();
}

// ============================================================================
// Tool Registry
// ============================================================================

bool AgenticToolIntegration::HasTool(const std::string& toolName) const {
    return toolDescriptions_.find(toolName) != toolDescriptions_.end();
}

std::vector<std::string> AgenticToolIntegration::GetAvailableTools() const {
    std::vector<std::string> tools;
    tools.reserve(toolDescriptions_.size());
    for (const auto& pair : toolDescriptions_) {
        tools.push_back(pair.first);
    }
    return tools;
}

void AgenticToolIntegration::ClearCache() {
    if (toolExecutor_) {
        toolExecutor_->ClearCache();
    }
}

// ============================================================================
// C API Implementation
// ============================================================================

void* AgenticToolIntegration::Create() {
    return new AgenticToolIntegration();
}

void AgenticToolIntegration::Destroy(void* instance) {
    delete static_cast<AgenticToolIntegration*>(instance);
}

int AgenticToolIntegration::ExecuteToolC(void* instance, const char* toolName,
                                           const char* jsonParams, char* resultBuffer, int bufferSize) {
    auto* integration = static_cast<AgenticToolIntegration*>(instance);
    
    // Parse JSON params
    std::unordered_map<std::string, std::string> params;
    std::string jsonStr(jsonParams);
    
    // Simple JSON parsing
    size_t pos = 0;
    while (pos < jsonStr.size()) {
        size_t keyStart = jsonStr.find('"', pos);
        if (keyStart == std::string::npos) break;
        size_t keyEnd = jsonStr.find('"', keyStart + 1);
        if (keyEnd == std::string::npos) break;
        
        std::string key = jsonStr.substr(keyStart + 1, keyEnd - keyStart - 1);
        
        size_t valStart = jsonStr.find(':', keyEnd) + 1;
        while (valStart < jsonStr.size() && 
               (jsonStr[valStart] == ' ' || jsonStr[valStart] == '\t')) valStart++;
        
        std::string value;
        if (jsonStr[valStart] == '"') {
            size_t valEnd = jsonStr.find('"', valStart + 1);
            value = jsonStr.substr(valStart + 1, valEnd - valStart - 1);
            pos = valEnd + 1;
        } else {
            size_t valEnd = jsonStr.find_first_of(",}", valStart);
            value = jsonStr.substr(valStart, valEnd - valStart);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) 
                value.pop_back();
            pos = valEnd;
        }
        
        params[key] = value;
        if (pos < jsonStr.size() && jsonStr[pos] == ',') pos++;
    }
    
    // Execute tool
    AgenticToolResult result = integration->ExecuteTool(toolName, params);
    
    // Build result JSON
    std::string json = "{";
    json += "\"success\":" + std::string(result.success ? "true" : "false") + ",";
    json += "\"error\":\"" + EscapeJson(result.error) + "\",";
    json += "\"output\":\"" + EscapeJson(result.output) + "\",";
    json += "\"execution_id\":" + std::to_string(result.executionId) + ",";
    json += "\"can_undo\":" + std::string(result.canUndo ? "true" : "false");
    json += "}";
    
    int copySize = (json.size() < static_cast<size_t>(bufferSize - 1)) ? 
                   static_cast<int>(json.size()) : (bufferSize - 1);
    memcpy(resultBuffer, json.c_str(), copySize);
    resultBuffer[copySize] = '\0';
    
    return result.success ? 1 : 0;
}

int AgenticToolIntegration::CanUndoC(void* instance, uint64_t executionId) {
    auto* integration = static_cast<AgenticToolIntegration*>(instance);
    return integration->CanUndo(executionId) ? 1 : 0;
}

int AgenticToolIntegration::UndoC(void* instance, uint64_t executionId) {
    auto* integration = static_cast<AgenticToolIntegration*>(instance);
    return integration->Undo(executionId) ? 1 : 0;
}

std::string AgenticToolIntegration::EscapeJson(const std::string& str) {
    std::ostringstream escaped;
    for (char c : str) {
        switch (c) {
            case '"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    escaped << c;
                } else {
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                }
        }
    }
    return escaped.str();
}

// ============================================================================
// C API
// ============================================================================

extern "C" {

void* AgenticToolIntegration_Create() {
    return AgenticToolIntegration::Create();
}

void AgenticToolIntegration_Destroy(void* instance) {
    AgenticToolIntegration::Destroy(instance);
}

int AgenticToolIntegration_Initialize(void* instance, const char** allowedDirs, int dirCount) {
    auto* integration = static_cast<AgenticToolIntegration*>(instance);
    std::vector<std::string> dirs;
    for (int i = 0; i < dirCount; i++) {
        dirs.push_back(allowedDirs[i]);
    }
    return integration->Initialize(dirs) ? 1 : 0;
}

int AgenticToolIntegration_Execute(void* instance, const char* toolName,
                                   const char* jsonParams, char* resultBuffer, int bufferSize) {
    return AgenticToolIntegration::ExecuteToolC(instance, toolName, jsonParams, resultBuffer, bufferSize);
}

int AgenticToolIntegration_CanUndo(void* instance, uint64_t executionId) {
    return AgenticToolIntegration::CanUndoC(instance, executionId);
}

int AgenticToolIntegration_Undo(void* instance, uint64_t executionId) {
    return AgenticToolIntegration::UndoC(instance, executionId);
}

const char* AgenticToolIntegration_GetToolsDescription(void* instance) {
    auto* integration = static_cast<AgenticToolIntegration*>(instance);
    static std::string desc;
    desc = integration->GetToolsDescription();
    return desc.c_str();
}

} // extern "C"

} // namespace Agentic
} // namespace RawrXD
