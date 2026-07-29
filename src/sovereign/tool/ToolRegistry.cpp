// ToolRegistry.cpp
// Tool System with MCP-compatible abstraction

#include "ToolRegistry.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>

namespace Sovereign {

namespace fs = std::filesystem;

void ToolRegistry::Register(std::shared_ptr<ITool> tool) {
    if (!tool) return;

    std::lock_guard<std::mutex> guard(registryMutex);
    tools[tool->Name()] = tool;
}

ToolResult ToolRegistry::Invoke(const std::string& name, const ToolContext& ctx) {
    std::shared_ptr<ITool> tool;
    {
        std::lock_guard<std::mutex> guard(registryMutex);
        auto it = tools.find(name);
        if (it == tools.end()) {
            return {false, "", "TOOL_NOT_FOUND: " + name, {}};
        }
        tool = it->second;
    }

    // Check permission
    if (static_cast<int>(ctx.permission) < static_cast<int>(tool->RequiredPermission())) {
        return {false, "", "PERMISSION_DENIED: " + name, {}};
    }

    // Execute
    return tool->Execute(ctx);
}

bool ToolRegistry::HasTool(const std::string& name) {
    std::lock_guard<std::mutex> guard(registryMutex);
    return tools.find(name) != tools.end();
}

std::shared_ptr<ITool> ToolRegistry::GetTool(const std::string& name) {
    std::lock_guard<std::mutex> guard(registryMutex);
    auto it = tools.find(name);
    if (it != tools.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> ToolRegistry::GetToolNames() {
    std::lock_guard<std::mutex> guard(registryMutex);
    std::vector<std::string> names;
    names.reserve(tools.size());
    for (const auto& [name, tool] : tools) {
        names.push_back(name);
    }
    return names;
}

std::vector<std::string> ToolRegistry::GetToolsByPermission(Permission perm) {
    std::lock_guard<std::mutex> guard(registryMutex);
    std::vector<std::string> names;
    for (const auto& [name, tool] : tools) {
        if (tool->RequiredPermission() == perm) {
            names.push_back(name);
        }
    }
    return names;
}

bool ToolRegistry::Unregister(const std::string& name) {
    std::lock_guard<std::mutex> guard(registryMutex);
    return tools.erase(name) > 0;
}

void ToolRegistry::Clear() {
    std::lock_guard<std::mutex> guard(registryMutex);
    tools.clear();
}

void ToolRegistry::RegisterCoreTools() {
    Register(std::make_shared<ReadFileTool>());
    Register(std::make_shared<WriteFileTool>());
    Register(std::make_shared<TerminalTool>());
    Register(std::make_shared<SearchCodeTool>());
    Register(std::make_shared<PatchTool>());
}

// ============================================================
// Built-in Tool Implementations
// ============================================================

ToolResult ReadFileTool::Execute(const ToolContext& ctx) {
    std::ifstream file(ctx.input);
    if (!file) {
        return {false, "", "FILE_NOT_FOUND: " + ctx.input, {}};
    }
    
    std::stringstream ss;
    ss << file.rdbuf();
    
    return {true, ss.str(), "", {ctx.input}};
}

std::string ReadFileTool::Schema() const {
    return R"({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path to read"}
        },
        "required": ["path"]
    })";
}

ToolResult WriteFileTool::Execute(const ToolContext& ctx) {
    // Parse input for path and content
    // Format: "path\n---\ncontent"
    size_t sep = ctx.input.find("\n---\n");
    if (sep == std::string::npos) {
        return {false, "", "INVALID_FORMAT: expected 'path\\n---\\ncontent'", {}};
    }
    
    std::string path = ctx.input.substr(0, sep);
    std::string content = ctx.input.substr(sep + 5);
    
    std::ofstream file(path);
    if (!file) {
        return {false, "", "WRITE_FAILED: " + path, {}};
    }
    
    file << content;
    
    return {true, "File written successfully", "", {path}};
}

std::string WriteFileTool::Schema() const {
    return R"({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path to write"},
            "content": {"type": "string", "description": "Content to write"}
        },
        "required": ["path", "content"]
    })";
}

ToolResult TerminalTool::Execute(const ToolContext& ctx) {
    // Execute command via system()
    // In production, use CreateProcessW for better control
    int result = std::system(ctx.input.c_str());
    
    if (result != 0) {
        return {false, "", "COMMAND_FAILED: exit code " + std::to_string(result), {}};
    }
    
    return {true, "Command executed", "", {}};
}

std::string TerminalTool::Schema() const {
    return R"({
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Command to execute"}
        },
        "required": ["command"]
    })";
}

ToolResult SearchCodeTool::Execute(const ToolContext& ctx) {
    // Simple recursive search
    std::string pattern = ctx.input;
    std::string results;
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(ctx.workingDirectory)) {
            if (entry.is_regular_file()) {
                std::string path = entry.path().string();
                if (path.find(pattern) != std::string::npos) {
                    results += path + "\n";
                }
            }
        }
    } catch (...) {
        return {false, "", "SEARCH_FAILED", {}};
    }
    
    return {true, results, "", {}};
}

std::string SearchCodeTool::Schema() const {
    return R"({
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "Search pattern"},
            "path": {"type": "string", "description": "Directory to search"}
        },
        "required": ["pattern"]
    })";
}

ToolResult PatchTool::Execute(const ToolContext& ctx) {
    // Parse patch specification
    // Format: "path\n---\nold\n+++\nnew"
    size_t sep1 = ctx.input.find("\n---\n");
    if (sep1 == std::string::npos) {
        return {false, "", "INVALID_FORMAT", {}};
    }
    
    std::string path = ctx.input.substr(0, sep1);
    std::string rest = ctx.input.substr(sep1 + 5);
    
    size_t sep2 = rest.find("\n+++\n");
    if (sep2 == std::string::npos) {
        return {false, "", "INVALID_FORMAT: expected 'old\\n+++\\nnew'", {}};
    }
    
    std::string oldContent = rest.substr(0, sep2);
    std::string newContent = rest.substr(sep2 + 6);
    
    // Read current file
    std::ifstream inFile(path);
    if (!inFile) {
        return {false, "", "FILE_NOT_FOUND: " + path, {}};
    }
    
    std::stringstream ss;
    ss << inFile.rdbuf();
    std::string currentContent = ss.str();
    
    // Find and replace
    size_t pos = currentContent.find(oldContent);
    if (pos == std::string::npos) {
        return {false, "", "PATCH_NOT_APPLICABLE: old content not found", {}};
    }
    
    currentContent.replace(pos, oldContent.length(), newContent);
    
    // Write back
    std::ofstream outFile(path);
    if (!outFile) {
        return {false, "", "WRITE_FAILED: " + path, {}};
    }
    
    outFile << currentContent;
    
    return {true, "Patch applied successfully", "", {path}};
}

std::string PatchTool::Schema() const {
    return R"({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File to patch"},
            "old": {"type": "string", "description": "Content to replace"},
            "new": {"type": "string", "description": "Replacement content"}
        },
        "required": ["path", "old", "new"]
    })";
}

} // namespace Sovereign
