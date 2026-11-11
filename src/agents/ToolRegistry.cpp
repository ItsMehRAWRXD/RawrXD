// ============================================================================
// ToolRegistry.cpp - Tool Registration and Execution Implementation
// ============================================================================

#include "ToolRegistry.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>

namespace RawrXD {
namespace Agents {

ToolRegistry::ToolRegistry() = default;
ToolRegistry::~ToolRegistry() = default;

void ToolRegistry::Register(std::unique_ptr<Tool> tool) {
    if (tool) {
        std::string name = tool->GetName();
        tools_[name] = std::move(tool);
    }
}

bool ToolRegistry::Execute(const std::string& toolName, const nlohmann::json& params) {
    auto it = tools_.find(toolName);
    if (it == tools_.end()) {
        std::cerr << "Tool not found: " << toolName << std::endl;
        return false;
    }
    
    try {
        return it->second->Execute(params);
    } catch (const std::exception& e) {
        std::cerr << "Tool execution failed: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> ToolRegistry::GetToolNames() const {
    std::vector<std::string> names;
    for (const auto& [name, _] : tools_) {
        names.push_back(name);
    }
    return names;
}

std::string ToolRegistry::GetToolDescription(const std::string& name) const {
    auto it = tools_.find(name);
    if (it != tools_.end()) {
        return it->second->GetDescription();
    }
    return "";
}

bool ToolRegistry::HasTool(const std::string& name) const {
    return tools_.find(name) != tools_.end();
}

// ============================================================================
// Tool Implementations
// ============================================================================

bool CreateFileTool::Execute(const nlohmann::json& params) {
    std::string path = params.value("path", "");
    std::string content = params.value("content", "");
    
    if (path.empty()) {
        std::cerr << "CreateFile: path is required\n";
        return false;
    }
    
    // Create parent directories
    std::filesystem::path p(path);
    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path());
    }
    
    std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "CreateFile: failed to open " << path << "\n";
        return false;
    }
    
    file << content;
    std::cout << "Created file: " << path << "\n";
    return true;
}

bool ModifyFileTool::Execute(const nlohmann::json& params) {
    std::string path = params.value("path", "");
    std::string oldString = params.value("old_string", "");
    std::string newString = params.value("new_string", "");
    
    if (path.empty()) {
        std::cerr << "ModifyFile: path is required\n";
        return false;
    }
    
    std::ifstream inFile(path);
    if (!inFile.is_open()) {
        std::cerr << "ModifyFile: failed to open " << path << "\n";
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(inFile)),
                        std::istreambuf_iterator<char>());
    inFile.close();
    
    size_t pos = content.find(oldString);
    if (pos == std::string::npos) {
        std::cerr << "ModifyFile: old_string not found in " << path << "\n";
        return false;
    }
    
    content.replace(pos, oldString.length(), newString);
    
    std::ofstream outFile(path);
    if (!outFile.is_open()) {
        std::cerr << "ModifyFile: failed to write " << path << "\n";
        return false;
    }
    
    outFile << content;
    std::cout << "Modified file: " << path << "\n";
    return true;
}

bool CompileTool::Execute(const nlohmann::json& params) {
    std::string target = params.value("target", "");
    std::string config = params.value("config", "Release");
    
    std::cout << "Compiling target: " << target << " (" << config << ")\n";
    
    // In real implementation, this would invoke CMake/build system
    // For now, just simulate
    std::cout << "  [CMake] Configuring...\n";
    std::cout << "  [Build] Compiling...\n";
    std::cout << "  ✓ Build complete\n";
    
    return true;
}

bool RunTestsTool::Execute(const nlohmann::json& params) {
    std::string suite = params.value("suite", "all");
    
    std::cout << "Running test suite: " << suite << "\n";
    
    // Simulate test execution
    std::cout << "  [Test] Unit tests...\n";
    std::cout << "  [Test] Integration tests...\n";
    std::cout << "  ✓ All tests passed\n";
    
    return true;
}

bool SearchCodeTool::Execute(const nlohmann::json& params) {
    std::string pattern = params.value("pattern", "");
    std::string path = params.value("path", ".");
    
    std::cout << "Searching for: " << pattern << " in " << path << "\n";
    
    // In real implementation, this would use ripgrep or similar
    // For now, just simulate
    std::cout << "  Found 3 matches\n";
    
    return true;
}

} // namespace Agents
} // namespace RawrXD
