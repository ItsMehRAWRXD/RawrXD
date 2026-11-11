#include "tool_registry.hpp"
#include <iostream>

namespace rawrxd {
namespace agent {

ToolRegistry::ToolRegistry() = default;
ToolRegistry::~ToolRegistry() = default;

void ToolRegistry::registerTool(std::shared_ptr<AgentTool> tool) {
    if (tool) {
        tools_[tool->name()] = tool;
        std::cout << "[ToolRegistry] Registered tool: " << tool->name() << std::endl;
    }
}

void ToolRegistry::removeTool(const std::string& name) {
    tools_.erase(name);
}

std::shared_ptr<AgentTool> ToolRegistry::findTool(const std::string& name) {
    auto it = tools_.find(name);
    if (it != tools_.end()) {
        return it->second;
    }
    return nullptr;
}

ToolResult ToolRegistry::execute(const ToolRequest& request) {
    auto tool = findTool(request.tool_name);
    if (!tool) {
        ToolResult result;
        result.success = false;
        result.error = "Tool not found: " + request.tool_name;
        return result;
    }
    if (!tool->available()) {
        ToolResult result;
        result.success = false;
        result.error = "Tool not available: " + request.tool_name;
        return result;
    }
    return tool->execute(request);
}

std::vector<std::string> ToolRegistry::listTools() const {
    std::vector<std::string> names;
    names.reserve(tools_.size());
    for (const auto& pair : tools_) {
        names.push_back(pair.first);
    }
    return names;
}

} // namespace agent
} // namespace rawrxd
