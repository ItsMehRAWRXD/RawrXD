// ============================================================================
// ToolRegistry.hpp - Tool Registration and Execution
// ============================================================================

#pragma once

#include "CEOAgent.hpp"
#include <memory>
#include <vector>
#include <map>
#include <functional>

namespace RawrXD {
namespace Agents {

// ============================================================================
// Tool Registry
// ============================================================================
class ToolRegistry {
public:
    ToolRegistry();
    ~ToolRegistry();
    
    // Register a tool
    void Register(std::unique_ptr<Tool> tool);
    
    // Execute a tool by name
    bool Execute(const std::string& toolName, const nlohmann::json& params);
    
    // Get tool info
    std::vector<std::string> GetToolNames() const;
    std::string GetToolDescription(const std::string& name) const;
    bool HasTool(const std::string& name) const;

private:
    std::map<std::string, std::unique_ptr<Tool>> tools_;
};

} // namespace Agents
} // namespace RawrXD
