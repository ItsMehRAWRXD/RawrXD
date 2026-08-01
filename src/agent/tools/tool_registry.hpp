#pragma once

#include "tool.hpp"
#include <unordered_map>
#include <memory>
#include <vector>

namespace rawrxd {
namespace agent {

class ToolRegistry {
public:
    ToolRegistry();
    ~ToolRegistry();

    void registerTool(std::shared_ptr<AgentTool> tool);
    void removeTool(const std::string& name);
    std::shared_ptr<AgentTool> findTool(const std::string& name);
    ToolResult execute(const ToolRequest& request);
    std::vector<std::string> listTools() const;

private:
    std::unordered_map<std::string, std::shared_ptr<AgentTool>> tools_;
};

} // namespace agent
} // namespace rawrxd
