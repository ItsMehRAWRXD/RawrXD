#pragma once

#include "tool.hpp"
#include <string>

namespace rawrxd {
namespace agent {

class SearchTool : public AgentTool {
public:
    std::string name() const override { return "search"; }
    ToolResult execute(const ToolRequest& request) override;
    bool available() const override { return true; }

private:
    ToolResult handleGrep(const std::string& pattern, const std::string& root);
    ToolResult handleSymbol(const std::string& name);
};

} // namespace agent
} // namespace rawrxd
