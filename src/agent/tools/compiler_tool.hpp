#pragma once

#include "tool.hpp"
#include <string>

namespace rawrxd {
namespace agent {

class CompilerTool : public AgentTool {
public:
    std::string name() const override { return "compiler"; }
    ToolResult execute(const ToolRequest& request) override;
    bool available() const override { return true; }

private:
    ToolResult handleBuild(const std::string& target);
    ToolResult handleTest(const std::string& target);
    ToolResult handleConfigure(const std::string& params);
};

} // namespace agent
} // namespace rawrxd
