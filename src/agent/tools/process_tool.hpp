#pragma once

#include "tool.hpp"
#include <string>

namespace rawrxd {
namespace agent {

class ProcessTool : public AgentTool {
public:
    std::string name() const override { return "process"; }
    ToolResult execute(const ToolRequest& request) override;
    bool available() const override { return true; }

private:
    ToolResult handleExecute(const std::string& command, uint64_t timeout_ms);
    ToolResult handleTerminate(const std::string& pid);
};

} // namespace agent
} // namespace rawrxd
