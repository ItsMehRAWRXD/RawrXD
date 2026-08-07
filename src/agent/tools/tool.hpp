#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace rawrxd {
namespace agent {

struct ToolRequest {
    std::string tool_name;
    std::string action;
    std::string target;
    std::string parameters;
    uint64_t timeout_ms;

    ToolRequest() : timeout_ms(30000) {}
};

struct ToolResult {
    bool success;
    std::string output;
    std::string error;
    std::string mime_type;
    uint64_t duration_ms;

    ToolResult() : success(false), duration_ms(0) {}
};

class AgentTool {
public:
    virtual ~AgentTool() = default;
    virtual std::string name() const = 0;
    virtual ToolResult execute(const ToolRequest& request) = 0;
    virtual bool available() const = 0;
};

} // namespace agent
} // namespace rawrxd
