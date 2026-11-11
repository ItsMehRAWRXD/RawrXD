#pragma once

#include "tool.hpp"
#include <string>

namespace rawrxd {
namespace agent {

class FilesystemTool : public AgentTool {
public:
    std::string name() const override { return "filesystem"; }
    ToolResult execute(const ToolRequest& request) override;
    bool available() const override { return true; }

private:
    ToolResult handleRead(const std::string& path);
    ToolResult handleWrite(const std::string& path, const std::string& content);
    ToolResult handleDelete(const std::string& path);
    ToolResult handleList(const std::string& path);
    ToolResult handleSearch(const std::string& pattern, const std::string& root);
};

} // namespace agent
} // namespace rawrxd
