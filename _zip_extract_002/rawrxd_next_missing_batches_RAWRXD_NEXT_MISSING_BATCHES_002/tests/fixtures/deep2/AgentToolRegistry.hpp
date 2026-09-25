#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace RawrXD::Agentic {
enum class AgentToolSurface : std::uint8_t { Unknown=0, CLI, GUI, Headless, AgentCore, LocalServer };
struct ToolRequest {
    std::uint64_t run_id{};
    std::uint64_t action_id{};
    AgentToolSurface surface{AgentToolSurface::Unknown};
    std::string tool_id;
    std::vector<std::string> args;
    std::string stdin_text;
    std::filesystem::path working_directory;
};
struct ToolResult {
    int exit_code{};
    std::string stdout_text;
    std::string stderr_text;
    bool ok() const noexcept { return exit_code == 0; }
};
struct ToolContext { std::function<bool()> cancelled; };
struct ToolDescriptor { std::string id; std::vector<std::string> aliases; std::string description; };
class AgentToolRegistry {
public:
    using Handler = std::function<ToolResult(const ToolRequest&, ToolContext&)>;
    void registerTool(ToolDescriptor descriptor, Handler handler) {
        if (!handler || descriptor.id.empty()) throw std::invalid_argument("bad tool");
        handlers_[descriptor.id] = std::move(handler);
        for (const auto& alias : descriptor.aliases) aliases_[alias] = descriptor.id;
    }
    ToolResult invoke(ToolRequest request, ToolContext context) const {
        auto id = request.tool_id;
        if (auto a = aliases_.find(id); a != aliases_.end()) id = a->second;
        auto it = handlers_.find(id);
        if (it == handlers_.end()) return ToolResult{127, {}, "unregistered tool"};
        request.tool_id = id;
        if (context.cancelled && context.cancelled()) return ToolResult{130, {}, "cancelled"};
        return it->second(request, context);
    }
private:
    std::unordered_map<std::string, Handler> handlers_;
    std::unordered_map<std::string, std::string> aliases_;
};
} // namespace RawrXD::Agentic
