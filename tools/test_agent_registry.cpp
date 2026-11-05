// Portable registry tests; compile with C++20 on Linux/Windows.
// g++ -std=c++20 -pthread -I~dev/rawrxd/src tools/test_agent_registry.cpp -o /tmp/agent_registry_test
#include "deep2/AgentToolRegistry.hpp"
#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>
using namespace RawrXD::Agentic;
int main() {
    AgentToolRegistry registry;
    const auto ok = [](const ToolRequest&, ToolContext&) {
        ToolResult r; r.stdout_text = "OK"; return r;
    };
    registry.registerTool({"workspace.list", {"workspace_ls", "list.workspace"}, "listing"}, ok);
    assert(registry.contains("workspace.list"));
    assert(registry.contains("workspace_ls"));
    assert(registry.describe("list.workspace").has_value());
    assert(registry.invoke(ToolRequest{.surface=AgentToolSurface::CLI,
                                      .tool_id="workspace_ls"}, {}).ok());
    assert(registry.authoritySnapshot().cli_dispatch_count == 1);
    assert(registry.list().size() == 1);
    bool rejected = false;
    try {
        registry.registerTool({"duplicate", {"same.alias", "same_alias"}, "bad"}, ok);
    } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    assert(!registry.contains("duplicate"));
    rejected = false;
    try {
        registry.registerTool({"other", {"workspace_ls"}, "bad"}, ok);
    } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    assert(registry.invoke(ToolRequest{.tool_id="not.registered"}, {}).exit_code == 127);
    ToolContext cancelled; cancelled.cancelled = [] { return true; };
    assert(registry.invoke(ToolRequest{.tool_id="workspace.list"}, cancelled).exit_code == 130);
    assert(registry.unregisterTool("workspace_ls"));
    assert(!registry.contains("workspace.list"));
    assert(!registry.contains("list.workspace"));
    registry.registerTool({"replacement", {"workspace_ls"}, "reuse"}, ok);
    assert(registry.contains("workspace_ls"));
    assert(registry.authoritySnapshot().rejected_tool_count == 1);
    return 0;
}
