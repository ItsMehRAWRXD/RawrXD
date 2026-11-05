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
    // Additional boundary and accounting checks.
    assert(!registry.contains("unknown"));
    assert(!registry.describe("unknown").has_value());
    assert(registry.list().size() == 1);
    assert(registry.contains("replacement"));
    assert(registry.describe("replacement")->id == "replacement");
    assert(registry.invoke(ToolRequest{.tool_id="replacement"}, {}).ok());
    assert(registry.authoritySnapshot().dispatch_count == 4);
    assert(registry.authoritySnapshot().failed_dispatch_count == 2);
    assert(registry.authoritySnapshot().rejected_tool_count == 1);
    rejected = false;
    try { registry.registerTool({"replacement", {}, "duplicate ID"}, ok); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    rejected = false;
    try { registry.registerTool({"", {}, "empty ID"}, ok); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    rejected = false;
    try { registry.registerTool({"invalid", {}, "empty handler"}, {}); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    assert(!registry.unregisterTool("unknown"));
    assert(registry.unregisterTool("replacement"));
    assert(registry.list().empty());
    registry.resetAuthorityMetrics();
    assert(registry.authoritySnapshot().dispatch_count == 0);
    assert(registry.authoritySnapshot().failed_dispatch_count == 0);
    // Fifteen independent cases for registry authorization boundaries.
    {
        AgentToolRegistry g;
        int called = 0;
        const auto pass = [&](const ToolRequest& req, ToolContext&) {
            ++called;
            assert(req.tool_id == "alpha-beta");
            return ToolResult{};
        };
        g.registerTool({"Alpha.Beta", {"alpha_beta_alias"}, "test"}, pass);
        assert(g.contains("alpha-beta"));                           // R01
        assert(g.contains("ALPHA.BETA"));                           // R02
        assert(g.contains("alpha_beta_alias"));                     // R03
        assert(g.describe("alpha.beta")->id == "alpha-beta");       // R04
        assert(g.invoke(ToolRequest{.tool_id="alpha.beta"}, {}).ok()); // R05
        assert(called == 1);                                       // R06
        bool duplicate = false;
        try { g.registerTool({"alpha_beta", {}, "duplicate"}, pass); }
        catch (const std::invalid_argument&) { duplicate = true; }
        assert(duplicate);                                         // R07
        duplicate = false;
        try { g.registerTool({"different", {"alpha_beta_alias"}, "duplicate"}, pass); }
        catch (const std::invalid_argument&) { duplicate = true; }
        assert(duplicate);                                         // R08
        assert(g.list().size() == 1);                              // R09
        assert(g.invoke(ToolRequest{.tool_id="absent"}, {}).exit_code == 127); // R10
        ToolContext stop;
        stop.cancelled = [] { return true; };
        assert(g.invoke(ToolRequest{.tool_id="alpha.beta"}, stop).exit_code == 130); // R11
        assert(called == 1);                                       // R12
        assert(g.authoritySnapshot().failed_dispatch_count == 2); // R13
        assert(g.unregisterTool("alpha_beta_alias"));              // R14
        assert(!g.contains("alpha.beta") && g.list().empty());      // R15
    }
    return 0;
}
