#include "AgentToolAuthority.hpp"
#include "CliSpecialToolProviders.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

using namespace RawrXD::Agentic;

static ToolResult passResult(std::string text = "ok") {
    ToolResult r;
    r.stdout_text = std::move(text);
    return r;
}

int main() {
    int failed = 0;
    auto check = [&](bool condition, const char* name) {
        std::cout << "TEST=" << name << " " << (condition ? "PASS" : "FAIL") << "\n";
        if (!condition) ++failed;
    };

    AgentToolRegistry authority;
    BindAgentToolAuthority(authority);

    check(&AgentToolAuthority() == &authority, "SAME_BOUND_REGISTRY");

    bool duplicateAuthorityRejected = false;
    try {
        AgentToolRegistry second;
        BindAgentToolAuthority(second);
    } catch (const std::logic_error&) {
        duplicateAuthorityRejected = true;
    }
    check(duplicateAuthorityRejected, "DUPLICATE_AUTHORITY_REJECTED");

    authority.registerTool(
        {"read-file", {"read_file"}, "read"},
        [](const ToolRequest&, ToolContext&) { return passResult("data"); });

    authority.registerTool(
        {"list-dir", {"list_dir"}, "list"},
        [](const ToolRequest&, ToolContext&) { return passResult("entry"); });

    authority.registerTool(
        {"write-file", {"write_file"}, "write"},
        [](const ToolRequest&, ToolContext&) { return passResult("OK"); });

    authority.registerTool(
        {"run-shell", {"run_shell"}, "shell"},
        [](const ToolRequest&, ToolContext&) { return passResult("shell"); });

    authority.registerTool(
        {"build-project", {"BuildProject"}, "build"},
        [](const ToolRequest&, ToolContext&) {
            ToolResult r;
            r.exit_code = 2;
            r.stderr_text = "intentional build failure";
            return r;
        });

    authority.registerTool(
        {"static-analysis", {"StaticAnalysis"}, "analysis"},
        [](const ToolRequest&, ToolContext&) { return passResult("analysis"); });

    authority.registerTool(
        {"git-status", {"GitStatus"}, "git"},
        [](const ToolRequest&, ToolContext&) { return passResult("clean"); });

    RegisterCliSpecialToolProviders(
        authority,
        {
            [](const ToolRequest&, ToolContext&) { return passResult("ssa"); },
            [](const ToolRequest&, ToolContext&) { return passResult("byte"); },
            [](const ToolRequest&, ToolContext&) { return passResult("memory"); }
        });

    auto invoke = [&](const char* name, AgentToolSurface surface) {
        ToolRequest req;
        req.tool_id = name;
        req.surface = surface;
        ToolContext ctx;
        return authority.invoke(std::move(req), std::move(ctx));
    };

    check(invoke("read_file", AgentToolSurface::Headless).ok(), "READ_FILE");
    check(invoke("list_dir", AgentToolSurface::Headless).ok(), "LIST_DIRECTORY");
    check(invoke("write_file", AgentToolSurface::Headless).ok(), "WRITE_TEMP");
    check(invoke("run_shell", AgentToolSurface::Headless).ok(), "SHELL");
    check(invoke("static_analysis", AgentToolSurface::AgentCore).ok(), "STATIC_ANALYSIS");
    check(invoke("git_status", AgentToolSurface::AgentCore).ok(), "GIT_STATUS");
    check(invoke("ssa_lift", AgentToolSurface::CLI).ok(), "SSA_DISPATCH");
    check(invoke("byte_patch", AgentToolSurface::CLI).ok(), "BYTE_PATCH_DISPATCH");
    check(invoke("memory_patch", AgentToolSurface::CLI).ok(), "MEMORY_PATCH_DISPATCH");

    const ToolResult build = invoke("build_project", AgentToolSurface::AgentCore);
    check(!build.ok() && build.exit_code != 0 && !build.stderr_text.empty(),
          "BUILD_FAILURE_CAPTURE");

    const ToolResult miss = invoke("definitely_missing", AgentToolSurface::Headless);
    check(miss.exit_code == 127, "UNKNOWN_TOOL_REJECTED");

    const auto m = authority.authoritySnapshot();
    check(m.dispatch_count == 11, "DISPATCH_COUNT");
    check(m.headless_dispatch_count == 5, "HEADLESS_METRIC");
    check(m.cli_dispatch_count == 3, "CLI_METRIC");
    check(m.agent_core_dispatch_count == 3, "AGENT_CORE_METRIC");
    check(m.failed_dispatch_count == 2, "FAILED_DISPATCH_METRIC");
    check(m.rejected_tool_count == 1, "REJECTED_TOOL_METRIC");

    std::cout << "AUTHORITY=AgentToolRegistry\n";
    std::cout << "DUPLICATE_DISPATCH_AUTHORITY=0\n";
    std::cout << "FRAMEWORK_SELFTEST=" << (failed == 0 ? "PASS" : "FAIL") << "\n";
    std::cout << "FAILED=" << failed << "\n";
    return failed == 0 ? 0 : 1;
}
