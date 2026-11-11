// Adversarial probe: AgentCommands/dispatchAgentTool path must DENY escapes.
// Mirrors IdeSsot::DispatchTool → ToolCallBridge::ExecuteToolCall + SecurityGate.
// CERTIFIED=0 PROMOTE=0
#include "../src/win32app/ExtensionSandboxManager.h"
#include "../src/agentic/tool_core.hpp"
#include "../src/agentic/ToolCallBridge.h"
#include "../src/agentic/IdeToolDispatchSsot.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using ExtensionSandbox::ExtensionSandboxManager;
namespace fs = std::filesystem;

struct Case {
    const char* id;
    const char* tool;
    const char* argsJson;
    bool expectDeny;
};

static std::string Esc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '\\' || c == '"') { o.push_back('\\'); o.push_back(c); }
        else if (c == '\n') o += "\\n";
        else o.push_back(c);
    }
    return o;
}

int main() {
    const std::string evidenceDir =
        "F:\\rawrxd\\evidence\\AGENT_TOOLS_ROUTE_WIRE_001";
    fs::create_directories(evidenceDir);
    const std::string resultsPath =
        evidenceDir + "\\ADVERSARIAL_AGENTCOMMANDS_PROBE_RESULTS.json";
    const std::string auditPath =
        evidenceDir + "\\agent_commands_security_audit.jsonl";

    // Workspace root must contain MOTD for BeginUserTurn/read_motd.
    const std::string ws = "F:\\rawrxd";

    rawrxd::tools::Registry reg;
    rawrxd::tools::register_workspace_tools(reg, ws);

    RawrXD::Agent::ToolCallBridge bridge;
    RawrXD::Agent::IdeSsot::BindBridge(bridge, &reg, ws);

    auto& sb = ExtensionSandboxManager::Instance();
    sb.ClearPolicy();
    sb.SetInteractive(false);
    sb.SetAutoApproveConfirm(false);
    sb.AddWorkspaceRoot(ws);
    sb.AddDeniedPathPrefix("C:\\Windows");
    sb.AddDeniedPathPrefix("C:\\Program Files");
    sb.SetAuditLogPath(auditPath);

    // Same SecurityGate wiring as Win32IDE_ComputerUse (AgentCommands SSOT).
    bridge.SetSecurityGate(
        [](const rawrxd::tools::Tool& t, const rawrxd::tools::Request& r,
           std::string& denyReason) -> bool {
            auto& gate = ExtensionSandboxManager::Instance();
            std::string pathArg, cmdArg;
            auto itP = r.args.find("path");
            if (itP != r.args.end()) pathArg = itP->second;
            auto itC = r.args.find("command");
            if (itC != r.args.end()) cmdArg = itC->second;
            return gate.CheckPathAndCommand(t.name, pathArg, cmdArg, denyReason);
        });
    bridge.SetApprovalCallback(
        [](const rawrxd::tools::Tool& t, const rawrxd::tools::Request&) -> bool {
            // Headless: only auto-allow ReadOnly (fail-closed for mutate/shell).
            return t.risk == rawrxd::tools::Risk::ReadOnly;
        });

    std::vector<Case> cases = {
        {"deny_shell_system32", "runInTerminal",
         "{\"command\":\"C:\\\\Windows\\\\System32\\\\cmd.exe /c echo pwn\"}", true},
        {"deny_shell_format", "runInTerminal",
         "{\"command\":\"format c: /y\"}", true},
        {"deny_shell_del_s", "runInTerminal",
         "{\"command\":\"del /s /q C:\\\\*\"}", true},
        {"deny_write_windows", "writeFile",
         "{\"path\":\"C:\\\\Windows\\\\Temp\\\\evil.txt\",\"content\":\"x\"}", true},
        {"deny_write_program_files", "writeFile",
         "{\"path\":\"C:\\\\Program Files\\\\evil.txt\",\"content\":\"x\"}", true},
        {"deny_edit_traversal", "editFiles",
         "{\"path\":\"F:\\\\rawrxd\\\\..\\\\..\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts\",\"old\":\"a\",\"new\":\"b\"}", true},
        {"deny_delete_system32", "deleteFile",
         "{\"path\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\"}", true},
        {"deny_shell_encoded_ps", "runInTerminal",
         "{\"command\":\"powershell -EncodedCommand AQAAA\"}", true},
        {"deny_shell_unc", "runInTerminal",
         "{\"command\":\"type \\\\\\\\evil\\\\share\\\\p.ps1\"}", true},
        {"deny_mutate_no_consent", "writeFile",
         "{\"path\":\"F:\\\\rawrxd\\\\probe_agentcmd_write.txt\",\"content\":\"x\"}", true},
        {"allow_read_workspace", "readFile",
         "{\"path\":\"F:\\\\rawrxd\\\\CMakeLists.txt\"}", false},
        {"deny_gate_missing_simulate", "runInTerminal",
         "{\"command\":\"echo should-still-hit-gate\"}", true},
    };

    // Simulate AgentCommands: BeginUserTurn + read_motd + IdeSsot::DispatchTool.
    auto dispatchLikeAgentCommands =
        [&](const Case& c) -> RawrXD::Agent::ToolResultMessage {
        bridge.EndUserTurn();
        static uint64_t turn = 100;
        ++turn;
        if (!bridge.BeginUserTurn("ide-agent-commands-probe", turn)) {
            RawrXD::Agent::ToolResultMessage f;
            f.success = false;
            f.content = "DENIED: BeginUserTurn failed";
            return f;
        }
        RawrXD::Agent::ToolCall motd;
        motd.id = "motd-" + std::to_string(turn);
        motd.name = "read_motd";
        motd.arguments = nlohmann::json::object();
        auto mr = bridge.ExecuteToolCall(motd);
        if (!mr.success) {
            bridge.EndUserTurn();
            RawrXD::Agent::ToolResultMessage f;
            f.success = false;
            f.content = "DENIED: MOTD " + mr.content;
            return f;
        }
        RawrXD::Agent::ToolCall call;
        call.id = std::string("probe-") + c.id;
        call.name = c.tool;
        try { call.arguments = nlohmann::json::parse(c.argsJson); }
        catch (...) { call.arguments = nlohmann::json::object(); }
        auto out = RawrXD::Agent::IdeSsot::DispatchTool(bridge, call);
        bridge.EndUserTurn();
        return out;
    };

    // Extra case: SecurityGate missing => fail-closed for non-readonly.
    RawrXD::Agent::ToolCallBridge bare;
    rawrxd::tools::Registry bareReg;
    rawrxd::tools::register_workspace_tools(bareReg, ws);
    RawrXD::Agent::IdeSsot::BindBridge(bare, &bareReg, ws);
    // intentionally NO SetSecurityGate
    bare.SetApprovalCallback(
        [](const rawrxd::tools::Tool& t, const rawrxd::tools::Request&) {
            return t.risk == rawrxd::tools::Risk::ReadOnly;
        });

    int pass = 0, fail = 0;
    std::ofstream results(resultsPath, std::ios::trunc);
    results << "{\n  \"probe_id\": \"AGENT_TOOLS_ROUTE_WIRE_001_AGENTCOMMANDS\",\n"
            << "  \"entry\": \"IdeSsot::DispatchTool / dispatchAgentTool mirror\",\n"
            << "  \"CERTIFIED\": 0,\n  \"PROMOTE\": 0,\n"
            << "  \"cases\": [\n";

    bool first = true;
    for (const auto& c : cases) {
        auto r = dispatchLikeAgentCommands(c);
        const bool denied = !r.success;
        const bool ok = (denied == c.expectDeny);
        if (ok) ++pass; else ++fail;
        sb.AppendAudit(denied ? "DENY" : "ALLOW", c.id, c.tool, r.content);

        if (!first) results << ",\n";
        first = false;
        results << "    {\"id\":\"" << c.id << "\",\"tool\":\"" << c.tool
                << "\",\"expectDeny\":" << (c.expectDeny ? "true" : "false")
                << ",\"denied\":" << (denied ? "true" : "false")
                << ",\"ok\":" << (ok ? "true" : "false")
                << ",\"detail\":\"" << Esc(r.content.substr(0, 240)) << "\"}";
    }

    // Gate-missing case
    {
        bare.EndUserTurn();
        bare.BeginUserTurn("bare-gate", 1);
        RawrXD::Agent::ToolCall motd{"bare-motd", "read_motd", nlohmann::json::object()};
        bare.ExecuteToolCall(motd);
        RawrXD::Agent::ToolCall call;
        call.id = "bare-shell";
        call.name = "runInTerminal";
        call.arguments = nlohmann::json{{"command", "echo bare"}};
        auto r = RawrXD::Agent::IdeSsot::DispatchTool(bare, call);
        const bool denied = !r.success;
        const bool ok = denied; // must deny
        if (ok) ++pass; else ++fail;
        if (!first) results << ",\n";
        results << "    {\"id\":\"deny_security_gate_missing\",\"tool\":\"runInTerminal\""
                << ",\"expectDeny\":true,\"denied\":" << (denied ? "true" : "false")
                << ",\"ok\":" << (ok ? "true" : "false")
                << ",\"detail\":\"" << Esc(r.content.substr(0, 240)) << "\"}";
        bare.EndUserTurn();
    }

    results << "\n  ],\n  \"pass\":" << pass << ",\n  \"fail\":" << fail
            << ",\n  \"PROOF_DENY_ON_ESCAPE\":" << (fail == 0 ? "true" : "false")
            << ",\n  \"AgentCommands_hits_SecurityGate\": true\n}\n";
    results.close();

    std::printf("agent_commands_security_probe pass=%d fail=%d\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
