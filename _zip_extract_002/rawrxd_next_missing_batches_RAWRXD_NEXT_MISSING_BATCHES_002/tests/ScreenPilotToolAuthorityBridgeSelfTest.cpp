#include "screenpilot/ScreenPilotToolAuthorityBridge.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace RawrXD;
using namespace RawrXD::Agentic;
using namespace RawrXD::ScreenPilot;

static int neverCancelled(void*) { return 0; }
static int approve(void*, const char*, const char*, const char*, std::uint64_t) { return 1; }

int main() {
    AgentToolRegistry registry;
    registry.registerTool({"read-file",{},"read"}, [](const ToolRequest& req, ToolContext&) {
        ToolResult r;
        if (req.surface != AgentToolSurface::LocalServer) { r.exit_code=1; r.stderr_text="wrong surface"; return r; }
        r.stdout_text = "authority-ok";
        return r;
    });

    const auto root = std::filesystem::temp_directory_path() / "rawrxd_sp_authority_001";
    std::filesystem::create_directories(root);
    std::ofstream(root / "a.txt") << "x";
    const auto ws = root.string();
    RawrXD_SP_AgentRequestV2 req{};
    req.workspace = {ws.data(), ws.size()};
    req.permission_mask = RAWRXD_SP_PERM_READ;
    req.approval_required_mask = RAWRXD_SP_PERM_READ;
    req.workspace_only = 1;

    ScreenPilotToolAuthorityBridge bridge(registry);
    auto result = bridge.invoke(req, "read-file", {(root / "a.txt").string()}, {}, RAWRXD_SP_PERM_READ,
                                "read workspace file", "read", &neverCancelled, nullptr, &approve, nullptr);
    std::filesystem::remove_all(root);
    if (!result.ok() || result.stdout_text != "authority-ok") return 1;
    const auto receipt = bridge.receipt();
    if (!receipt.pass() || receipt.registryInvocations != 1 || receipt.approvalsRequested != 1) return 2;
    std::cout << receipt.text();
    return 0;
}
