// IDE agent tool SSOT (gaps 5/9): dispatchAgentTool → IdeSsot → ExecuteToolCall.
#include "Win32IDE.h"
#include "IDELogger.h"
#include "agentic/tool_core.hpp"
#include "agentic/ToolCallBridge.h"
#include "agentic/IdeToolDispatchSsot.hpp"
#include <atomic>
#if defined(RAWRXD_HAS_COMPUTER_USE)
#include "ComputerUseBridge.h"
#endif

namespace {
void DeleteRegistry(void* p) {
    delete static_cast<rawrxd::tools::Registry*>(p);
}
void DeleteToolBridge(void* p) {
    delete static_cast<RawrXD::Agent::ToolCallBridge*>(p);
}
std::atomic<uint64_t> g_ideDispatchTurn{1};
}  // namespace

RawrXD::Agent::ToolCallBridge* Win32IDE::agentToolCallBridge() {
    return static_cast<RawrXD::Agent::ToolCallBridge*>(m_agentToolCallBridge.get());
}

bool Win32IDE::ensureAgentToolSsotReady() {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    // ComputerUse path owns sandbox+consent gates on the same SSOT bridge.
    ensureComputerUseReady();
    return agentToolCallBridge() != nullptr;
#else
    std::string ws;
    if (!m_currentExplorerPath.empty()) ws = m_currentExplorerPath;
    else if (!m_currentFile.empty()) {
        const size_t slash = m_currentFile.find_last_of("\\/");
        ws = (slash == std::string::npos) ? m_currentFile
                                          : m_currentFile.substr(0, slash);
    }
    if (!m_agentToolsRegistry) {
        auto* reg = new rawrxd::tools::Registry();
        m_agentToolsRegistry = {reg, &DeleteRegistry};
        if (!ws.empty()) {
            try { rawrxd::tools::register_workspace_tools(*reg, ws); }
            catch (...) { LOG_WARNING("Workspace tools registration skipped"); }
        }
        auto* bridge = new RawrXD::Agent::ToolCallBridge();
        RawrXD::Agent::IdeSsot::BindBridge(*bridge, reg, ws);
        m_agentToolCallBridge = {bridge, &DeleteToolBridge};
        LOG_INFO("IDE agent ToolCallBridge SSOT bound (no ComputerUse)");
    }
    return agentToolCallBridge() != nullptr;
#endif
}

RawrXD::Agent::ToolResultMessage
Win32IDE::dispatchAgentTool(const RawrXD::Agent::ToolCall& call) {
    ensureAgentToolSsotReady();
    auto* bridge = agentToolCallBridge();
    if (!bridge) {
        RawrXD::Agent::ToolResultMessage fail;
        fail.tool_call_id = call.id;
        fail.tool_name = call.name;
        fail.success = false;
        fail.content = "DENIED: IDE ToolCallBridge SSOT not initialized";
        return fail;
    }

    // IDE AgentCommands-originated dispatch: open turn + ACK MOTD so
    // SecurityGate runs before any mutate/shell side effect (fail-closed).
    bridge->EndUserTurn();
    const uint64_t turn = g_ideDispatchTurn.fetch_add(1);
    if (!bridge->BeginUserTurn("ide-agent-commands", turn)) {
        RawrXD::Agent::ToolResultMessage fail;
        fail.tool_call_id = call.id;
        fail.tool_name = call.name;
        fail.success = false;
        fail.content = "DENIED: cannot begin IDE tool turn (workspace/MOTD root required)";
        RawrXD::Agent::IdeSsot::Evidence(
            "IDE_DISPATCH_TURN_FAIL session=ide-agent-commands");
        return fail;
    }
    {
        RawrXD::Agent::ToolCall motd;
        motd.id = "ide-motd-" + std::to_string(turn);
        motd.name = "read_motd";
        motd.arguments = nlohmann::json::object();
        auto motdResult = bridge->ExecuteToolCall(motd);
        if (!motdResult.success) {
            RawrXD::Agent::ToolResultMessage fail;
            fail.tool_call_id = call.id;
            fail.tool_name = call.name;
            fail.success = false;
            fail.content = std::string("DENIED: MOTD required before tools: ") +
                           motdResult.content;
            bridge->EndUserTurn();
            return fail;
        }
    }

    // Single choke: IdeSsot::DispatchTool → ToolCallBridge::ExecuteToolCall
    // (SecurityGate + ApprovalCallback BEFORE registry->call).
    auto result = RawrXD::Agent::IdeSsot::DispatchTool(*bridge, call);
    bridge->EndUserTurn();
    return result;
}
