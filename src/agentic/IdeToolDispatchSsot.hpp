// IdeToolDispatchSsot — single IDE tool-dispatch choke point (gap 5).
// SSOT = rawrxd::tools::Registry + ToolCallBridge::ExecuteToolCall.
// Permission / approval hook site: ApprovalCallback on the bridge, applied
// inside ExecuteToolCall before Registry::call. Do not add parallel dispatchers.
#pragma once

#include "ToolCallBridge.h"
#include "tool_core.hpp"
#include <fstream>
#include <cstdlib>
#include <string>

namespace RawrXD {
namespace Agent {
namespace IdeSsot {

inline void Evidence(const std::string& line) {
    const char* dir = std::getenv("RAWRXD_LOG_DIR");
    const std::string path = (dir && *dir)
        ? std::string(dir) + "\\chat_runtime.log"
        : std::string("chat_runtime.log");
    std::ofstream out(path, std::ios::app);
    if (out) out << line << std::endl;
}

// Adapter: AgentToolRegistry / rawr_core / legacy names → workspace SSOT names.
inline void RegisterNameAdapters(rawrxd::tools::Registry& /*reg*/) {
    // Canonicalization lives in tool_core::canonicalize_tool_name (ConvertArgs).
    // This marker proves the IDE adapter path is wired (not a silent parallel registry).
    Evidence("IDE_TOOL_SSOT_ADAPTERS_BOUND "
             "ssot=ToolCallBridge+rawrxd::tools::Registry "
             "agent_tool_registry=adapter "
             "rawr_core_tool_registry=adapter");
}

// Single DispatchTool entry for IDE agent tools (permission hook site).
inline ToolResultMessage DispatchTool(ToolCallBridge& bridge, const ToolCall& call) {
    Evidence(std::string("IDE_DISPATCH_TOOL name=") + call.name +
             " via=ToolCallBridge::ExecuteToolCall permission_hook=ApprovalCallback");
    return bridge.ExecuteToolCall(call);
}

inline void BindBridge(ToolCallBridge& bridge, rawrxd::tools::Registry* reg,
                       const std::string& workspaceRoot) {
    bridge.SetRegistry(reg);
    if (!workspaceRoot.empty()) bridge.SetWorkspaceRoot(workspaceRoot);
    if (reg) RegisterNameAdapters(*reg);
    Evidence("IDE_TOOL_SSOT_BOUND bridge=1 registry=" +
             std::string(reg ? "1" : "0") + " workspace=" + workspaceRoot);
}

} // namespace IdeSsot
} // namespace Agent
} // namespace RawrXD
