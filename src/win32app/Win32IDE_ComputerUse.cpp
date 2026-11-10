// Wire native Computer Use into session-owned agent Registry + ToolCallBridge.
#include "Win32IDE.h"
#include "IDELogger.h"
#if defined(RAWRXD_HAS_COMPUTER_USE)
#include "ComputerUseBridge.h"
#include "agentic/tool_core.hpp"
#include "agentic/ToolCallBridge.h"
#include <fstream>
#endif

namespace {
#if defined(RAWRXD_HAS_COMPUTER_USE)
void DeleteRegistry(void* p) {
    delete static_cast<rawrxd::tools::Registry*>(p);
}
void DeleteToolBridge(void* p) {
    delete static_cast<RawrXD::Agent::ToolCallBridge*>(p);
}
void CuEvidence(const std::string& line) {
    const char* dir = std::getenv("RAWRXD_LOG_DIR");
    const std::string path = (dir && *dir)
        ? std::string(dir) + "\\chat_runtime.log"
        : std::string("chat_runtime.log");
    std::ofstream out(path, std::ios::app);
    if (out) out << line << std::endl;
}
#endif
}  // namespace

bool Win32IDE::isAgentModeActive() const {
    if (m_agentModeActive) return true;
    if (const char* env = std::getenv("RAWRXD_AGENT_MODE")) {
        if (!env[0]) return false;
        if (env[0] == '1' && env[1] == '\0') return true;
        if (_stricmp(env, "ACTIVE") == 0) return true;
        if (_stricmp(env, "true") == 0) return true;
    }
    return false;
}

void Win32IDE::setAgentModeActive(bool active) {
    m_agentModeActive = active;
}

rawrxd::tools::Registry* Win32IDE::agentToolsRegistry() {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    return static_cast<rawrxd::tools::Registry*>(m_agentToolsRegistry.get());
#else
    return nullptr;
#endif
}

void Win32IDE::ensureComputerUseReady() {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    auto& cu = rawrxd::computer_use::ComputerUseBridge::Instance();
    cu.EnsureInitialized();
    cu.AllowOwnAndConfiguredParents();
    cu.ResetCancel();

    if (!m_agentToolsRegistry) {
        auto* reg = new rawrxd::tools::Registry();
        m_agentToolsRegistry = {reg, &DeleteRegistry};
        std::string ws;
        if (!m_currentExplorerPath.empty()) ws = m_currentExplorerPath;
        else if (!m_currentFile.empty()) {
            const size_t slash = m_currentFile.find_last_of("\\/");
            ws = (slash == std::string::npos)
                ? m_currentFile
                : m_currentFile.substr(0, slash);
        }
        if (!ws.empty()) {
            try {
                rawrxd::tools::register_workspace_tools(*reg, ws);
            } catch (...) {
                LOG_WARNING("Workspace tools registration skipped");
            }
        }
        cu.RegisterTools(*reg);
        auto* bridge = new RawrXD::Agent::ToolCallBridge();
        bridge->SetRegistry(reg);
        if (!ws.empty()) bridge->SetWorkspaceRoot(ws);
        m_agentToolCallBridge = {bridge, &DeleteToolBridge};
        m_computerUseRegistry = reg;
        m_computerUseToolsRegistered = true;
        CuEvidence("AGENT_TOOLS_REGISTRY_BOUND computer_use=1 orphan_static=0");
        CuEvidence("TOOL_SCHEMA_READY computer_use.find_window=1 "
                   "computer_use.screenshot=1");
        LOG_INFO("ComputerUse bound to session Registry + ToolCallBridge");
        return;
    }

    auto* reg = static_cast<rawrxd::tools::Registry*>(m_agentToolsRegistry.get());
    if (!m_computerUseToolsRegistered && reg) {
        cu.RegisterTools(*reg);
        m_computerUseRegistry = reg;
        m_computerUseToolsRegistered = true;
        CuEvidence("AGENT_TOOLS_REGISTRY_CU_ATTACHED computer_use=1");
        LOG_INFO("ComputerUse attached to existing session Registry");
    }
#else
    LOG_INFO("ComputerUse not linked in this build");
#endif
}

void Win32IDE::cancelComputerUse() {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    rawrxd::computer_use::ComputerUseBridge::Instance().Cancel();
    appendToOutput(" ComputerUse cancelled\n", "Output", OutputSeverity::Warning);
#endif
}

std::vector<std::string> Win32IDE::listComputerUseTools() const {
#if defined(RAWRXD_HAS_COMPUTER_USE)
    return {
        "computer_use.screenshot",
        "computer_use.find_window",
        "computer_use.inspect",
        "computer_use.click",
        "computer_use.type",
        "computer_use.key",
        "computer_use.scroll",
        "computer_use.launch",
    };
#else
    return {};
#endif
}
