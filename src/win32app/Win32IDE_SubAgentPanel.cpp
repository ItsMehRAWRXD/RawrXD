// =============================================================================
// Win32IDE_SubAgentPanel.cpp — A6 multi-agent orchestration UI (TOP50 A6).
// =============================================================================
// AGENTS panel tab (5): live list of sub-agents from the real subagent_core
// SubAgentManager (spawn/cancel/chains/swarms). The command box routes
// `agents` / `spawn <description>` / `kill <agentId>` through the same
// manager. Without an inference engine the manager fails closed.
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <string>

#include "subagent_core.h"

#define IDC_AGENT_LIST 1311
#define IDC_AGENT_SPAWN_INPUT 1312

// One persistent manager per IDE process (subagent_core is not a singleton;
// a null engine makes spawn fail closed until an engine is attached).
static SubAgentManager& SubAgents() {
    static SubAgentManager mgr(nullptr);
    return mgr;
}

void Win32IDE::initSubAgentPanel() {
    ensurePanelTabBodies();
    if (!m_hwndSubAgentList || !IsWindow(m_hwndSubAgentList)) {
        OutputDebugStringA("WARN: initSubAgentPanel list missing\n");
        return;
    }
    refreshSubAgentList();
    switchPanelTab(PanelTab::Agents);
}

void Win32IDE::refreshSubAgentList() {
    if (!m_hwndSubAgentList || !IsWindow(m_hwndSubAgentList)) return;
    ListView_DeleteAllItems(m_hwndSubAgentList);
    try {
        const auto agents = SubAgents().getAllSubAgents();
        int row = 0;
        for (const auto& a : agents) {
            LVITEMA lvi = {0};
            lvi.mask = LVIF_TEXT;
            lvi.iItem = row;
            char idBuf[64];
            std::snprintf(idBuf, sizeof(idBuf), "%s (parent %s)",
                          a.id.substr(0, 8).c_str(),
                          a.parentId.substr(0, 8).c_str());
            lvi.pszText = idBuf;
            SendMessageA(m_hwndSubAgentList, LVM_INSERTITEMA, 0,
                         (LPARAM)&lvi);
            lvi.iSubItem = 1;
            lvi.pszText = const_cast<char*>(a.description.c_str());
            SendMessageA(m_hwndSubAgentList, LVM_SETITEMTEXTA, row, (LPARAM)&lvi);
            lvi.iSubItem = 2;
            const char* st = a.state == SubAgent::State::Running ? "Running"
                           : a.state == SubAgent::State::Completed ? "Completed"
                           : a.state == SubAgent::State::Failed ? "Failed"
                           : a.state == SubAgent::State::Cancelled ? "Cancelled"
                                                                   : "Pending";
            lvi.pszText = const_cast<char*>(st);
            SendMessageA(m_hwndSubAgentList, LVM_SETITEMTEXTA, row, (LPARAM)&lvi);
            ++row;
        }
        char sum[128];
        std::snprintf(sum, sizeof(sum),
                      "[Agents] %zu sub-agent(s), %d active\n", agents.size(),
                      SubAgents().activeSubAgentCount());
        appendToOutput(sum, "Agent", OutputSeverity::Info);
    } catch (const std::exception& e) {
        appendToOutput(std::string("[Agents] manager error: ") + e.what() +
                           "\n",
                       "Agent", OutputSeverity::Error);
    }
}

void Win32IDE::spawnSubAgent(const std::string& description) {
    if (description.empty()) {
        appendToOutput("[Agents] Usage: spawn <description>\n", "Agent",
                       OutputSeverity::Info);
        return;
    }
    try {
        const std::string id = SubAgents().spawnSubAgent("ide", description,
                                                         description);
        appendToOutput("[Agents] spawned " + id + " : " + description + "\n",
                       "Agent", OutputSeverity::Info);
        refreshSubAgentList();
    } catch (const std::exception& e) {
        // Fail-closed: no engine wired -> no fabricated agent output.
        appendToOutput(std::string("[Agents] spawn refused (fail-closed): ") +
                           e.what() + "\n",
                       "Agent", OutputSeverity::Warning);
    }
}

void Win32IDE::killSubAgent(const std::string& agentId) {
    if (agentId.empty()) {
        appendToOutput("[Agents] Usage: kill <agentId>\n", "Agent",
                       OutputSeverity::Info);
        return;
    }
    try {
        SubAgents().cancelSubAgent(agentId);
        appendToOutput("[Agents] cancel requested: " + agentId + "\n", "Agent",
                       OutputSeverity::Info);
        refreshSubAgentList();
    } catch (const std::exception& e) {
        appendToOutput(std::string("[Agents] cancel failed: ") + e.what() +
                           "\n",
                       "Agent", OutputSeverity::Error);
    }
}