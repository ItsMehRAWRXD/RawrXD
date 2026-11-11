// ============================================================================
// chat_workspace.cpp - Weaponized Agent Integration
// ============================================================================

#include "chat_workspace.h"
#include <windows.h>
#include <chrono>
#include <sstream>
#include <mutex>
#include <vector>

namespace RawrXD {

ChatWorkspace::ChatWorkspace(void* parent) : m_parent(parent), m_agentBridge(nullptr) {}

void ChatWorkspace::initialize() {
    // Lightweight init
}

void ChatWorkspace::commandIssued(const std::string& command) {
    if (command.empty()) return;
    if (command[0] == '/') {
        std::istringstream iss(command);
        std::string cmd;
        iss >> cmd;
        if (cmd == "/agent") ProcessAgentCommand(iss);
    }
}

void ChatWorkspace::ProcessAgentCommand(std::istringstream& iss) {
    std::string missionType, missionParams;
    iss >> missionType;
    std::string rest;
    std::getline(iss, rest);
    rest.erase(0, rest.find_first_not_of(" \t"));
    
    if (!m_agentBridge) m_agentBridge = std::make_unique<RawrXD::WeaponizedAgentBridge>();
    if (!m_agentBridge->initialize()) return;
    
    auto result = m_agentBridge->executeMission(missionType, rest);
    // Output result (in production, this would stream to UI)
}

} // namespace RawrXD
