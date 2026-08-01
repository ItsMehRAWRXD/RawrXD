#pragma once
#include <string>
#include <memory>
#include <sstream>
#include "weaponized_agent_bridge.hpp"

namespace RawrXD {

class ChatWorkspace {
public:
    explicit ChatWorkspace(void* parent = nullptr);
    void initialize();
    void commandIssued(const std::string& command);

private:
    void* m_parent;
    std::unique_ptr<RawrXD::WeaponizedAgentBridge> m_agentBridge;
    void ProcessAgentCommand(std::istringstream& iss);
};

} // namespace RawrXD
