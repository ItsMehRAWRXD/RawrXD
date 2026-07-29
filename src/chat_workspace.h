#pragma once
#include <string>
#include <memory>
#include <sstream>
#include "weaponized_agent_bridge.hpp"

<<<<<<< HEAD
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
=======

class ChatWorkspace : public void {

public:
    explicit ChatWorkspace(void* parent = nullptr);
    void initialize();


    void commandIssued(const std::string& command);
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
