// rawr_terminal_host.hpp — named-pipe broker loop
#pragma once
#include "rawr_terminal_protocol.hpp"
#include "rawr_terminal_supervisor.hpp"
#include <string>

namespace rawr::term {

std::string HandleHostRequest(TerminalSupervisor& sup, const std::string& line);
int RunTerminalHost(int idleExitMs = 0); // 0 = run until KILLALL+empty or forever
bool HostIsAlive();

} // namespace rawr::term
