// rawr_agent_terminal_tool.hpp — agent-facing terminal client wrappers
#pragma once
#include "rawr_terminal_client.hpp"
#include "rawr_terminal_supervisor.hpp"
#include <string>

namespace rawr::term {

struct AgentTerminalTool {
    bool useHost = false;
    std::string hostExe;

    int start(const std::string& name, const std::string& cmd) {
        if (useHost) {
            EnsureHostRunning(hostExe);
            std::string rsp;
            return TermClientStart(name, cmd, rsp) ? 0 : 1;
        }
        return TerminalSupervisor::instance().start(name, cmd);
    }

    std::string tail(const std::string& name, size_t n = 8192) {
        if (useHost) {
            EnsureHostRunning(hostExe);
            std::string data;
            TermClientTail(name, n, data);
            return data;
        }
        return TerminalSupervisor::instance().tail(name, n);
    }

    bool stop(const std::string& name) {
        if (useHost) {
            EnsureHostRunning(hostExe);
            std::string rsp;
            return TermClientStop(name, rsp);
        }
        return TerminalSupervisor::instance().stop(name);
    }

    bool send(const std::string& name, const std::string& text) {
        if (useHost) {
            EnsureHostRunning(hostExe);
            std::string rsp;
            return TermClientSend(name, text, rsp);
        }
        return TerminalSupervisor::instance().send(name, text);
    }
};

} // namespace rawr::term
