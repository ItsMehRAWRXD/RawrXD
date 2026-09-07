// rawr_agent_terminal_tool.hpp — agent TERM_* tools
#pragma once
#include "rawr_terminal_supervisor.hpp"
#include <string>

namespace rawr {

inline int ToolTermStart(const SafetyPolicy& p, const std::string& name,
                         const std::string& cmd) {
    return TerminalSupervisor::instance().start(p, name, cmd);
}

inline std::string ToolTermTail(const std::string& name, size_t n = 8192) {
    return TerminalSupervisor::instance().tail(name, n);
}

inline bool ToolTermStop(const std::string& name) {
    return TerminalSupervisor::instance().stop(name);
}

inline bool ToolTermSend(const std::string& name, const std::string& in) {
    return TerminalSupervisor::instance().send(name, in);
}

inline std::string ToolTermList() {
    return TerminalSupervisor::instance().list();
}

inline bool ApplyTermSteer(const SteerCommand& c, std::string& out) {
    out.clear();
    if (c.verb == "tail") {
        out = ToolTermTail(c.arg.empty() ? "build" : c.arg);
        return true;
    }
    if (c.verb == "stop") {
        return ToolTermStop(c.arg.empty() ? "build" : c.arg);
    }
    if (c.verb == "list" || c.verb == "term_list") {
        out = ToolTermList();
        return true;
    }
    return false;
}

} // namespace rawr
