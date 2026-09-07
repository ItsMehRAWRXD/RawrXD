// rawr_terminal_commands.hpp — rawr term ... integration helpers
#pragma once
#include "rawr_terminal_client.hpp"
#include "rawr_agent_terminal_tool.hpp"
#include <cstdio>
#include <string>

namespace rawr::term {

inline int CmdTermDispatch(const std::string& hostExe, const std::string& sub,
                           const std::string& name, const std::string& rest) {
    EnsureHostRunning(hostExe);
    std::string rsp;
    if (sub == "start") {
        if (!TermClientStart(name, rest, rsp)) {
            fprintf(stderr, "%s", rsp.c_str());
            return 1;
        }
        fputs(rsp.c_str(), stderr);
        return 0;
    }
    if (sub == "tail") {
        size_t n = rest.empty() ? 8192 : (size_t)atoi(rest.c_str());
        std::string data;
        if (!TermClientTail(name, n ? n : 8192, data)) return 1;
        fputs(data.c_str(), stdout);
        return 0;
    }
    if (sub == "status") {
        if (!TermClientStatus(name, rsp)) return 1;
        fputs(rsp.c_str(), stdout);
        return 0;
    }
    if (sub == "send") {
        if (!TermClientSend(name, rest, rsp)) return 1;
        return 0;
    }
    if (sub == "stop") {
        if (!TermClientStop(name, rsp)) return 1;
        fputs(rsp.c_str(), stderr);
        return 0;
    }
    if (sub == "list") {
        std::string data;
        if (!TermClientList(data)) return 1;
        fputs(data.c_str(), stdout);
        return 0;
    }
    if (sub == "killall") {
        if (!TermClientKillAll(rsp)) return 1;
        fputs(rsp.c_str(), stderr);
        return 0;
    }
    fprintf(stderr, "usage: term start|tail|status|send|stop|list|killall\n");
    return 1;
}

} // namespace rawr::term
