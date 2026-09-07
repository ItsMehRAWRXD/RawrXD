// rawr_terminal_commands.hpp — rawr term start|list|tail|send|stop
#pragma once
#include "rawr_argument_parser.hpp"
#include "rawr_agent_terminal_tool.hpp"
#include "rawr_output_router.hpp"
#include "rawr_exit_codes.hpp"

namespace rawr {

inline int CmdTerm(const CliArgs& a) {
    SafetyPolicy p{};
    p.level = AutonomyLevel::Build;
    const std::string& sub = a.termSub;
    if (sub == "start") {
        if (a.termName.empty() || a.termCmd.empty()) {
            Diag("usage: rawr term start <name> -- <command>\n");
            return ExitCode::Usage;
        }
        int rc = ToolTermStart(p, a.termName, a.termCmd);
        if (rc != 0) {
            Diag("term start failed rc=%d\n", rc);
            return ExitCode::BuildFail;
        }
        auto* s = TerminalSupervisor::instance().get(a.termName);
        Diag("TERM_START=1 name=%s pid=%lu\n", a.termName.c_str(),
             s ? (unsigned long)s->pid : 0ul);
        OutTextLn(a.termName);
        return ExitCode::Ok;
    }
    if (sub == "list") {
        OutText(ToolTermList().c_str());
        return ExitCode::Ok;
    }
    if (sub == "tail") {
        if (a.termName.empty()) return ExitCode::Usage;
        OutText(ToolTermTail(a.termName).c_str());
        return ExitCode::Ok;
    }
    if (sub == "send") {
        if (a.termName.empty()) return ExitCode::Usage;
        if (!ToolTermSend(a.termName, a.prompt)) return ExitCode::BuildFail;
        return ExitCode::Ok;
    }
    if (sub == "stop") {
        if (a.termName.empty()) return ExitCode::Usage;
        if (!ToolTermStop(a.termName)) {
            Diag("term stop failed\n");
            return ExitCode::BuildFail;
        }
        Diag("TERM_STOP=1 name=%s\n", a.termName.c_str());
        return ExitCode::Ok;
    }
    Diag("usage: rawr term start|list|tail|send|stop\n");
    return ExitCode::Usage;
}

} // namespace rawr
