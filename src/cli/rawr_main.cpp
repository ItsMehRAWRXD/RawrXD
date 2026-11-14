// rawr_main.cpp — RAWRXD_AGENTIC_CLI front door
#include "rawr_commands.hpp"
#include "rawr_argument_parser.hpp"
#include "rawr_exit_codes.hpp"

int main(int argc, char** argv) {
    rawr::CliArgs a = rawr::ParseArgs(argc, argv);
    const bool cmdHelp =
        a.cmd == "--help" || a.cmd == "-h" || a.cmd == "help";
    if (a.help || cmdHelp) {
        rawr::PrintUsage();
        return rawr::ExitCode::Ok;
    }
    if (a.cmd.empty()) {
        rawr::PrintUsage();
        return rawr::ExitCode::Usage;
    }
    if (a.cmd == "list") return rawr::CmdList(a);
    if (a.cmd == "show") return rawr::CmdShow(a);
    if (a.cmd == "paths") return rawr::CmdPaths(a);
    if (a.cmd == "run") return rawr::CmdRun(a);
    if (a.cmd == "chat") return rawr::CmdChat(a);
    if (a.cmd == "agent") return rawr::CmdAgent(a);
    if (a.cmd == "steer") return rawr::CmdSteer(a);
    if (a.cmd == "resume") return rawr::CmdResume(a);
    if (a.cmd == "term") return rawr::CmdTerm(a);
    if (a.cmd == "serve") return rawr::CmdServe(a);
    if (a.cmd == "debug") return rawr::CmdDebug(a);
    rawr::PrintUsage();
    return rawr::ExitCode::Usage;
}
