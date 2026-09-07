// rawr_main.cpp — RAWRXD_AGENTIC_CLI front door
#include "rawr_commands.hpp"
#include "rawr_argument_parser.hpp"
#include "rawr_exit_codes.hpp"

int main(int argc, char** argv) {
    rawr::CliArgs a = rawr::ParseArgs(argc, argv);
    if (a.help || a.cmd.empty()) {
        rawr::PrintUsage();
        return rawr::ExitCode::Usage;
    }
    if (a.cmd == "run") return rawr::CmdRun(a);
    if (a.cmd == "chat") return rawr::CmdChat(a);
    if (a.cmd == "agent") return rawr::CmdAgent(a);
    if (a.cmd == "steer") return rawr::CmdSteer(a);
    if (a.cmd == "resume") return rawr::CmdResume(a);
    if (a.cmd == "term") return rawr::CmdTerm(a);
    rawr::PrintUsage();
    return rawr::ExitCode::Usage;
}
