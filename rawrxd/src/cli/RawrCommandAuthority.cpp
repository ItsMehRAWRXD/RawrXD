// RawrCommandAuthority.cpp — RAWRXD_COMMAND_AUTHORITY_001
#include "RawrCommandAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <cstdio>
namespace rawrxd { namespace cli {
Command resolveCommand(const std::string& cmd) {
    if (cmd == "list") return Command::List; if (cmd == "run") return Command::Run;
    if (cmd == "config") return Command::ConfigGet; if (cmd == "doctor") return Command::Doctor;
    if (cmd == "cert") return Command::Cert; if (cmd == "install") return Command::Install;
    if (cmd == "service") return Command::Service; if (cmd == "server") return Command::Server;
    if (cmd == "reverse") return Command::ReverseAssembly;
    return Command::Unknown;
}
// RAWRXD_COMMAND_AUTHORITY_002 — dispatch was a hardcoded success:
//
//   int dispatch(Command cmd, const std::vector<std::string>& args) { (void)cmd; (void)args; return 0; }
//
// Every one of the eight commands resolved to this and returned 0, and
// writeCommandReceipt then evaluated `exitCode == 0 ? "PASS" : "FAIL"` into
// RAWRXD_COMMAND_AUTHORITY_001=PASS without a single line of the command ever
// executing. A stub that reports success is worse than no stub: the receipt is
// indistinguishable from a real run.
//
// dispatch now fails closed. It reports which command was asked for and returns
// a non-zero code, so the receipt records FAIL and the failure is visible. It
// does NOT pretend to implement these commands: doing so would require the real
// list/run/doctor/service implementations, which do not exist here.
int dispatch(Command cmd, const std::vector<std::string>& args) {
    (void)args;
    std::fprintf(stderr,
        "rawr: subcommand '%s' is recognised but NOT IMPLEMENTED in "
        "RawrCommandAuthority::dispatch (RAWRXD_COMMAND_AUTHORITY_002).\n"
        "rawr: the real implementations are 'rawr list|ls|models', "
        "'rawr dump', 'rawr agent', 'rawr agent-e2e' and "
        "'rawr modes|audit|gate|cert' -- see src/deep2/rawr_run.cpp.\n",
        commandName(cmd));
    return 127;  // conventional "command not found / not executable"
}
const char* commandName(Command c) {
    switch (c) { case Command::List: return "list"; case Command::Run: return "run";
        case Command::ConfigGet: return "config"; case Command::Doctor: return "doctor";
        case Command::Cert: return "cert"; case Command::Install: return "install";
        case Command::Service: return "service"; case Command::Server: return "server";
        case Command::ReverseAssembly: return "reverse";
        default: return "unknown"; }
}
void writeCommandReceipt(const std::string& path, Command cmd, bool modelResolved, bool modelLoaded, bool genAttempted, int exitCode) {
    rawrxd::receipt::beginGate(path, "RAWRXD_COMMAND_AUTHORITY_001");
    rawrxd::receipt::writeKeyValue(path, "COMMAND", commandName(cmd));
    rawrxd::receipt::writeKeyValueInt(path, "ARGS_PARSED", 1);
    rawrxd::receipt::writeKeyValueInt(path, "MODEL_RESOLUTION_ATTEMPTED", modelResolved ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "MODEL_LOAD_ATTEMPTED", modelLoaded ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "GENERATION_ATTEMPTED", genAttempted ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "EXIT_CODE", exitCode);
    rawrxd::receipt::endGate(path, exitCode == 0 ? "PASS" : "FAIL");
}
}} // namespace rawrxd::cli