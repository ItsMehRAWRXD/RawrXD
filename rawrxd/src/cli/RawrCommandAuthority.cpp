// RawrCommandAuthority.cpp — RAWRXD_COMMAND_AUTHORITY_001
#include "RawrCommandAuthority.h"
#include "../ReceiptAuthority.h"
namespace rawrxd { namespace cli {
Command resolveCommand(const std::string& cmd) {
    if (cmd == "list") return Command::List; if (cmd == "run") return Command::Run;
    if (cmd == "config") return Command::ConfigGet; if (cmd == "doctor") return Command::Doctor;
    if (cmd == "cert") return Command::Cert; if (cmd == "install") return Command::Install;
    if (cmd == "service") return Command::Service; if (cmd == "server") return Command::Server;
    return Command::Unknown;
}
int dispatch(Command cmd, const std::vector<std::string>& args) { (void)cmd; (void)args; return 0; }
const char* commandName(Command c) {
    switch (c) { case Command::List: return "list"; case Command::Run: return "run";
        case Command::ConfigGet: return "config"; case Command::Doctor: return "doctor";
        case Command::Cert: return "cert"; case Command::Install: return "install";
        case Command::Service: return "service"; case Command::Server: return "server";
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