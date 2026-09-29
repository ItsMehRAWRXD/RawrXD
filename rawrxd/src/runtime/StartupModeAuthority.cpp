// StartupModeAuthority.cpp — RAWRXD_STARTUP_MODE_AUTHORITY_001
#include "StartupModeAuthority.h"
#include "../ReceiptAuthority.h"
#include <cstring>
namespace rawrxd { namespace startup {
Mode resolveMode(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] && std::strstr(argv[i], "--headless")) return Mode::CliOnly;
        if (argv[i] && std::strstr(argv[i], "--server")) return Mode::Server;
        if (argv[i] && std::strstr(argv[i], "--agent")) return Mode::Agent;
        if (argv[i] && std::strstr(argv[i], "--diagnostic")) return Mode::Diagnostic;
        if (argv[i] && std::strstr(argv[i], "--safe-mode")) return Mode::SafeMode;
        if (argv[i] && std::strstr(argv[i], "--hold")) return Mode::Hold;
    }
    return Mode::Ide;
}
Mode resolveModeFromArgs(const std::string& args) {
    if (args.find("--headless") != std::string::npos) return Mode::CliOnly;
    if (args.find("--server") != std::string::npos) return Mode::Server;
    if (args.find("--agent") != std::string::npos) return Mode::Agent;
    return Mode::Ide;
}
void applyMode(Mode m) { (void)m; }
const char* modeName(Mode m) {
    switch (m) {
        case Mode::CliOnly: return "cli_only"; case Mode::Ide: return "ide";
        case Mode::Server: return "server"; case Mode::Agent: return "agent";
        case Mode::Diagnostic: return "diagnostic"; case Mode::SafeMode: return "safe_mode";
        case Mode::Hold: return "hold"; default: return "unknown";
    }
}
void writeStartupModeReceipt(const std::string& path, Mode m) {
    rawrxd::receipt::beginGate(path, "RAWRXD_STARTUP_MODE_AUTHORITY_001");
    rawrxd::receipt::writeKeyValue(path, "STARTUP_MODE", modeName(m));
    rawrxd::receipt::endGate(path, "PASS");
}
}} // namespace rawrxd::startup