// StartupModeAuthority.h — RAWRXD_STARTUP_MODE_AUTHORITY_001
#pragma once
#include <string>
namespace rawrxd { namespace startup {
enum class Mode { CliOnly, Ide, Server, Agent, Diagnostic, SafeMode, Hold };
Mode resolveMode(int argc, char* argv[]);
Mode resolveModeFromArgs(const std::string& args);
void applyMode(Mode m);
void writeStartupModeReceipt(const std::string& path, Mode m);
const char* modeName(Mode m);
}} // namespace rawrxd::startup