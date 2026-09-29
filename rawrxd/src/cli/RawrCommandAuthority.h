// RawrCommandAuthority.h — RAWRXD_COMMAND_AUTHORITY_001
#pragma once
#include <string>
#include <vector>
namespace rawrxd { namespace cli {
enum class Command { List, Run, RunModelname, ConfigGet, ConfigSet, Doctor, Cert, Install, Service, Server, Unknown };
Command resolveCommand(const std::string& cmd);
int dispatch(Command cmd, const std::vector<std::string>& args);
void writeCommandReceipt(const std::string& path, Command cmd, bool modelResolved, bool modelLoaded, bool genAttempted, int exitCode);
const char* commandName(Command c);
}} // namespace rawrxd::cli