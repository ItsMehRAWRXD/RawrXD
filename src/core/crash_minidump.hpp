#pragma once
// Shared crash reporter / minidump path (C49) — dbghelp MiniDumpWriteDump.
#include <string>

namespace RawrXD {
namespace Obs {

bool WriteProcessMinidump(const std::string& outPath, unsigned long pid);
bool WriteSelfTestMinidump(const std::string& outPath);
void InstallUnhandledExceptionFilter(const std::string& dumpDir);

}  // namespace Obs
}  // namespace RawrXD
