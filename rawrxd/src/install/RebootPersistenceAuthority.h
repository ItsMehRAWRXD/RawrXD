// RebootPersistenceAuthority.h — RAWRXD_REBOOT_PERSISTENCE_AUTHORITY_001
#pragma once
#include <string>
namespace rawrxd { namespace install {
bool registerStartup(const std::string& mode);
bool verifyStartupAfterReboot();
void writeRebootReceipt(const std::string& path, const std::string& mode,
    bool bootExpected, bool bootObserved, bool rawRunAvail, bool ideAvail, bool modelDirAvail);
}} // namespace rawrxd::install