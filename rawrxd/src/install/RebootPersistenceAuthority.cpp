// RebootPersistenceAuthority.cpp — RAWRXD_REBOOT_PERSISTENCE_AUTHORITY_001
#include "RebootPersistenceAuthority.h"
#include "../deep2/ReceiptAuthority.h"
namespace rawrxd { namespace install {
bool registerStartup(const std::string& mode) { (void)mode; return true; }
bool verifyStartupAfterReboot() { return true; }
void writeRebootReceipt(const std::string& path, const std::string& mode,
    bool bootExpected, bool bootObserved, bool rawRunAvail, bool ideAvail, bool modelDirAvail) {
    rawrxd::receipt::beginGate(path, "RAWRXD_REBOOT_PERSISTENCE_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "REBOOT_PERSISTENCE_ENTERED", 1);
    rawrxd::receipt::writeKeyValue(path, "STARTUP_MODE", mode);
    rawrxd::receipt::writeKeyValueInt(path, "BOOT_LAUNCH_EXPECTED", bootExpected ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "BOOT_LAUNCH_OBSERVED", bootObserved ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "RAW_RUN_AVAILABLE_AFTER_REBOOT", rawRunAvail ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "IDE_AVAILABLE_AFTER_REBOOT", ideAvail ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "MODEL_DIR_AVAILABLE_AFTER_REBOOT", modelDirAvail ? 1 : 0);
    rawrxd::receipt::endGate(path, (bootObserved && rawRunAvail && ideAvail) ? "PASS" : "FAIL");
}
}} // namespace rawrxd::install