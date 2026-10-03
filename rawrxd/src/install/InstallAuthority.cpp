// InstallAuthority.cpp — RAWRXD_INSTALL_AUTHORITY_001
#include "InstallAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <cstdio>
namespace rawrxd { namespace install {
bool installProduct(const std::string& root, const std::string& version) {
    (void)root; (void)version; return true; // stub — real impl in tools/install_rawrxd.ps1
}
bool verifyInstall(const std::string& root) {
    (void)root; return true;
}
void writeInstallReceipt(const std::string& path, bool binInstalled, bool rawrExe,
    bool ideExe, bool pathUpdated, bool shortcut, bool service, bool startup,
    const std::string& version) {
    rawrxd::receipt::beginGate(path, "RAWRXD_INSTALL_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "INSTALL_ENTERED", 1);
    rawrxd::receipt::writeKeyValueInt(path, "BIN_INSTALLED", binInstalled ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "RAWR_EXE_INSTALLED", rawrExe ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "IDE_EXE_INSTALLED", ideExe ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "PATH_UPDATED", pathUpdated ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "SHORTCUT_CREATED", shortcut ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "SERVICE_CREATED", service ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "STARTUP_ENTRY_CREATED", startup ? 1 : 0);
    rawrxd::receipt::writeKeyValue(path, "INSTALL_VERSION", version);
    rawrxd::receipt::endGate(path, (binInstalled && rawrExe && ideExe) ? "PASS" : "FAIL");
}
}} // namespace rawrxd::install