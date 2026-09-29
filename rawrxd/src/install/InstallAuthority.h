// InstallAuthority.h — RAWRXD_INSTALL_AUTHORITY_001
#pragma once
#include <string>
namespace rawrxd { namespace install {
bool installProduct(const std::string& root, const std::string& version);
bool verifyInstall(const std::string& root);
void writeInstallReceipt(const std::string& path, bool binInstalled, bool rawrExe,
    bool ideExe, bool pathUpdated, bool shortcut, bool service, bool startup,
    const std::string& version);
}} // namespace rawrxd::install