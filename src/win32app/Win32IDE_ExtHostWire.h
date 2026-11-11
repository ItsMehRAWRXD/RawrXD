#pragma once
// Tip-only ExtensionHost product wire (RAWRXD_NATIVE_IDE_EXT builds).
// Forces JSExtensionHost retention and exposes CLI + install path surface.

#if defined(RAWRXD_NATIVE_IDE_EXT) && RAWRXD_NATIVE_IDE_EXT

#include <string>

struct ExtHostWireResult {
    bool attempted = false;
    bool initOk = false;
    bool loadOk = false;
    bool activateOk = false;
    bool cmdOk = false;
    bool deactivateOk = false;
    bool reloadOk = false;
    bool faultIsolated = false;
    bool processAlive = false;
    char extensionId[256] = {};
    char detail[512] = {};
};

// Returns true if cmdline contained --vsix / --ext-* and was handled.
bool RawrXD_ExtHost_HandleCmdLine(const char* lpCmdLine, ExtHostWireResult* out);

// Install/load a .vsix path or extracted extension directory, then activate.
bool RawrXD_ExtHost_InstallPath(const std::string& pathOrId, ExtHostWireResult* out);

void RawrXD_ExtHost_WriteReceipt(const ExtHostWireResult& r, const char* receiptPath);

#endif
