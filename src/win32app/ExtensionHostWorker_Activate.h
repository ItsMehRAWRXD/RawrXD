// ExtensionHostWorker_Activate.h — native load/activate for product host child.
#pragma once
#include <windows.h>

struct ExtHostActivateResult {
    char extensionId[128];
    char extensionPath[MAX_PATH];
    char detail[256];
    int loadOk;
    int activateOk;
    int mainPresent;
    int processAlive;
};

// Parse WinMain cmdline for --extension-id / --extension-path.
void ExtHost_ParseArgs(const char* cmdLine, ExtHostActivateResult* out);

// Load package.json + main entry; write receipt; fail-closed (no invent PASS).
int ExtHost_LoadAndActivate(ExtHostActivateResult* io);

// Write RAWRXD_EXT_HOST_RECEIPT or default evidence receipt path.
void ExtHost_WriteReceipt(const ExtHostActivateResult& r);
