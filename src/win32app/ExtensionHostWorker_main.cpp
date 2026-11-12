// RawrXD-ExtensionHost.exe — product child: load/activate + stop-event wait.
#include "ExtensionHostWorker_Activate.h"
#include <cstdio>
#include <windows.h>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    ExtHostActivateResult r{};
    ExtHost_ParseArgs(lpCmdLine, &r);
    if (r.extensionPath[0]) {
        ExtHost_LoadAndActivate(&r);
        ExtHost_WriteReceipt(r);
    } else {
        r.processAlive = 1;
        std::snprintf(r.detail, sizeof(r.detail), "no_extension_args");
        ExtHost_WriteReceipt(r);
    }

    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, L"Local\\RawrXD_ExtensionHost_Stop");
    if (!stop) {
        for (;;) Sleep(60000);
        return 0;
    }
    WaitForSingleObject(stop, INFINITE);
    CloseHandle(stop);
    return (r.extensionPath[0] && !r.activateOk) ? 2 : 0;
}
