#include "Win32IDE.h"
#include <windows.h>
#include <shellapi.h>
#include <string>

void HandleOSExplorerInterceptor(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    wchar_t cwd[MAX_PATH] = {};
    GetCurrentDirectoryW(MAX_PATH, cwd);
    const HINSTANCE r =
        ShellExecuteW(ide ? ide->getMainWindow() : nullptr, L"explore", cwd,
                      nullptr, nullptr, SW_SHOWNORMAL);
    const bool ok = reinterpret_cast<INT_PTR>(r) > 32;
    if (ide) {
        ide->appendToOutput(
            ok ? "[OSExplorer] ShellExecute explore cwd ok\n"
               : "[OSExplorer] ShellExecute explore failed\n",
            "Explorer",
            ok ? Win32IDE::OutputSeverity::Info : Win32IDE::OutputSeverity::Error);
    }
    if (!ok) {
        MessageBoxA(ide ? ide->getMainWindow() : nullptr,
                    "Failed to open Explorer on workspace cwd.",
                    "OS Explorer Interceptor", MB_ICONERROR | MB_OK);
    }
}
