// ============================================================================
// [SOURCE] win32app\main_win32.cpp
// FILE: D:\rawrxd\src\win32app\main_win32.cpp
// ============================================================================

// [CONSOLIDATED] #include "Win32IDE.h"
// [CONSOLIDATED] #include "IDELogger.h"
// [SYSINCLUDE] #include <windows.h>
// [SYSINCLUDE] #include <string>
// [SYSINCLUDE] #include <fstream>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Initialize logger early
    try {
        IDELogger::getInstance().initialize("C:\\RawrXD_IDE.log");
        IDELogger::getInstance().setLevel(IDELogger::Level::DEBUG);

    } catch (...) {
        // Fallback to file diagnostic if logger fails
        std::ofstream errLog("C:\\LOGGER_INIT_FAILED.txt");
        errLog << "Logger initialization threw exception" << std::endl;
        errLog.close();
    }

    Win32IDE ide(hInstance);

    if (!ide.createWindow()) {

        MessageBoxA(nullptr, "Failed to create window", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ide.showWindow();

    int rc = ide.runMessageLoop();

    return rc;
}
