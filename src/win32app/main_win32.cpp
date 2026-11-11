#include "Win32IDE.h"
#include "IDELogger.h"
#include <windows.h>
#include <string>
#include <fstream>

namespace {
void startupTrace(const char* message)
{
    std::ofstream trace("F:\\rawrxd\\startup_trace.log", std::ios::app);
    if (trace) trace << message << '\n';
}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    startupTrace("WinMain entered");
    startupTrace(lpCmdLine && *lpCmdLine ? lpCmdLine : "WinMain command line empty");
    // Initialize logger early
    try {
        IDELogger::getInstance().initialize("C:\\RawrXD_IDE.log");
        IDELogger::getInstance().setLevel(IDELogger::Level::DEBUG);
        LOG_INFO("WinMain started - RawrXD Win32 IDE initializing");
    } catch (...) {
        // Fallback to file diagnostic if logger fails
        std::ofstream errLog("C:\\LOGGER_INIT_FAILED.txt");
        errLog << "Logger initialization threw exception" << std::endl;
        errLog.close();
    }

    LOG_DEBUG("Creating Win32IDE instance");
    startupTrace("before Win32IDE constructor");
    Win32IDE ide(hInstance);
    startupTrace("after Win32IDE constructor");
    LOG_DEBUG("Win32IDE constructor completed");

    if (!ide.createWindow()) {
        startupTrace("createWindow failed");
        LOG_ERROR("createWindow() failed");
        MessageBoxA(nullptr, "Failed to create window", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    std::string initialPath;
    // The verification and normal shell launch paths may provide an initial
    // document.  WinMain receives the command line without argv[0]; accept a
    // single quoted or unquoted path and load it only after the editor HWND
    // exists so the normal document/session machinery is used.
    if (lpCmdLine && *lpCmdLine) {
        initialPath = lpCmdLine;
        while (!initialPath.empty() &&
               (initialPath.front() == ' ' || initialPath.front() == '\t')) {
            initialPath.erase(initialPath.begin());
        }
        while (!initialPath.empty() &&
               (initialPath.back() == ' ' || initialPath.back() == '\t')) {
            initialPath.pop_back();
        }
        if (initialPath.size() >= 2 && initialPath.front() == '"' &&
            initialPath.back() == '"') {
            initialPath = initialPath.substr(1, initialPath.size() - 2);
        }
    }

    LOG_INFO("Main window created successfully");
    startupTrace("createWindow succeeded");
    ide.showWindow();
    startupTrace("showWindow returned");
    if (!initialPath.empty()) {
        LOG_INFO("Opening initial document: " + initialPath);
        const bool opened = ide.openDocumentPath(initialPath);
        startupTrace(opened ? "initial document opened" : "initial document open FAILED");
        if (!opened) {
            LOG_ERROR("Failed to open initial document: " + initialPath);
        }
    }
    LOG_INFO("Entering message loop");
    startupTrace("entering message loop");
    int rc = ide.runMessageLoop();
    LOG_INFO("Message loop exited with code " + std::to_string(rc));
    return rc;
}
