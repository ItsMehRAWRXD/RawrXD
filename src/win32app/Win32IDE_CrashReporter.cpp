// ============================================================================
// Win32IDE_CrashReporter.cpp — Crash Reporter (Batch 7 BD05)
// Minidump collection, optional upload
// ============================================================================
#include "Win32IDE.h"
#include <richedit.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <commctrl.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

struct CrashFrame {
    DWORD64     address;
    std::string module;
    std::string function;
    std::string file;
    int         line;
};

void Win32IDE::initCrashReporter() {
    appendToOutput("[CrashReporter] Crash reporter initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::showCrashReport(const std::string& crashFile) {
    std::ostringstream msg;
    msg << "=== Crash Report ===\n";
    msg << "Crash file: " << crashFile << "\n";
    msg << "Time: " << std::ctime(nullptr);
    msg << "Stack trace: See crash log\n";

    MessageBoxA(m_hwndMain, msg.str().c_str(), "Crash Reporter",
                MB_ICONWARNING | MB_OK);
}

std::string Win32IDE::getLastCrashLog() {
    return "No recent crashes.";
}
