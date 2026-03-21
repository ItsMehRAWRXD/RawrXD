#include "ErrorReporter.hpp"
#include <fstream>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

void ErrorReporter::report(const std::string& msg, HWND parent) {
    // Append to a simple log file next to the executable.
    std::ofstream logFile("RawrXD_error.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << msg << std::endl;
    }

#ifdef _WIN32
    // Show a modal message box to the user.
    MessageBoxA(parent ? parent : nullptr, msg.c_str(), "Error", MB_OK | MB_ICONERROR);
#else
    // Print to stderr on non-Windows platforms.
    std::cerr << "[ERROR] " << msg << std::endl;
#endif
}
