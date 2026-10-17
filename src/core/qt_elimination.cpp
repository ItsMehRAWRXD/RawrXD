/**
 * @file qt_elimination.cpp
 * @brief Global instances for QT elimination compatibility layer
 */

#include "qt_elimination.h"

// Global signal/slot dispatcher
NativeSignalSlot g_signalSlot;

// Global settings (stored in app data directory)
NativeSettings g_settings([]() -> std::string {
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string exePath(path);
    size_t pos = exePath.find_last_of("/\\");
    if (pos != std::string::npos) {
        exePath = exePath.substr(0, pos);
    }
    return exePath + "/settings.json";
}());
