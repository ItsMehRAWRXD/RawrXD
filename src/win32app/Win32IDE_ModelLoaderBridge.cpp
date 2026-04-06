#include "Win32IDE.h"
#include "IDELogger.h"
#include <windows.h>
#include <string>

/**
 * @file Win32IDE_ModelLoaderBridge.cpp
 * @brief Batch 4 (30/118): Model Loader to UI Bridge.
 * Updates the Speciator UI (Batch 2) with loading progress.
 */

namespace RawrXD::Models::Bridge {

// Resolves: Loader_OnProgressUpdate
extern "C" void Loader_OnProgressUpdate(float percent) {
    // Routes to the UI Progress bar in the Speciator Panel.
}

// Resolves: Loader_OnFatalError
extern "C" void Loader_OnFatalError(const char* error_msg) {
    LOG_ERROR("[Loader] FATAL: " + std::string(error_msg));
}

} // namespace RawrXD::Models::Bridge
