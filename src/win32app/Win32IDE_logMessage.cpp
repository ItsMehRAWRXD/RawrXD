// =============================================================================
// Win32IDE_logMessage.cpp — Build variant: LogMessage fallback for targets that link
// Win32IDE panel code but not the full GUI (e.g. RawrEngine). Production impl:
// writes to OutputDebugString and %APPDATA%\RawrXD\ide.log.
// =============================================================================
#include "Win32IDE.h"

// NOTE: Win32IDE::logMessage is implemented in Win32IDE_Logger.cpp
// This file is kept for build system compatibility but contains no code
// to avoid duplicate symbol errors during linking.

// If you need a fallback implementation, use Win32IDE_Logger.cpp instead.
