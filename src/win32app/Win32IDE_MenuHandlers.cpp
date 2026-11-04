// Compatibility translation unit for the native IDE menu build target.
// Menu dispatch is owned by Win32IDE::routeCommand() and the command handlers
// in Win32IDE_Commands.cpp.  Do not add parallel smoke-test handlers here.

#include "Win32IDE.h"

void InitializeMenuHandlers(HWND) {
    // Command registration is performed by the Win32IDE instance.
}

extern "C" void Win32IDE_MenuHandlers_MinimalInit(void) {
    // ABI-compatible no-op retained for older startup code.
}
