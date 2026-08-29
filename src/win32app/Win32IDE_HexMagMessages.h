// ============================================================================
// Win32IDE_HexMagMessages.h — shared HexMag Copilot completion message IDs
// ============================================================================
// Used by Win32IDE_HexMagCopilotRoute.cpp (poster) and Win32IDE_Core.cpp (handler).
// Do not redefine these privately in a single TU.
// ============================================================================
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifndef WM_HEXMAG_COPILOT_DONE
// Keep clear of Copilot WM_APP+109..111 and plan/agent 500–521 bands.
#define WM_HEXMAG_COPILOT_DONE (WM_APP + 220)
#endif

class Win32IDE;

/// UI-thread finish for controller outcomes (FINAL | NEED_INPUT | FAIL-CLOSED).
void RawrXD_FinishHexMagCopilotDone(void* idePtr, LPARAM lParam);
