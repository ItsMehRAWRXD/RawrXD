// Win32IDE_CommandRouter.h
// Command router that connects menu IDs to handler functions

#pragma once
#include <windows.h>

// =============================================================================
// COMMAND ROUTER
// =============================================================================

// Handle a menu command by ID
// Returns true if handled, false if not
bool HandleMenuCommand(int commandId);

// Window message handler for WM_COMMAND
// Call this from your main window procedure
LRESULT CALLBACK Win32IDECommandHandler(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

// Initialize command router (sets initial menu states)
void InitializeCommandRouter();
