// ============================================================================
// GhostTextWndProc.hpp - Ghost Text Window Procedure Integration Header
// ============================================================================

#pragma once
#include <Windows.h>

// Custom window messages for ghost text
#define UWM_SHOW_GHOST_TEXT    (WM_USER + 0x1000)
#define UWM_DISMISS_GHOST_TEXT (WM_USER + 0x1001)
#define UWM_ACCEPT_GHOST_TEXT  (WM_USER + 0x1002)

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Installation / Removal
// ============================================================================

// Install ghost text handling into IDE windows
// Call this once during IDE initialization
bool GhostText_Install(HWND hMainWindow, HWND hEditor);

// Remove ghost text subclassing
// Call this during IDE shutdown
void GhostText_Uninstall(HWND hMainWindow, HWND hEditor);

// ============================================================================
// Ghost Text Control
// ============================================================================

// Show a ghost text suggestion at caret position
void GhostText_ShowSuggestion(int caretPos, const char* suggestion);

// Dismiss current ghost text
void GhostText_Dismiss(void);

// Accept current ghost text (returns true if accepted)
bool GhostText_Accept(void);

// Check if ghost text is currently showing
bool GhostText_IsShowing(void);

// Get current suggestion text (nullptr if not showing)
const char* GhostText_GetCurrentSuggestion(void);

// ============================================================================
// AI Runtime Integration
// ============================================================================

// Call when AI generates a completion
void GhostText_OnAICompletion(const char* completion, int insertPos);

// Call when AI streaming starts
void GhostText_OnAIStreamStart(void);

// Call when AI streaming ends
void GhostText_OnAIStreamEnd(void);

// ============================================================================
// Menu Integration
// ============================================================================

// Add these to your resource.h
#define IDM_AI_STOP_GENERATION  0xE100
#define IDM_AI_SHOW_COMPLETION  0xE101
#define IDM_AI_ACCEPT_COMPLETION 0xE102
#define IDM_AI_DISMISS_COMPLETION 0xE103

// Menu strings for your .rc file:
// MENUITEM "Stop Generation\tCtrl+Break", IDM_AI_STOP_GENERATION
// MENUITEM "Show Completion\tCtrl+Space", IDM_AI_SHOW_COMPLETION
// MENUITEM "Accept Completion\tTab", IDM_AI_ACCEPT_COMPLETION
// MENUITEM "Dismiss Completion\tEsc", IDM_AI_DISMISS_COMPLETION

#ifdef __cplusplus
}
#endif
