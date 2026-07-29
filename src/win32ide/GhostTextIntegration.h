// ============================================================================
// GhostTextIntegration.h - Bridge ghost_text_engine to GhostOverlay (Day 2)
// ============================================================================
// Connects the thread-safe GhostTextBuffer (inference thread) to the
// UI GhostOverlay (main thread) via WM_APP messages.
//
// DAY 2 DELIVERABLE:
// - Initialize/Shutdown integration
// - Poll for new suggestions from inference thread
// - Handle WM_APP_GHOST_* messages
// - Provide status text for IDE status bar
// ============================================================================

#pragma once

#include <windows.h>
#include <string>

namespace RawrXD {
namespace UI {

// ============================================================================
// GhostTextIntegration - Bridge between engine and UI
// ============================================================================
class GhostTextIntegration {
public:
    // Initialize integration with editor window
    // Call once at IDE startup
    static bool Initialize(HWND hwndEditor);
    
    // Shutdown integration
    // Call once at IDE shutdown
    static void Shutdown();
    
    // Poll for new suggestions from GhostTextBuffer
    // Call periodically (e.g., on idle or timer)
    static void PollForSuggestions();
    
    // Check if there's an active suggestion
    static bool HasActiveSuggestion();
    
    // Accept current suggestion (Tab key)
    static void AcceptSuggestion();
    
    // Reject current suggestion (Escape key)
    static void RejectSuggestion();
    
    // Get status text for status bar
    static std::wstring GetStatusText();
    
    // Handle WM_APP messages (called from IDE WndProc)
    // Returns true if message was handled
    static bool HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Editor focus/blur handlers
    static void OnEditorFocus(HWND hwndEditor);
    static void OnEditorBlur(HWND hwndEditor);
};

} // namespace UI
} // namespace RawrXD
