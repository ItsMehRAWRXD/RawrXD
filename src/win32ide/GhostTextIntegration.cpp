// ============================================================================
// GhostTextIntegration.cpp - Bridge ghost_text_engine to GhostOverlay (Day 2)
// ============================================================================
// Connects the thread-safe GhostTextBuffer (inference thread) to the
// UI GhostOverlay (main thread) via WM_APP messages.
//
// DAY 2 DELIVERABLE:
// - Poll GhostTextBuffer for new suggestions
// - Convert UTF-8 to wide string
// - Push to GhostOverlay via SetSuggestion()
// - Handle WM_APP_GHOST_* messages in IDE message loop
// ============================================================================

#include "GhostTextIntegration.h"
#include "GhostOverlay.h"
#include "../ghost_text_engine.h"
#include <string>

namespace RawrXD {
namespace UI {

// Global overlay instance (managed by IDE)
static GhostOverlay* g_ghostOverlay = nullptr;

// ============================================================================
// GhostTextIntegration Implementation
// ============================================================================

bool GhostTextIntegration::Initialize(HWND hwndEditor) {
    if (!hwndEditor) return false;
    
    // Create overlay if not exists
    if (!g_ghostOverlay) {
        g_ghostOverlay = new GhostOverlay();
    }
    
    // Attach to editor window
    if (!g_ghostOverlay->Attach(hwndEditor)) {
        return false;
    }
    
    // Reset buffer state
    GhostText_Reset();
    
    return true;
}

void GhostTextIntegration::Shutdown() {
    if (g_ghostOverlay) {
        g_ghostOverlay->Detach();
        delete g_ghostOverlay;
        g_ghostOverlay = nullptr;
    }
    
    GhostText_Shutdown();
}

void GhostTextIntegration::PollForSuggestions() {
    if (!g_ghostOverlay) return;
    
    // Check if new suggestion arrived from inference thread
    auto& buffer = GhostTextBuffer::Instance();
    if (buffer.HasNewData()) {
        std::string utf8Text = buffer.GetSuggestion();
        if (!utf8Text.empty()) {
            // Convert UTF-8 to wide string
            int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8Text.c_str(), -1, nullptr, 0);
            if (wideLen > 0) {
                std::wstring wideText(wideLen - 1, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, utf8Text.c_str(), -1, &wideText[0], wideLen);
                
                // Create suggestion with generation ID for stale protection
                GhostSuggestion suggestion;
                suggestion.type = GhostType::Insert;
                suggestion.text = wideText;
                suggestion.active = true;
                suggestion.generation_id = buffer.GetCurrentGenerationId();
                
                // Get cursor position from buffer
                int line, column;
                buffer.GetCursorPosition(line, column);
                suggestion.line = line;
                suggestion.column = column;
                
                g_ghostOverlay->SetSuggestion(suggestion);
            }
        }
    }
}

bool GhostTextIntegration::HasActiveSuggestion() {
    return g_ghostOverlay && g_ghostOverlay->HasSuggestion();
}

void GhostTextIntegration::AcceptSuggestion() {
    if (g_ghostOverlay) {
        g_ghostOverlay->Accept();
    }
}

void GhostTextIntegration::RejectSuggestion() {
    if (g_ghostOverlay) {
        g_ghostOverlay->Reject();
    }
}

std::wstring GhostTextIntegration::GetStatusText() {
    if (g_ghostOverlay) {
        return g_ghostOverlay->GetStatusText();
    }
    return L"";
}

// ============================================================================
// WM_APP Message Handlers (called from IDE WndProc)
// ============================================================================

bool GhostTextIntegration::HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)hwnd;
    (void)wParam;
    (void)lParam;
    
    switch (msg) {
    case WM_GHOST_TEXT_UPDATE:
        // New suggestion available - poll and display
        PollForSuggestions();
        return true; // Handled
        
    case WM_GHOST_TEXT_CLEAR:
        // Clear current suggestion
        if (g_ghostOverlay) {
            g_ghostOverlay->ClearSuggestion();
        }
        return true; // Handled
        
    case WM_GHOST_TEXT_ACCEPT:
        // Accept current suggestion
        AcceptSuggestion();
        return true; // Handled
        
    case WM_GHOST_TEXT_DISMISS:
        // Dismiss current suggestion
        RejectSuggestion();
        return true; // Handled
    }
    
    return false; // Not handled
}

// ============================================================================
// IDE Integration Helpers
// ============================================================================

void GhostTextIntegration::OnEditorFocus(HWND hwndEditor) {
    // Re-attach if needed
    if (g_ghostOverlay && !g_ghostOverlay->HasSuggestion()) {
        // Clear any stale suggestions
        GhostText_Dismiss();
    }
    (void)hwndEditor;
}

void GhostTextIntegration::OnEditorBlur(HWND hwndEditor) {
    // Optionally hide ghost text when editor loses focus
    (void)hwndEditor;
}

} // namespace UI
} // namespace RawrXD
