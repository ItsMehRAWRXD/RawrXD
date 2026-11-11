#pragma once
// ============================================================================
// RawrXD_IDE_GhostText_Engine.hpp
// Ghost Text / Inline Completion Engine - Header
// Zero dependencies, pure Win32 GDI + Sovereign Runtime Integration
// ============================================================================

#include <windows.h>
#include <atomic>
#include <string>

// Forward declarations
namespace RawrXD {
namespace IDE {
    class SovereignBridge;
    class SovereignSharedMemoryBridge;
}
}

// Ghost suggestion data
struct GhostSuggestion {
    std::string text;           // The suggested text
    int triggerLine;            // Line where suggestion was triggered
    int triggerCol;             // Column where suggestion starts
    bool isMultiLine;           // Does suggestion contain newlines?
    DWORD timestamp;            // When suggestion was received
    float confidence;           // 0.0-1.0 confidence score
    bool visible;               // Currently showing?
};

// Ghost Text Engine - Native Win32 Implementation
class GhostTextEngine {
public:
    GhostTextEngine(HWND hwndEditor);
    ~GhostTextEngine();

    // Initialize the engine (call after construction)
    bool Initialize();

    // Shutdown the engine (call before destruction)
    void Shutdown();

    // Check if engine is ready for inference
    bool IsAvailable() const;

    // Called when user types — requests suggestion asynchronously
    void OnTextChanged(const char* buffer, int cursorLine, int cursorCol);

    // Called when suggestion arrives from model (thread-safe)
    void OnSuggestionReceived(const std::string& text, int line, int col, float confidence);

    // Accept suggestion (Tab key) - returns true if accepted
    bool AcceptSuggestion(std::string& outText);

    // Partial accept — word by word (Ctrl+Right) - returns true if accepted
    bool AcceptPartial(std::string& outText);

    // Dismiss suggestion (Esc or typing mismatch)
    void HideSuggestion();
    void LogDismissal();

    // Check if suggestion should be dismissed (user typed something else)
    void CheckDismiss(const char* currentLine, int cursorCol);

    // Paint ghost text into editor DC
    void PaintGhostText(HDC hdc, const RECT& editorRect,
                        int lineHeight, int charWidth,
                        int scrollX, int scrollY,
                        int cursorScreenX, int cursorScreenY);

    // Handle key events - returns true if consumed
    bool HandleKey(WPARAM key);

    // Check if ghost text is currently active
    bool IsActive() const { return m_active; }

    // Get current suggestion
    const GhostSuggestion& GetCurrent() const { return m_current; }

    // Handle async inference result (called from UI thread via PostMessage)
    void HandleInferenceResult(const std::string& text, int line, int col, float confidence);

private:
    HWND m_hwnd;
    GhostSuggestion m_current;
    bool m_active;
    DWORD m_lastRequest;
    RawrXD::IDE::SovereignBridge* m_bridge;
    RawrXD::IDE::SovereignSharedMemoryBridge* m_shmBridge;
    std::atomic<bool> m_requestInFlight{false};
    bool m_useSharedMemory;

    std::string ExtractContext(const char* buffer, int cursorLine, int cursorCol);
    void RequestSuggestion(const std::string& context, int line, int col);
    void InvalidateGhostRegion();
};

// Custom message for async inference results
#define WM_GHOST_SUGGESTION (WM_USER + 0x1000)
