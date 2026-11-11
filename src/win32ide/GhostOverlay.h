// ============================================================================
// Ghost Overlay - Inline Diff Preview for Win32 Editor
// Tab = Accept, Esc = Reject, Typing = Cancel
// ============================================================================

#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace RawrXD {
namespace UI {

enum class GhostType {
    Insert,     // Green ghost text (new code)
    Replace,    // Orange ghost text (replacement)
    Delete      // Red strikethrough (removal preview)
};

struct GhostSuggestion {
    GhostType type = GhostType::Insert;
    int line = 0;              // 0-based line index
    int column = 0;            // Character index
    std::wstring text;         // Suggested text
    std::wstring original;     // Original text (for replace)
    bool active = false;
    
    // Stale suggestion protection
    uint64_t generation_id = 0;  // Monotonically increasing ID
    
    // Multi-file support
    std::wstring filePath;     // Target file
    bool isMultiFile = false;  // True if patch spans multiple files
};

class GhostOverlay {
public:
    GhostOverlay();
    ~GhostOverlay();

    // Attach to an editor window (subclassing)
    bool Attach(HWND hEditor);
    void Detach();

    // Set/clear suggestion
    void SetSuggestion(const GhostSuggestion& suggestion);
    void ClearSuggestion();
    bool HasSuggestion() const { return m_suggestion.active; }
    const GhostSuggestion& GetSuggestion() const { return m_suggestion; }

    // Manual accept/reject (for button UI)
    void Accept();
    void Reject();

    // Get status text for status bar
    std::wstring GetStatusText() const;

private:
    static LRESULT CALLBACK SubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    void DrawGhost(HDC hdc);
    void DrawMultiLineGhost(HDC hdc, int x, int y, int lineHeight, const std::wstring& text);
    void ApplySuggestion();
    void RejectSuggestion();
    void ExpireSuggestion();  // Dismissed due to typing/navigation (not user rejection)
    POINT GetCaretPixelPos();
    int GetLineHeight(HDC hdc);

    HWND m_editor = nullptr;
    WNDPROC m_origProc = nullptr;
    GhostSuggestion m_suggestion;
    bool m_attached = false;
    
    // Animation state for fade-in
    struct AnimationState {
        uint64_t startTime = 0;
        uint32_t durationMs = 150;  // Fade-in duration
        uint8_t currentAlpha = 0;
        bool isAnimating = false;
    } m_animation;
    
    void StartAnimation();
    uint8_t CalculateCurrentAlpha();
    
    // Timer ID for animation
    static constexpr UINT_PTR kAnimationTimerId = 1001;
    static constexpr UINT kAnimationIntervalMs = 16;  // ~60fps

    // Colors
    static constexpr COLORREF kColorInsert = RGB(120, 200, 120);
    static constexpr COLORREF kColorReplace = RGB(255, 180, 80);
    static constexpr COLORREF kColorDelete = RGB(255, 100, 100);
    static constexpr COLORREF kColorMultiFile = RGB(180, 140, 255);
};

} // namespace UI
} // namespace RawrXD
