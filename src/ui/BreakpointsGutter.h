// BreakpointsGutter.h
// Phase 24: The Cockpit - Breakpoint Margin Rendering
// ============================================================================
// Renders breakpoint indicators in the editor gutter
// Handles click events to toggle breakpoints
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace UI {

// ============================================================================
// Breakpoint Visual State
// ============================================================================
enum class BreakpointVisualState {
    None,           // No breakpoint
    Enabled,        // Red circle - active breakpoint
    Disabled,       // Hollow circle - disabled breakpoint
    Hit,            // Highlighted - currently stopped here
};

// ============================================================================
// Breakpoint Gutter Configuration
// ============================================================================
struct BreakpointGutterConfig {
    int width = 40;                     // Gutter width in pixels
    int breakpointSize = 14;            // Diameter of breakpoint circle
    COLORREF enabledColor = RGB(255, 0, 0);      // Red
    COLORREF disabledColor = RGB(128, 128, 128); // Gray
    COLORREF hitColor = RGB(255, 255, 0);        // Yellow
    COLORREF backgroundColor = RGB(240, 240, 240); // Light gray
    COLORREF borderColor = RGB(200, 200, 200);   // Border
};

// ============================================================================
// Breakpoint Gutter
// ============================================================================
class BreakpointsGutter {
public:
    using BreakpointToggleCallback = std::function<void(const std::wstring& filePath, uint32_t lineNumber)>;

    BreakpointsGutter();
    ~BreakpointsGutter();

    // Initialization
    bool Initialize(HWND parentWindow);
    void Shutdown();

    // Configuration
    void SetConfig(const BreakpointGutterConfig& config);
    const BreakpointGutterConfig& GetConfig() const;

    // Breakpoint state management
    virtual void SetBreakpointState(uint32_t lineNumber, BreakpointVisualState state);
    virtual void ClearBreakpointState(uint32_t lineNumber);
    virtual void ClearAllBreakpoints();
    virtual void SetCurrentLine(uint32_t lineNumber);  // IP indicator
    virtual void ClearCurrentLine();

    // Rendering
    void Render(HDC hdc, const RECT& gutterRect, int firstVisibleLine, int linesVisible, int lineHeight);
    void Invalidate();

    // Event handling
    void SetBreakpointToggleCallback(BreakpointToggleCallback callback);
    bool OnMouseClick(int x, int y, const std::wstring& currentFile);
    bool OnMouseMove(int x, int y);
    bool OnMouseLeave();

    // Hit testing
    int LineFromPoint(int y, int firstVisibleLine, int lineHeight) const;
    bool IsInGutter(int x) const;

    // Sizing
    int GetWidth() const;
    void SetWidth(int width);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Breakpoint Gutter Window Procedure
// ============================================================================
LRESULT CALLBACK BreakpointGutterWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

} // namespace UI
} // namespace RawrXD
