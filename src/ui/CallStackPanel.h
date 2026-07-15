// CallStackPanel.h
// Phase 24: The Cockpit - Call Stack Visualization
// ============================================================================
// Displays the call stack during debugging with navigation
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Debugger { struct StackFrame; }

namespace UI {

// ============================================================================
// Call Stack Panel Configuration
// ============================================================================
struct CallStackPanelConfig {
    int rowHeight = 20;
    int iconWidth = 20;
    COLORREF backgroundColor = RGB(255, 255, 255);
    COLORREF textColor = RGB(0, 0, 0);
    COLORREF selectedColor = RGB(0, 120, 215);
    COLORREF selectedTextColor = RGB(255, 255, 255);
    COLORREF framePointerColor = RGB(255, 200, 0);  // Yellow for current frame
    wchar_t fontName[32] = L"Consolas";
    int fontSize = 10;
};

// ============================================================================
// Call Stack Display Frame
// ============================================================================
struct CallStackDisplayFrame {
    uint32_t frameNumber;
    std::wstring functionName;
    std::wstring moduleName;
    std::wstring filePath;
    uint32_t lineNumber;
    uint64_t address;
    bool isCurrentFrame = false;
};

// ============================================================================
// Call Stack Panel
// ============================================================================
class CallStackPanel {
public:
    using FrameSelectedCallback = std::function<void(size_t frameIndex)>;

    CallStackPanel();
    ~CallStackPanel();

    // Initialization
    bool Initialize(HWND parentWindow);
    void Shutdown();

    // Configuration
    void SetConfig(const CallStackPanelConfig& config);

    // Data updates
    void UpdateCallStack(const std::vector<Debugger::StackFrame>& frames);
    void ClearCallStack();
    void SetCurrentFrame(size_t frameIndex);

    // Rendering
    void Render(HDC hdc, const RECT& panelRect);
    void Invalidate();

    // Event handling
    void SetFrameSelectedCallback(FrameSelectedCallback callback);
    bool OnMouseClick(int x, int y);
    bool OnMouseDoubleClick(int x, int y);
    bool OnKeyDown(WPARAM keyCode);

    // Sizing
    SIZE GetPreferredSize() const;
    void SetSize(int width, int height);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace UI
} // namespace RawrXD
