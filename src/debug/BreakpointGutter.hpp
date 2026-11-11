// BreakpointGutter.hpp
// Phase 24B: Visual Breakpoint Management
// ============================================================================
// Click-to-toggle breakpoints with IDE↔Debugger sync
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <functional>

namespace RawrXD {
namespace Debug {
namespace UI {

// ============================================================================
// Breakpoint Structure
// ============================================================================
struct BreakpointInfo {
    uint32_t id = 0;
    std::string filePath;
    uint32_t line;
    bool verified = false;
    bool enabled = true;
    std::string condition;
    std::string message;  // Error message if unverified
};

// ============================================================================
// Breakpoint Gutter
// ============================================================================
class BreakpointGutter {
public:
    BreakpointGutter();
    ~BreakpointGutter();

    // Initialization
    bool Create(HWND hwndParent, int width = 40);
    void Destroy();
    
    // Positioning
    void SetPosition(int x, int y, int height);
    void SetLineHeight(int lineHeight);
    void SetScrollOffset(int scrollOffset);
    
    // Breakpoint Management
    void ToggleBreakpoint(uint32_t line);
    void AddBreakpoint(const BreakpointInfo& bp);
    void RemoveBreakpoint(uint32_t line);
    void RemoveBreakpointById(uint32_t breakpointId);
    void UpdateBreakpoint(const BreakpointInfo& bp);
    void ClearAllBreakpoints();
    
    // Query
    bool HasBreakpoint(uint32_t line) const;
    BreakpointInfo GetBreakpoint(uint32_t line) const;
    std::vector<BreakpointInfo> GetAllBreakpoints() const;
    
    // Visual State
    void SetCurrentLine(uint32_t line);  // Yellow arrow (execution point)
    void ClearCurrentLine();
    void SetHoveredLine(uint32_t line);  // Mouse hover feedback
    void ClearHoveredLine();
    
    // Rendering
    void Invalidate();
    void Render(HDC hdc);
    
    // Event Handling
    void OnMouseMove(int x, int y);
    void OnMouseLeave();
    bool OnMouseClick(int x, int y);  // Returns true if breakpoint toggled
    void OnContextMenu(int x, int y);  // Right-click menu
    
    // Callbacks
    std::function<void(uint32_t line, bool added)> onBreakpointToggled;
    std::function<void(uint32_t line)> onBreakpointEnabledChanged;
    std::function<void(uint32_t line)> onBreakpointConditionEdit;
    std::function<void(uint32_t line)> onGoToBreakpoint;
    
    // Sync with Debugger
    void SyncWithDebugger(class DapService* service);
    void OnDebuggerBreakpointVerified(uint32_t breakpointId, bool verified);
    void OnDebuggerBreakpointHit(uint32_t line);

private:
    HWND hwnd_ = nullptr;
    HWND hwndParent_ = nullptr;
    
    // Layout
    int x_ = 0, y_ = 0;
    int width_ = 40;
    int height_ = 0;
    int lineHeight_ = 20;
    int scrollOffset_ = 0;
    
    // Breakpoints
    std::map<uint32_t, BreakpointInfo> breakpoints_;
    uint32_t nextBreakpointId_ = 1;
    
    // Visual State
    uint32_t currentLine_ = 0;   // Yellow arrow (0 = none)
    uint32_t hoveredLine_ = 0;   // Hover highlight (0 = none)
    
    // Drawing
    static constexpr int MARGIN_LEFT = 4;
    static constexpr int MARGIN_RIGHT = 4;
    static constexpr int DOT_SIZE = 12;
    
    void DrawBreakpoint(HDC hdc, int y, const BreakpointInfo& bp);
    void DrawCurrentLineIndicator(HDC hdc, int y);
    void DrawHoverIndicator(HDC hdc, int y);
    
    uint32_t LineFromY(int y) const;
    int YFromLine(uint32_t line) const;
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
};

// ============================================================================
// Breakpoint Manager
// ============================================================================
class BreakpointManager {
public:
    static BreakpointManager& instance();
    
    // File-specific breakpoints
    void SetBreakpointsForFile(const std::string& filePath, 
                                const std::vector<BreakpointInfo>& breakpoints);
    std::vector<BreakpointInfo> GetBreakpointsForFile(const std::string& filePath) const;
    
    // Global operations
    void ClearAllBreakpoints();
    void DisableAllBreakpoints();
    void EnableAllBreakpoints();
    
    // Persistence
    bool SaveBreakpoints(const std::string& projectPath);
    bool LoadBreakpoints(const std::string& projectPath);
    
    // Sync
    void SyncToDebugger(class DapService* service);
    void SyncFromDebugger(const std::vector<BreakpointInfo>& debuggerBreakpoints);
    
    // Callbacks
    std::function<void(const std::string& file, uint32_t line, bool added)> onBreakpointChanged;

private:
    BreakpointManager() = default;
    
    std::map<std::string, std::vector<BreakpointInfo>> fileBreakpoints_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Editor Integration Helpers
// ============================================================================

// Call this from your editor's WM_LBUTTONDOWN in the gutter area
bool HandleGutterClick(HWND hwndEditor, int x, int y, BreakpointGutter* gutter);

// Call this from your editor's paint routine
void RenderBreakpointGutter(HDC hdc, const BreakpointGutter* gutter, 
                            int firstLine, int lastLine);

// Context menu for breakpoint options
void ShowBreakpointContextMenu(HWND hwnd, int x, int y, uint32_t line,
                                const BreakpointInfo& bp);

} // namespace UI
} // namespace Debug
} // namespace RawrXD
