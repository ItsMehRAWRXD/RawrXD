//=============================================================================
// RawrXD Breakpoint Manager Panel
// Centralized breakpoint management for Win32IDE
// Integrates with DAPIntegrationBridge
//=============================================================================
#pragma once

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Win32 {

//=============================================================================
// Breakpoint Info Structure
//=============================================================================

struct BreakpointInfo {
    int id = 0;                    // DAP breakpoint ID
    std::wstring filePath;         // Source file path
    std::wstring fileName;         // Just the filename for display
    int line = 0;                  // Line number (1-based)
    uint64_t address = 0;          // Memory address (if resolved)
    bool enabled = true;           // Is breakpoint enabled?
    bool verified = false;         // Has debugger verified it?
    std::string condition;         // Conditional expression
    int hitCount = 0;              // Times hit
    int hitCondition = 0;          // Break when hit count == N
    std::string hitConditionExpr;  // "== 5", ">= 10", etc.
};

//=============================================================================
// Breakpoint Manager Callbacks
//=============================================================================

struct IBreakpointManagerCallbacks {
    virtual ~IBreakpointManagerCallbacks() = default;
    
    // Called when user toggles breakpoint enable/disable
    virtual void OnBreakpointToggled(int breakpointId, bool enabled) = 0;
    
    // Called when user deletes a breakpoint
    virtual void OnBreakpointDeleted(int breakpointId) = 0;
    
    // Called when user navigates to breakpoint (double-click)
    virtual void OnBreakpointNavigate(const std::wstring& file, int line) = 0;
    
    // Called when user edits breakpoint condition
    virtual void OnBreakpointConditionChanged(int breakpointId, const std::string& condition) = 0;
    
    // Called when user clears all breakpoints
    virtual void OnClearAllBreakpoints() = 0;
};

//=============================================================================
// Breakpoint Manager Panel
// Win32 ListView-based breakpoint management UI
//=============================================================================

class BreakpointManagerPanel {
public:
    BreakpointManagerPanel();
    ~BreakpointManagerPanel();
    
    // Window creation
    bool Create(HWND hwndParent, HINSTANCE hInstance, int x, int y, int width, int height);
    void Destroy();
    
    // Window handle access
    HWND GetHwnd() const { return m_hwnd; }
    bool IsWindow() const { return m_hwnd != NULL && ::IsWindow(m_hwnd); }
    
    // Callbacks
    void SetCallbacks(IBreakpointManagerCallbacks* callbacks);
    
    // Breakpoint management
    void AddBreakpoint(const BreakpointInfo& bp);
    void UpdateBreakpoint(const BreakpointInfo& bp);
    void RemoveBreakpoint(int breakpointId);
    void ClearAllBreakpoints();
    
    // Bulk update (e.g., after DAP sync)
    void SetBreakpoints(const std::vector<BreakpointInfo>& breakpoints);
    
    // Get selected breakpoint
    int GetSelectedBreakpointId() const;
    BreakpointInfo GetBreakpointInfo(int id) const;
    
    // Enable/disable
    void ToggleBreakpointEnabled(int breakpointId);
    void SetBreakpointEnabled(int breakpointId, bool enabled);
    
    // Navigation
    void SelectBreakpoint(int breakpointId);
    void NavigateToSelected();
    
    // UI updates
    void Refresh();
    void UpdateColumnWidths();
    
    // Enable/disable all
    void EnableAll();
    void DisableAll();
    
    // Hit count update (called when breakpoint is hit)
    void UpdateHitCount(int breakpointId, int hitCount);

private:
    // Window procedure
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // ListView handlers
    void OnItemChanged(NMLISTVIEW* pnmv);
    void OnDoubleClick(NMITEMACTIVATE* pnmia);
    void OnRightClick(NMITEMACTIVATE* pnmia);
    void OnKeyDown(NMLVKEYDOWN* pnmkd);
    void OnColumnClick(NMLISTVIEW* pnmv);
    
    // Context menu
    void ShowContextMenu(int itemIndex, POINT pt);
    
    // Helpers
    int FindBreakpointIndex(int breakpointId) const;
    void UpdateListViewItem(int index, const BreakpointInfo& bp);
    std::wstring FormatBreakpointText(const BreakpointInfo& bp, int column) const;
    int AddListViewItem(const BreakpointInfo& bp);
    
    // Sorting
    void SortItems(int column);
    static int CALLBACK CompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
    
    // Window handles
    HWND m_hwnd = NULL;
    HWND m_hwndListView = NULL;
    HWND m_hwndParent = NULL;
    
    // State
    HINSTANCE m_hInstance = NULL;
    IBreakpointManagerCallbacks* m_callbacks = nullptr;
    std::vector<BreakpointInfo> m_breakpoints;
    int m_sortColumn = -1;
    bool m_sortAscending = true;
    
    // Icons
    HICON m_hIconEnabled = NULL;
    HICON m_hIconDisabled = NULL;
    HICON m_iconVerified = NULL;
    HICON m_iconUnverified = NULL;
    HIMAGELIST m_hImageList = NULL;
    
    // Constants
    static constexpr int COL_ENABLED = 0;
    static constexpr int COL_FILE = 1;
    static constexpr int COL_LINE = 2;
    static constexpr int COL_CONDITION = 3;
    static constexpr int COL_HITCOUNT = 4;
    static constexpr int COL_ADDRESS = 5;
};

//=============================================================================
// Breakpoint Manager Dialog
// Modal dialog for editing breakpoint properties
//=============================================================================

class BreakpointPropertiesDialog {
public:
    static bool Show(HWND hwndParent, BreakpointInfo& bp);
    
private:
    static INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
    static void InitializeDialog(HWND hwndDlg, BreakpointInfo* pbp);
    static void SaveChanges(HWND hwndDlg, BreakpointInfo* pbp);
};

//=============================================================================
// Breakpoint Manager Factory
// Singleton access for Win32IDE integration
//=============================================================================

class BreakpointManagerFactory {
public:
    static BreakpointManagerPanel* GetPanel();
    static void DestroyPanel();
    
private:
    static BreakpointManagerPanel* s_panel;
};

} // namespace Win32
} // namespace RawrXD
