#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>

// Forward declarations for a generic docking framework.
// In a real implementation, these would be the types from the chosen library.
class CDockingManager;
class CPane;

class DockingPaneManager
{
public:
    DockingPaneManager();
    ~DockingPaneManager();

    // Initialize the docking manager and attach it to the main frame window.
    bool Initialize(HWND hWndMain);

    // Create and dock a new pane.
    CPane* CreatePane(HWND hWnd, const std::wstring& title, DWORD dwStyle);

    // Updates the layout of the panes, typically called on WM_SIZE.
    void RecalculateLayout();

    // Show or hide a pane by its window handle.
    void ShowPane(HWND hWnd, bool bShow);

private:
    // Pointer to the main docking manager instance.
    std::unique_ptr<CDockingManager> m_pDockManager;

    // The main frame window.
    HWND m_hWndMain;
};
