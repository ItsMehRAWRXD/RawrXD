// Win32IDE_CommandRouter.cpp
// Command router that connects menu IDs to handler functions
// This is the glue that makes menus actually work

#include "../Win32IDE.h"
#include "Win32IDE_Resource.h"
#include "Win32IDE_Helpers.h"

// External handler functions from Win32IDE_MenuHandlers.cpp
extern void OnFileNewProject();
extern void OnFileOpenProject();
extern void OnFileSaveProject();
extern void OnBuildCompile();
extern void OnBuildRun();
extern void OnBuildDebug();
extern void OnBuildClean();
extern void OnToolsAnalyze();
extern void OnToolsPatch();
extern void OnToolsOptions();

// =============================================================================
// COMMAND ROUTER
// =============================================================================

bool HandleMenuCommand(int commandId) {
    switch (commandId) {
    // File Menu
    case ID_FILE_NEW_PROJECT:
        OnFileNewProject();
        return true;
        
    case ID_FILE_OPEN_PROJECT:
        OnFileOpenProject();
        return true;
        
    case ID_FILE_SAVE_PROJECT:
        OnFileSaveProject();
        return true;
        
    case ID_FILE_EXIT:
        // Send WM_CLOSE to main window
        extern HWND g_hWndMain;
        if (g_hWndMain) {
            PostMessage(g_hWndMain, WM_CLOSE, 0, 0);
        }
        return true;
        
    // Edit Menu
    case ID_EDIT_UNDO:
        // TODO: Implement undo
        MessageBox(nullptr, L"Undo not yet implemented", L"RawrXD IDE", MB_OK);
        return true;
        
    case ID_EDIT_REDO:
        // TODO: Implement redo
        MessageBox(nullptr, L"Redo not yet implemented", L"RawrXD IDE", MB_OK);
        return true;
        
    case ID_EDIT_CUT:
        // Send WM_CUT to editor
        {
            extern HWND g_hWndEditor;
            if (g_hWndEditor) {
                SendMessage(g_hWndEditor, WM_CUT, 0, 0);
            }
        }
        return true;
        
    case ID_EDIT_COPY:
        // Send WM_COPY to editor
        {
            extern HWND g_hWndEditor;
            if (g_hWndEditor) {
                SendMessage(g_hWndEditor, WM_COPY, 0, 0);
            }
        }
        return true;
        
    case ID_EDIT_PASTE:
        // Send WM_PASTE to editor
        {
            extern HWND g_hWndEditor;
            if (g_hWndEditor) {
                SendMessage(g_hWndEditor, WM_PASTE, 0, 0);
            }
        }
        return true;
        
    // Build Menu
    case ID_BUILD_COMPILE:
        OnBuildCompile();
        return true;
        
    case ID_BUILD_RUN:
        OnBuildRun();
        return true;
        
    case ID_BUILD_DEBUG:
        OnBuildDebug();
        return true;
        
    case ID_BUILD_CLEAN:
        OnBuildClean();
        return true;
        
    // Tools Menu
    case ID_TOOLS_ANALYZE:
        OnToolsAnalyze();
        return true;
        
    case ID_TOOLS_PATCH:
        OnToolsPatch();
        return true;
        
    case ID_TOOLS_OPTIONS:
        OnToolsOptions();
        return true;
        
    // View Menu
    case ID_VIEW_OUTPUT:
        // Toggle output window visibility
        {
            extern HWND g_hWndOutput;
            if (g_hWndOutput) {
                BOOL visible = IsWindowVisible(g_hWndOutput);
                ShowWindow(g_hWndOutput, visible ? SW_HIDE : SW_SHOW);
            }
        }
        return true;
        
    case ID_VIEW_PROJECT:
        // Toggle project panel visibility
        // TODO: Implement project panel toggle
        MessageBox(nullptr, L"Project panel toggle not yet implemented", L"RawrXD IDE", MB_OK);
        return true;
        
    default:
        return false; // Not handled
    }
}

// =============================================================================
// WINDOW MESSAGE HANDLER
// =============================================================================

LRESULT CALLBACK Win32IDECommandHandler(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);
            
            // Try to handle the command
            if (HandleMenuCommand(wmId)) {
                return 0; // Handled
            }
        }
        break;
        
    case WM_INITMENU:
        // Update menu states before showing
        {
            HMENU hMenu = (HMENU)wParam;
            
            // Enable/disable Run menu based on whether executable exists
            BOOL hasExe = IsBuildOutputAvailable() ? TRUE : FALSE;
            EnableMenuItem(hMenu, ID_BUILD_RUN, MF_BYCOMMAND | (hasExe ? MF_ENABLED : MF_GRAYED));
        }
        return 0;
    }
    
    return DefWindowProc(hWnd, message, wParam, lParam);
}

// =============================================================================
// INITIALIZATION
// =============================================================================

void InitializeCommandRouter() {
    // Set initial menu states
    EnableMenuItemByID(ID_BUILD_RUN, FALSE);  // Disable Run until built
}
