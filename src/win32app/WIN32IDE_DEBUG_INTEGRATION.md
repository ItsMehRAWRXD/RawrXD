//=============================================================================
// RawrXD Win32IDE Debug Integration Guide
// How to wire DAPIntegrationBridge into Win32IDE's message loop
//=============================================================================

/*

INTEGRATION CHECKLIST
=====================

Step 1: Include Headers
-----------------------
In Win32IDE.cpp (or your main IDE file), add:

    #include "DAPIntegrationBridge.hpp"
    #include "StatusBarGitMonitor.hpp"
    using namespace RawrXD::Win32;

Step 2: Add Member Variables
----------------------------
In your Win32IDE class or as globals:

    class Win32IDE {
        // ... existing members ...
        
        // Debug integration
        DAPIntegrationBridge* m_dapBridge = nullptr;
        StatusBarGitMonitor* m_gitMonitor = nullptr;
        
        // Debug UI handles
        HWND m_hwndCallStack = NULL;
        HWND m_hwndVariables = NULL;
        HWND m_hwndDebugToolbar = NULL;
        HWND m_hwndStatusBar = NULL;
    };

Step 3: Initialize in OnCreate
------------------------------
In your WM_CREATE handler:

    case WM_CREATE: {
        // ... existing initialization ...
        
        // Initialize DAP bridge
        m_dapBridge = new DAPIntegrationBridge(this, m_dapServer);
        if (m_dapBridge->Initialize()) {
            SetDAPBridge(m_dapBridge);
        }
        
        // Initialize git status monitoring
        if (InitializeGitStatusBar(m_hWnd)) {
            m_gitMonitor = g_gitMonitor;  // Set by InitializeGitStatusBar
        }
        
        return 0;
    }

Step 4: Cleanup in OnDestroy
----------------------------
In your WM_DESTROY handler:

    case WM_DESTROY: {
        // Cleanup debug integration
        ShutdownGitStatusBar();
        
        if (m_dapBridge) {
            m_dapBridge->Shutdown();
            delete m_dapBridge;
            m_dapBridge = nullptr;
            SetDAPBridge(nullptr);
        }
        
        PostQuitMessage(0);
        return 0;
    }

Step 5: Handle Debug Messages
-----------------------------
Add to your main WndProc:

    case WM_USER_DEBUG_EVENT: {
        // State changed - update UI
        auto state = m_dapBridge->GetState();
        UpdateDebugToolbarState(state);
        return 0;
    }
    
    case WM_USER_DEBUG_PAUSED: {
        // Process stopped - show current line, populate call stack
        DWORD threadId = (DWORD)wParam;
        m_dapBridge->UpdateCallStackPanel();
        m_dapBridge->UpdateVariablesPanel();
        m_dapBridge->ShowCurrentLine();
        return 0;
    }
    
    case WM_USER_DEBUG_CONTINUED: {
        // Process resumed - clear highlight
        ClearExecutionHighlight();
        return 0;
    }
    
    case WM_USER_GIT_STATUS_UPDATE: {
        // Git status updated - refresh status bar
        HandleGitStatusUpdate(m_hWnd, wParam, lParam);
        return 0;
    }

Step 6: Wire Debug Commands
---------------------------
In your command handler (WM_COMMAND):

    case ID_DEBUG_START: {
        DAPIntegrationBridge::LaunchConfig config;
        config.program = GetCurrentExecutablePath();
        config.workingDirectory = GetCurrentWorkingDirectory();
        config.stopOnEntry = false;
        
        if (m_dapBridge->StartDebugging(config)) {
            UpdateDebugToolbarState(Debug::DapState::Running);
        }
        return 0;
    }
    
    case ID_DEBUG_ATTACH: {
        DWORD pid = ShowProcessPickerDialog();
        if (pid != 0) {
            m_dapBridge->AttachToProcess(pid);
        }
        return 0;
    }
    
    case ID_DEBUG_STOP: {
        m_dapBridge->StopDebugging();
        return 0;
    }
    
    case ID_DEBUG_CONTINUE: {
        m_dapBridge->Continue();
        return 0;
    }
    
    case ID_DEBUG_PAUSE: {
        m_dapBridge->Pause();
        return 0;
    }
    
    case ID_DEBUG_STEP_INTO: {
        m_dapBridge->StepInto();
        return 0;
    }
    
    case ID_DEBUG_STEP_OVER: {
        m_dapBridge->StepOver();
        return 0;
    }
    
    case ID_DEBUG_STEP_OUT: {
        m_dapBridge->StepOut();
        return 0;
    }
    
    case ID_DEBUG_TOGGLE_BREAKPOINT: {
        int line = GetCurrentLineNumber();
        std::wstring file = GetCurrentFilePath();
        m_dapBridge->ToggleBreakpoint(file, line);
        return 0;
    }

Step 7: Update Status Bar
-------------------------
In your status bar update routine:

    void UpdateStatusBar() {
        // ... existing status items ...
        
        // Git branch status
        if (m_gitMonitor) {
            auto gitStatus = m_gitMonitor->GetCurrentStatus();
            std::string gitText = FormatGitStatusForDisplay(gitStatus);
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 2, (LPARAM)gitText.c_str());
        }
        
        // Debug status
        if (m_dapBridge && m_dapBridge->IsDebugging()) {
            auto state = m_dapBridge->GetState();
            const char* stateText = StateToString(state);
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)stateText);
        } else {
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)"Ready");
        }
    }

Step 8: Update Debug Toolbar
----------------------------
Enable/disable buttons based on state:

    void UpdateDebugToolbarState(Debug::DapState state) {
        bool isRunning = (state == Debug::DapState::Running);
        bool isPaused = (state == Debug::DapState::Paused);
        bool isDebugging = (state != Debug::DapState::Disconnected);
        
        // Enable/disable buttons
        EnableWindow(GetDlgItem(m_hwndDebugToolbar, ID_DEBUG_START), !isDebugging);
        EnableWindow(GetDlgItem(m_hwndDebugToolbar, ID_DEBUG_STOP), isDebugging);
        EnableWindow(GetDlgItem(m_hwndDebugToolbar, ID_DEBUG_CONTINUE), isPaused);
        EnableWindow(GetDlgItem(m_hwndDebugToolbar, ID_DEBUG_PAUSE), isRunning);
        EnableWindow(GetDlgItem(m_hwndDebugToolbar, ID_DEBUG_STEP_INTO), isPaused);
        EnableWindow(GetDlgItem(m_hwndDebugToolbar, ID_DEBUG_STEP_OVER), isPaused);
        EnableWindow(GetDlgItem(m_hwndDebugToolbar, ID_DEBUG_STEP_OUT), isPaused);
    }

Step 9: Update Call Stack Panel
-------------------------------
When stack trace is received:

    void UpdateCallStackPanel(const std::vector<Debug::StackFrame>& frames) {
        // Clear existing items
        ListView_DeleteAllItems(m_hwndCallStack);
        
        // Add new items
        for (size_t i = 0; i < frames.size(); ++i) {
            const auto& frame = frames[i];
            
            LVITEM item = {};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = (int)i;
            item.lParam = frame.id;
            
            // Column 0: Frame number
            char buf[32];
            snprintf(buf, sizeof(buf), "%zu", i);
            item.pszText = buf;
            ListView_InsertItem(m_hwndCallStack, &item);
            
            // Column 1: Function name
            ListView_SetItemText(m_hwndCallStack, i, 1, (LPSTR)frame.name.c_str());
            
            // Column 2: Source location
            std::string location = frame.source + ":" + std::to_string(frame.line);
            ListView_SetItemText(m_hwndCallStack, i, 2, (LPSTR)location.c_str());
        }
    }

Step 10: Update Variables Panel
-------------------------------
When variables are received:

    void UpdateVariablesPanel(int scopeReference, const std::vector<Debug::Variable>& vars) {
        HTREEITEM hParent = GetScopeTreeItem(scopeReference);
        if (!hParent) return;
        
        // Clear existing children
        TreeView_DeleteChildren(m_hwndVariables, hParent);
        
        // Add new variables
        for (const auto& var : vars) {
            TVINSERTSTRUCT tvis = {};
            tvis.hParent = hParent;
            tvis.hInsertAfter = TVI_LAST;
            
            std::string text = var.name + " = " + var.value;
            if (!var.type.empty()) {
                text += " (" + var.type + ")";
            }
            
            tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
            tvis.item.pszText = (LPSTR)text.c_str();
            tvis.item.lParam = var.variablesReference;
            
            HTREEITEM hItem = TreeView_InsertItem(m_hwndVariables, &tvis);
            
            // If expandable, add a dummy child for lazy loading
            if (var.isExpandable) {
                TVINSERTSTRUCT dummy = {};
                dummy.hParent = hItem;
                dummy.item.mask = TVIF_TEXT;
                dummy.item.pszText = (LPSTR)"Loading...";
                TreeView_InsertItem(m_hwndVariables, &dummy);
            }
        }
    }

RESOURCE DEFINITIONS
====================

Add to your resource.h:

    #define ID_DEBUG_START          40010
    #define ID_DEBUG_ATTACH         40011
    #define ID_DEBUG_STOP           40012
    #define ID_DEBUG_CONTINUE       40013
    #define ID_DEBUG_PAUSE          40014
    #define ID_DEBUG_STEP_INTO      40015
    #define ID_DEBUG_STEP_OVER      40016
    #define ID_DEBUG_STEP_OUT       40017
    #define ID_DEBUG_TOGGLE_BREAKPOINT 40018

Add to your .rc file:

    // Debug menu
    POPUP "&Debug"
    BEGIN
        MENUITEM "&Start Debugging\tF5",      ID_DEBUG_START
        MENUITEM "&Attach to Process...",   ID_DEBUG_ATTACH
        MENUITEM SEPARATOR
        MENUITEM "&Stop Debugging\tShift+F5", ID_DEBUG_STOP
        MENUITEM SEPARATOR
        MENUITEM "&Continue\tF5",            ID_DEBUG_CONTINUE
        MENUITEM "&Pause\tCtrl+Break",        ID_DEBUG_PAUSE
        MENUITEM SEPARATOR
        MENUITEM "Step &Into\tF11",           ID_DEBUG_STEP_INTO
        MENUITEM "Step O&ver\tF10",          ID_DEBUG_STEP_OVER
        MENUITEM "Step O&ut\tShift+F11",     ID_DEBUG_STEP_OUT
        MENUITEM SEPARATOR
        MENUITEM "Toggle &Breakpoint\tF9",  ID_DEBUG_TOGGLE_BREAKPOINT
    END

BUILD INTEGRATION
=================

Add to your CMakeLists.txt or build script:

    # Debug integration sources
    set(DEBUG_INTEGRATION_SOURCES
        src/debug/DebugBackend.cpp
        src/debug/DebugBridge.cpp
        src/debug/DAPAdapter.cpp
        src/debug/DapService.cpp
        src/win32app/DAPIntegrationBridge.cpp
        src/win32app/StatusBarGitMonitor.cpp
        src/utils/GitHelper.cpp
    )
    
    target_sources(Win32IDE PRIVATE ${DEBUG_INTEGRATION_SOURCES})
    
    target_link_libraries(Win32IDE PRIVATE
        dbghelp.lib
        kernel32.lib
        user32.lib
    )

TROUBLESHOOTING
===============

Issue: "DapService not found"
- Check that DapService.cpp is compiled and linked
- Verify include path includes src/debug/

Issue: "Git status not updating"
- Ensure git.exe is in PATH
- Check that StatusBarGitMonitor::Initialize succeeded
- Verify WM_USER_GIT_STATUS_UPDATE is handled

Issue: "Debug commands not working"
- Check that DAPIntegrationBridge::Initialize returned true
- Verify command IDs match between menu and handler
- Ensure DebugBackend.cpp is linked with dbghelp.lib

Issue: "UI freezes during debugging"
- Make sure all DapService callbacks use PostMessage, not direct calls
- Check that DebugBridge events are processed on UI thread
- Verify no blocking calls in message handlers

Issue: "Call stack not showing"
- Ensure WM_USER_DEBUG_PAUSED is received
- Check that requestStackTrace is called in OnStopped callback
- Verify ListView control is created with proper columns

*/
