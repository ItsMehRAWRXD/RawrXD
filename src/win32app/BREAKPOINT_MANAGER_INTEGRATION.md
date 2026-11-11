//=============================================================================
// RawrXD Breakpoint Manager Integration Guide
// How to wire BreakpointManagerPanel into Win32IDE
//=============================================================================

/*

OVERVIEW
========

The BreakpointManagerPanel provides a centralized view of all breakpoints with:
- List of all breakpoints with file, line, condition, hit count
- Enable/disable individual breakpoints (checkbox)
- Enable/disable all breakpoints
- Delete individual or all breakpoints
- Navigate to breakpoint source (double-click)
- Edit breakpoint conditions
- Sort by any column
- Context menu for quick actions

INTEGRATION STEPS
=================

Step 1: Add to Build
--------------------

Add to your CMakeLists.txt or build script:

    set(BREAKPOINT_MANAGER_SOURCES
        src/win32app/BreakpointManagerPanel.cpp
        src/win32app/BreakpointPropertiesDialog.cpp
    )
    
    target_sources(Win32IDE PRIVATE ${BREAKPOINT_MANAGER_SOURCES})

Step 2: Include Headers
------------------------

In Win32IDE.h or your main header:

    #include "BreakpointManagerPanel.hpp"
    using namespace RawrXD::Win32;

Step 3: Add Member Variable
-----------------------------

In your Win32IDE class:

    class Win32IDE {
        // ... existing members ...
        
        // Breakpoint manager
        BreakpointManagerPanel* m_breakpointManager = nullptr;
        HWND m_hwndBreakpointPanel = NULL;
    };

Step 4: Create Panel
--------------------

In your initialization (e.g., when creating dockable panels):

    void Win32IDE::CreateBreakpointPanel() {
        // Create as child of dockable pane or main window
        m_breakpointManager = BreakpointManagerFactory::GetPanel();
        
        // Get panel size from parent
        RECT rc;
        GetClientRect(m_hwndParentPane, &rc);
        
        if (m_breakpointManager->Create(m_hwndParentPane, m_hInstance, 
                                          0, 0, rc.right, rc.bottom)) {
            m_hwndBreakpointPanel = m_breakpointManager->GetHwnd();
            
            // Setup callbacks
            m_breakpointManager->SetCallbacks(this);
        }
    }

Step 5: Implement Callbacks
---------------------------

Make Win32IDE inherit from IBreakpointManagerCallbacks:

    class Win32IDE : public IBreakpointManagerCallbacks {
        // ... existing declarations ...
        
        // IBreakpointManagerCallbacks implementation
        void OnBreakpointToggled(int breakpointId, bool enabled) override;
        void OnBreakpointDeleted(int breakpointId) override;
        void OnBreakpointNavigate(const std::wstring& file, int line) override;
        void OnBreakpointConditionChanged(int breakpointId, const std::string& condition) override;
        void OnClearAllBreakpoints() override;
    };

Implementation:

    void Win32IDE::OnBreakpointToggled(int breakpointId, bool enabled) {
        // Forward to DAPIntegrationBridge
        if (m_dapBridge) {
            m_dapBridge->SetBreakpointEnabled(breakpointId, enabled);
        }
        
        // Update editor gutter
        UpdateBreakpointGutter(breakpointId, enabled);
    }
    
    void Win32IDE::OnBreakpointDeleted(int breakpointId) {
        // Forward to DAPIntegrationBridge
        if (m_dapBridge) {
            // Get breakpoint info first
            auto bp = m_breakpointManager->GetBreakpointInfo(breakpointId);
            m_dapBridge->ClearBreakpoint(bp.filePath, bp.line);
        }
        
        // Remove from panel
        m_breakpointManager->RemoveBreakpoint(breakpointId);
        
        // Update editor gutter
        RemoveBreakpointFromGutter(breakpointId);
    }
    
    void Win32IDE::OnBreakpointNavigate(const std::wstring& file, int line) {
        // Open file in editor
        OpenFile(file);
        
        // Go to line
        GoToLine(line);
        
        // Center the line
        CenterEditorOnLine(line);
    }
    
    void Win32IDE::OnBreakpointConditionChanged(int breakpointId, const std::string& condition) {
        // Forward to DAPIntegrationBridge
        if (m_dapBridge) {
            // DAP doesn't have direct condition update, may need to delete and recreate
            auto bp = m_breakpointManager->GetBreakpointInfo(breakpointId);
            m_dapBridge->ClearBreakpoint(bp.filePath, bp.line);
            m_dapBridge->SetBreakpoint(bp.filePath, bp.line, condition);
        }
    }
    
    void Win32IDE::OnClearAllBreakpoints() {
        // Forward to DAPIntegrationBridge
        if (m_dapBridge) {
            m_dapBridge->ClearAllBreakpoints();
        }
        
        // Clear editor gutter
        ClearAllBreakpointsFromGutter();
    }

Step 6: Sync with DAP
---------------------

When DAP reports breakpoints, update the panel:

    void Win32IDE::OnDAPBreakpointsReceived(const std::vector<Debug::Breakpoint>& dapBreakpoints) {
        std::vector<BreakpointInfo> panelBreakpoints;
        
        for (const auto& dapBp : dapBreakpoints) {
            BreakpointInfo info;
            info.id = dapBp.id;
            info.filePath = dapBp.source.path;
            info.fileName = GetFileNameFromPath(dapBp.source.path);
            info.line = dapBp.line;
            info.verified = dapBp.verified;
            info.enabled = true;  // DAP doesn't track enabled state directly
            
            panelBreakpoints.push_back(info);
        }
        
        if (m_breakpointManager) {
            m_breakpointManager->SetBreakpoints(panelBreakpoints);
        }
    }

Step 7: Handle User Breakpoint Toggle
-------------------------------------

When user toggles breakpoint in editor:

    void Win32IDE::OnEditorToggleBreakpoint(const std::wstring& file, int line) {
        // Check if breakpoint exists
        bool exists = m_breakpointManager->HasBreakpoint(file, line);
        
        if (exists) {
            // Remove it
            int bpId = m_breakpointManager->FindBreakpoint(file, line);
            m_breakpointManager->RemoveBreakpoint(bpId);
            m_dapBridge->ClearBreakpoint(file, line);
        } else {
            // Add it
            BreakpointInfo info;
            info.filePath = file;
            info.fileName = GetFileNameFromPath(file);
            info.line = line;
            info.enabled = true;
            
            m_breakpointManager->AddBreakpoint(info);
            m_dapBridge->SetBreakpoint(file, line);
        }
    }

Step 8: Update Hit Counts
-------------------------

When debugger hits a breakpoint:

    void Win32IDE::OnBreakpointHit(int breakpointId) {
        // Update hit count in panel
        if (m_breakpointManager) {
            auto info = m_breakpointManager->GetBreakpointInfo(breakpointId);
            m_breakpointManager->UpdateHitCount(breakpointId, info.hitCount + 1);
        }
    }

Step 9: Cleanup
---------------

In destructor or cleanup:

    Win32IDE::~Win32IDE() {
        // Cleanup breakpoint manager
        BreakpointManagerFactory::DestroyPanel();
        m_breakpointManager = nullptr;
    }

MENU INTEGRATION
================

Add to Debug menu:

    POPUP "&Debug"
    BEGIN
        // ... existing items ...
        MENUITEM SEPARATOR
        MENUITEM "&Breakpoints...\tCtrl+Shift+B", ID_DEBUG_BREAKPOINTS
        MENUITEM "Clear All &Breakpoints",      ID_DEBUG_CLEAR_ALL_BP
    END

Command handlers:

    case ID_DEBUG_BREAKPOINTS:
        // Show/hide breakpoint panel
        if (m_hwndBreakpointPanel) {
            ShowWindow(m_hwndBreakpointPanel, SW_SHOW);
            SetFocus(m_hwndBreakpointPanel);
        }
        return 0;
        
    case ID_DEBUG_CLEAR_ALL_BP:
        if (m_breakpointManager) {
            m_breakpointManager->ClearAllBreakpoints();
        }
        return 0;

KEYBOARD SHORTCUTS
==================

Add to accelerator table:

    ID_DEBUG_BREAKPOINTS,    VK_F9,    VIRTKEY, CONTROL, SHIFT
    ID_DEBUG_CLEAR_ALL_BP, VK_F9,    VIRTKEY, CONTROL, SHIFT, ALT

VISUAL STYLES
=============

The panel uses standard Win32 ListView with:
- Full row select
- Grid lines
- Checkbox-style enabled column (☑/☐)
- Double-buffering for smooth updates

To customize appearance:

    // In Win32IDE initialization, before creating panel:
    // Set ListView theme
    SetWindowTheme(m_hwndBreakpointPanel, L"Explorer", NULL);
    
    // Or use custom colors:
    ListView_SetBkColor(m_hwndListView, RGB(30, 30, 30));
    ListView_SetTextColor(m_hwndListView, RGB(220, 220, 220));
    ListView_SetTextBkColor(m_hwndListView, CLR_NONE);

TROUBLESHOOTING
===============

Issue: "Breakpoint panel is empty"
- Check that SetBreakpoints() is called after DAP initialization
- Verify breakpoint IDs are unique and positive

Issue: "Can't toggle breakpoints"
- Ensure IBreakpointManagerCallbacks is implemented
- Check that SetCallbacks() was called

Issue: "Navigation doesn't work"
- Verify OnBreakpointNavigate opens the file
- Check that file paths are absolute, not relative

Issue: "Hit counts not updating"
- Ensure OnBreakpointHit is called from DAP stopped event
- Check that breakpoint IDs match between DAP and panel

Issue: "Panel doesn't show in dockable pane"
- Verify parent window handle is correct
- Check that panel is created after parent is visible

ADVANCED FEATURES
=================

Conditional Breakpoints:
- Edit condition via context menu or Enter key
- Condition is evaluated by debugger, not IDE
- Syntax depends on debugger (e.g., C++ expression)

Hit Count Conditions:
- "break when hit count is equal to N"
- "break when hit count is a multiple of N"
- "break when hit count is greater than or equal to N"

Export/Import:
- Save breakpoints to JSON file
- Load breakpoints from previous session
- Share breakpoints with team members

*/
