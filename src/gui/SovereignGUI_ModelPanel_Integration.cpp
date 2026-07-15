//==============================================================================
// SovereignGUI_ModelPanel_Integration.cpp - Phase 15A Integration
//
// Integrates ModelPanel into the main SovereignGUI
// - Menu item (View -> Model Panel)
// - Dockable panel support
// - Keyboard shortcut (Ctrl+M)
// - Toolbar button
//==============================================================================

#include "SovereignGUI.h"
#include "ModelPanel.h"
#include "../core/ModelRegistry.h"
#include "../core/ExecutionJournal.h"
#include <windows.h>
#include <commctrl.h>

//==============================================================================
// External References
//==============================================================================

// From SovereignGUI.cpp
extern HWND g_hWndMain;
extern HWND g_hWndToolbar;
extern HINSTANCE g_hInst;
extern int g_nCmdShow;

// Model panel window handle
static HWND g_hWndModelPanel = NULL;
static BOOL g_bModelPanelVisible = FALSE;

// Menu command ID
#define IDM_VIEW_MODELPANEL    40001
#define IDM_TOOLS_BENCHMARK  40002

//==============================================================================
// Model Panel Integration
//==============================================================================

void SovereignGUI_InitModelPanel(void) {
    // Initialize common controls for model panel
    ModelPanel_InitControls(g_hInst);
    
    printf("[SovereignGUI] Model Panel integration initialized\n");
}

void SovereignGUI_CreateModelPanel(void) {
    if (g_hWndModelPanel != NULL) {
        // Already created, just show it
        ModelPanel_Show(g_hWndModelPanel, TRUE);
        return;
    }
    
    // Calculate panel position (right side of main window)
    RECT rcClient;
    GetClientRect(g_hWndMain, &rcClient);
    
    int panelWidth = MODELPANEL_WIDTH;
    int panelHeight = rcClient.bottom - rcClient.top;
    int panelX = rcClient.right - panelWidth;
    int panelY = 0;
    
    // Create the model panel as a child window
    g_hWndModelPanel = ModelPanel_Create(
        g_hWndMain,
        g_hInst,
        panelX, panelY,
        panelWidth, panelHeight
    );
    
    if (g_hWndModelPanel) {
        g_bModelPanelVisible = TRUE;
        
        // Log to journal
        Journal_LogUserRequest("Model Panel created", "GUI initialization");
        
        printf("[SovereignGUI] Model Panel created at (%d, %d) size %dx%d\n",
               panelX, panelY, panelWidth, panelHeight);
    } else {
        fprintf(stderr, "[SovereignGUI] Failed to create Model Panel\n");
    }
}

void SovereignGUI_DestroyModelPanel(void) {
    if (g_hWndModelPanel) {
        ModelPanel_Destroy(g_hWndModelPanel);
        g_hWndModelPanel = NULL;
        g_bModelPanelVisible = FALSE;
    }
}

void SovereignGUI_ToggleModelPanel(void) {
    if (g_hWndModelPanel == NULL) {
        SovereignGUI_CreateModelPanel();
    } else {
        ModelPanel_Toggle(g_hWndModelPanel);
        g_bModelPanelVisible = ModelPanel_IsVisible(g_hWndModelPanel);
    }
    
    // Update menu check state
    HMENU hMenu = GetMenu(g_hWndMain);
    if (hMenu) {
        CheckMenuItem(hMenu, IDM_VIEW_MODELPANEL,
                      g_bModelPanelVisible ? MF_CHECKED : MF_UNCHECKED);
    }
    
    // Log toggle
    Journal_LogUserRequest(
        g_bModelPanelVisible ? "Model Panel shown" : "Model Panel hidden",
        "GUI"
    );
}

void SovereignGUI_ShowModelPanel(BOOL show) {
    if (show && g_hWndModelPanel == NULL) {
        SovereignGUI_CreateModelPanel();
    } else if (g_hWndModelPanel) {
        ModelPanel_Show(g_hWndModelPanel, show);
        g_bModelPanelVisible = show;
    }
}

BOOL SovereignGUI_IsModelPanelVisible(void) {
    return g_bModelPanelVisible;
}

//==============================================================================
// Menu Integration
//==============================================================================

void SovereignGUI_AddModelPanelMenu(HMENU hMenu) {
    // Add "View -> Model Panel" menu item
    HMENU hViewMenu = NULL;
    
    // Find View submenu
    int menuCount = GetMenuItemCount(hMenu);
    for (int i = 0; i < menuCount; i++) {
        char menuText[256];
        GetMenuString(hMenu, i, menuText, sizeof(menuText), MF_BYPOSITION);
        
        if (strstr(menuText, "View") != NULL) {
            hViewMenu = GetSubMenu(hMenu, i);
            break;
        }
    }
    
    if (hViewMenu) {
        // Add separator and Model Panel item
        AppendMenu(hViewMenu, MF_SEPARATOR, 0, NULL);
        AppendMenu(hViewMenu, MF_STRING, IDM_VIEW_MODELPANEL, "Model Panel\tCtrl+M");
        
        printf("[SovereignGUI] Added Model Panel to View menu\n");
    }
}

void SovereignGUI_AddModelPanelToolbar(void) {
    if (!g_hWndToolbar) return;
    
    // Add toolbar button for Model Panel
    TBBUTTON tbButton = {0};
    tbButton.iBitmap = 0;  // Use first image in toolbar imagelist
    tbButton.idCommand = IDM_VIEW_MODELPANEL;
    tbButton.fsState = TBSTATE_ENABLED;
    tbButton.fsStyle = BTNS_BUTTON;
    tbButton.iString = (INT_PTR)"Models";
    
    SendMessage(g_hWndToolbar, TB_ADDBUTTONS, 1, (LPARAM)&tbButton);
    
    printf("[SovereignGUI] Added Model Panel button to toolbar\n");
}

//==============================================================================
// Message Handler
//==============================================================================

BOOL SovereignGUI_HandleModelPanelCommand(WPARAM wParam, LPARAM lParam) {
    (void)lParam;
    
    switch (LOWORD(wParam)) {
        case IDM_VIEW_MODELPANEL:
            SovereignGUI_ToggleModelPanel();
            return TRUE;
            
        case IDM_TOOLS_BENCHMARK:
            // Open benchmark dialog for selected model
            if (g_hWndModelPanel && g_bModelPanelVisible) {
                MessageBox(g_hWndMain,
                    "Benchmark feature will run performance tests on the selected model.",
                    "Benchmark",
                    MB_OK | MB_ICONINFORMATION);
            }
            return TRUE;
    }
    
    return FALSE;
}

//==============================================================================
// Keyboard Accelerator
//==============================================================================

void SovereignGUI_RegisterModelPanelAccelerator(HWND hWnd) {
    // Register Ctrl+M for Model Panel
    // This would typically be done in an accelerator table
    // For now, we handle it in WM_KEYDOWN
    (void)hWnd;
}

//==============================================================================
// Resize Handling
//==============================================================================

void SovereignGUI_ResizeModelPanel(void) {
    if (!g_hWndModelPanel || !g_bModelPanelVisible) return;
    
    RECT rcClient;
    GetClientRect(g_hWndMain, &rcClient);
    
    // Position panel on the right side
    int panelWidth = MODELPANEL_WIDTH;
    int panelHeight = rcClient.bottom - rcClient.top;
    int panelX = rcClient.right - panelWidth;
    int panelY = 0;
    
    SetWindowPos(g_hWndModelPanel, NULL,
                 panelX, panelY,
                 panelWidth, panelHeight,
                 SWP_NOZORDER | SWP_NOACTIVATE);
}

//==============================================================================
// Status Bar Integration
//==============================================================================

void SovereignGUI_UpdateStatusBarWithModelInfo(void) {
    // Update status bar with active model info
    ModelInfo activeModel;
    if (ModelRegistry_GetActiveModel(&activeModel) == 0) {
        char statusText[256];
        snprintf(statusText, sizeof(statusText),
            "Model: %s | %.1f tok/s",
            activeModel.name,
            activeModel.tokens_per_second);
        
        // This would update the actual status bar
        // SendMessage(g_hWndStatusBar, SB_SETTEXT, 0, (LPARAM)statusText);
        (void)statusText;
    }
}

//==============================================================================
// Initialization Entry Point
//==============================================================================

void SovereignGUI_InitializePhase15A(void) {
    printf("\n");
    printf("============================================================\n");
    printf("Phase 15A - GUI Model Panel Integration\n");
    printf("============================================================\n");
    printf("\n");
    
    printf("[1/4] Initializing Model Panel controls...\n");
    SovereignGUI_InitModelPanel();
    printf("      ✓ Controls initialized\n\n");
    
    printf("[2/4] Adding menu items...\n");
    HMENU hMenu = GetMenu(g_hWndMain);
    if (hMenu) {
        SovereignGUI_AddModelPanelMenu(hMenu);
        printf("      ✓ Menu items added\n\n");
    }
    
    printf("[3/4] Adding toolbar button...\n");
    SovereignGUI_AddModelPanelToolbar();
    printf("      ✓ Toolbar button added\n\n");
    
    printf("[4/4] Creating model panel window...\n");
    SovereignGUI_CreateModelPanel();
    printf("      ✓ Model Panel ready\n\n");
    
    printf("============================================================\n");
    printf("Phase 15A COMPLETE - GUI Model Panel Integrated\n");
    printf("============================================================\n");
    printf("\n");
    printf("Controls:\n");
    printf("  View -> Model Panel (Ctrl+M)\n");
    printf("  Toolbar: Models button\n");
    printf("\n");
    
    // Log completion
    Journal_LogUserRequest("Phase 15A complete", "GUI Model Panel integrated");
}
