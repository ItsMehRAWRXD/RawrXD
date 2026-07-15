//==============================================================================
// ModelPanel.h - Phase 15A: GUI Model Panel
//
// Visual interface for ModelRegistry inside the Sovereign IDE
// Features:
// - Model list with icons
// - Real-time performance metrics
// - Capability badges
// - Hot-swap controls
// - Integration with ExecutionJournal
//==============================================================================

#ifndef MODEL_PANEL_H
#define MODEL_PANEL_H

#include <windows.h>
#include <commctrl.h>
#include "../core/ModelRegistry.h"

// Panel dimensions
#define MODELPANEL_WIDTH        400
#define MODELPANEL_HEIGHT       600
#define MODELPANEL_LIST_WIDTH   200
#define MODELPANEL_DETAIL_WIDTH 190

// Control IDs
#define IDC_MODEL_LIST          1001
#define IDC_MODEL_DETAILS       1002
#define IDC_BTN_SET_DEFAULT     1003
#define IDC_BTN_SWITCH          1004
#define IDC_BTN_REFRESH         1005
#define IDC_BTN_BENCHMARK       1006
#define IDC_BTN_DOWNLOAD        1010
#define IDC_BTN_DISTRIBUTED     1011
#define IDC_STATIC_ACTIVE       1007
#define IDC_STATIC_PERFORMANCE  1008
#define IDC_PROGRESS_LOADING    1009

// Model icon indices
#define ICON_MODEL_DEFAULT      0
#define ICON_MODEL_ACTIVE       1
#define ICON_MODEL_LOCAL        2
#define ICON_MODEL_REMOTE       3
#define ICON_MODEL_LOADING      4

// Timer for performance updates
#define TIMER_PERFORMANCE_UPDATE 100
#define PERFORMANCE_UPDATE_MS    1000

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Model Panel Functions
//==============================================================================

// Create the model panel window
HWND ModelPanel_Create(HWND hWndParent, HINSTANCE hInstance, int x, int y, int width, int height);

// Destroy the model panel
void ModelPanel_Destroy(HWND hWndPanel);

// Refresh the model list from registry
void ModelPanel_Refresh(HWND hWndPanel);

// Update performance metrics display
void ModelPanel_UpdatePerformance(HWND hWndPanel);

// Set the active model indicator
void ModelPanel_SetActiveModel(HWND hWndPanel, const char* model_id);

// Show model details in the details pane
void ModelPanel_ShowModelDetails(HWND hWndPanel, const ModelInfo* model);

// Handle model selection change
void ModelPanel_OnModelSelected(HWND hWndPanel, int index);

// Window procedure for the panel
LRESULT CALLBACK ModelPanel_WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

// Initialize common controls for the panel
void ModelPanel_InitControls(HINSTANCE hInstance);

// Create image list for model icons
HIMAGELIST ModelPanel_CreateImageList(HINSTANCE hInstance);

//==============================================================================
// Integration with SovereignGUI
//==============================================================================

// Add Model Panel menu item to main GUI
void ModelPanel_AddMenuItem(HWND hWndMenu);

// Show/hide the model panel
void ModelPanel_Show(HWND hWndPanel, BOOL show);

// Check if panel is visible
BOOL ModelPanel_IsVisible(HWND hWndPanel);

// Toggle panel visibility
void ModelPanel_Toggle(HWND hWndPanel);

#ifdef __cplusplus
}
#endif

#endif // MODEL_PANEL_H
