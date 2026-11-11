//==============================================================================
// VMManagerPanel.h - Phase 16: VM Management GUI Panel
//
// Visual interface for managing isolated execution environments:
// - VM list with live status
// - Resource usage graphs
// - Sandbox level controls
// - Checkpoint/restore operations
// - Tenant isolation view
//==============================================================================

#ifndef VM_MANAGER_PANEL_H
#define VM_MANAGER_PANEL_H

#include <windows.h>
#include <commctrl.h>
#include "../core/SovereignHypervisor.h"

// Panel dimensions
#define VMPANEL_WIDTH        700
#define VMPANEL_HEIGHT       550

// Control IDs
#define IDC_VM_LIST          4001
#define IDC_VM_CREATE_BTN    4002
#define IDC_VM_START_BTN     4003
#define IDC_VM_STOP_BTN      4004
#define IDC_VM_DESTROY_BTN   4005
#define IDC_VM_CHECKPOINT_BTN 4006
#define IDC_VM_REFRESH_BTN   4007
#define IDC_VM_TYPE_COMBO    4008
#define IDC_VM_MEMORY_EDIT   4009
#define IDC_VM_CPU_EDIT      4010
#define IDC_VM_SANDBOX_SLIDER 4011
#define IDC_VM_TENANT_COMBO  4012
#define IDC_VM_METRICS_LIST  4013

// Timer for live updates
#define TIMER_VM_UPDATE      400
#define VM_UPDATE_MS         1000

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Panel Functions
//==============================================================================

// Create VM manager panel
HWND VMManagerPanel_Create(HWND hWndParent, HINSTANCE hInstance,
                           int x, int y, int width, int height);

// Destroy panel
void VMManagerPanel_Destroy(HWND hWndPanel);

// Refresh VM list
void VMManagerPanel_Refresh(HWND hWndPanel);

// Update metrics display
void VMManagerPanel_UpdateMetrics(HWND hWndPanel);

// Window procedure
LRESULT CALLBACK VMManagerPanel_WndProc(HWND hWnd, UINT message,
                                        WPARAM wParam, LPARAM lParam);

//==============================================================================
// VM Operations
//==============================================================================

void VMManagerPanel_CreateVM(HWND hWndPanel);
void VMManagerPanel_StartVM(HWND hWndPanel);
void VMManagerPanel_StopVM(HWND hWndPanel);
void VMManagerPanel_DestroyVM(HWND hWndPanel);
void VMManagerPanel_CheckpointVM(HWND hWndPanel);
void VMManagerPanel_RestoreVM(HWND hWndPanel);

//==============================================================================
// Sandbox Controls
//==============================================================================

void VMManagerPanel_SetSandboxLevel(HWND hWndPanel, int level);
void VMManagerPanel_ApplySecurityProfile(HWND hWndPanel, const char* profile);

//==============================================================================
// Tenant Management
//==============================================================================

void VMManagerPanel_CreateTenant(HWND hWndPanel);
void VMManagerPanel_AssignTenant(HWND hWndPanel, const char* vm_id, const char* tenant);
void VMManagerPanel_ShowTenantUsage(HWND hWndPanel, const char* tenant);

#ifdef __cplusplus
}
#endif

#endif // VM_MANAGER_PANEL_H
