//==============================================================================
// MoEPanel.h - Real-Time MoE Expert Visualization
//
// Visual interface for monitoring your MASM MoE system:
// - Live expert activation heat map
// - Swarm composition visualization
// - Ghost text speculative branches
// - Latent expert trigger conditions
// - Shadow routing fallback paths
// - Real-time trace streaming
//==============================================================================

#ifndef MOE_PANEL_H
#define MOE_PANEL_H

#include <windows.h>
#include <commctrl.h>
#include "../inference/MoEBackend.h"

// Panel dimensions
#define MOEPANEL_WIDTH        800
#define MOEPANEL_HEIGHT       600

// Control IDs
#define IDC_MOE_EXPERT_LIST       2001
#define IDC_MOE_HEATMAP           2002
#define IDC_MOE_TRACE_VIEW        2003
#define IDC_MOE_SWARM_VIEW        2004
#define IDC_MOE_GHOST_VIEW        2005
#define IDC_MOE_STATS_PANEL       2006
#define IDC_BTN_TARGET_EXPERT     2007
#define IDC_BTN_SWARM_MODE        2008
#define IDC_BTN_RESET_STATS       2009
#define IDC_COMBO_EXPERT_TAG      2010
#define IDC_EDIT_PROMPT           2011
#define IDC_BTN_GENERATE          2012

// Timer for real-time updates
#define TIMER_MOE_UPDATE          200
#define MOE_UPDATE_MS             100

// Expert visualization colors
#define COLOR_CORE_EXPERT         RGB(100, 149, 237)   // Cornflower blue
#define CODE_GHOST_EXPERT         RGB(255, 165, 0)     // Orange
#define COLOR_SWARM_EXPERT        RGB(50, 205, 50)     // Lime green
#define COLOR_LATENT_EXPERT       RGB(255, 105, 180)   // Hot pink
#define COLOR_SHADOW_EXPERT       RGB(128, 128, 128)   // Gray
#define COLOR_MERGE_EXPERT        RGB(255, 215, 0)     // Gold
#define COLOR_ECHO_EXPERT         RGB(0, 191, 255)     // Deep sky blue
#define COLOR_SPECULATIVE_EXPERT  RGB(255, 69, 0)      // Red-orange

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// MoE Panel Functions
//==============================================================================

// Create the MoE panel window
HWND MoEPanel_Create(HWND hWndParent, HINSTANCE hInstance, 
                     int x, int y, int width, int height);

// Destroy the panel
void MoEPanel_Destroy(HWND hWndPanel);

// Set the MoE backend to monitor
void MoEPanel_SetBackend(HWND hWndPanel, Sovereign::Inference::MoEBackend* backend);

// Refresh expert list and heat map
void MoEPanel_Refresh(HWND hWndPanel);

// Add trace entry (called from backend callback)
void MoEPanel_AddTraceEntry(HWND hWndPanel, const MoEActivation* activation);

// Update swarm visualization
void MoEPanel_UpdateSwarm(HWND hWndPanel, const MoEActivation* swarm_members, int count);

// Update ghost text branches
void MoEPanel_UpdateGhostBranches(HWND hWndPanel, const MoEActivation* branches, int count);

// Window procedure
LRESULT CALLBACK MoEPanel_WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

// Initialize common controls
void MoEPanel_InitControls(HINSTANCE hInstance);

//==============================================================================
// Expert Targeting
//==============================================================================

// Target specific expert for generation
void MoEPanel_TargetExpert(HWND hWndPanel, const char* expert_tag);

// Enable swarm mode with selected experts
void MoEPanel_EnableSwarmMode(HWND hWndPanel, const char** expert_tags, int count);

// Reset statistics
void MoEPanel_ResetStats(HWND hWndPanel);

//==============================================================================
// Real-Time Callback
//==============================================================================

// Callback function type for trace updates
typedef void (*MoEPanelTraceCallback)(const MoEActivation* activation, void* user_data);

// Set trace callback
void MoEPanel_SetTraceCallback(HWND hWndPanel, MoEPanelTraceCallback callback, void* user_data);

#ifdef __cplusplus
}
#endif

#endif // MOE_PANEL_H
