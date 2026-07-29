//==============================================================================
// MoEPanel.cpp - Real-Time MoE Expert Visualization Implementation
//==============================================================================

#include "MoEPanel.h"
#include "../core/ExecutionJournal.h"
#include "../inference/MoEBackend.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <map>

#pragma comment(lib, "comctl32.lib")

//==============================================================================
// Internal State
//==============================================================================

typedef struct MoEPanelState {
    HWND hWndExpertList;      // List of all experts
    HWND hWndHeatMap;         // Heat map visualization
    HWND hWndTraceView;       // Real-time trace
    HWND hWndSwarmView;       // Swarm composition
    HWND hWndGhostView;       // Ghost text branches
    HWND hWndStatsPanel;      // Statistics panel
    HWND hWndPromptEdit;      // Prompt input
    HWND hWndExpertCombo;     // Expert selection combo
    HWND hWndGenerateBtn;     // Generate button
    
    Sovereign::Inference::MoEBackend* backend;
    std::vector<MoEActivation> expertList;
    std::map<int, int> activationCounts;  // expert_id -> count
    std::vector<MoEActivation> recentTraces;
    
    HFONT hFontNormal;
    HFONT hFontBold;
    HBRUSH hBrushes[8];  // Color brushes for expert types
} MoEPanelState;

static MoEPanelState g_moePanel = {0};
static HWND g_hMoEPanel = NULL;

//==============================================================================
// Color Constants
//==============================================================================

static COLORREF g_expertColors[] = {
    COLOR_CORE_EXPERT,         // Core
    COLOR_CORE_EXPERT,
    COLOR_CORE_EXPERT,
    COLOR_CORE_EXPERT,
    RGB(0, 128, 0),            // Code (dark green)
    RGB(0, 128, 0),
    RGB(0, 128, 0),
    RGB(0, 128, 0),
    COLOR_GHOST_EXPERT,        // Ghost
    COLOR_GHOST_EXPERT,
    COLOR_GHOST_EXPERT,
    COLOR_GHOST_EXPERT,
    COLOR_SWARM_EXPERT,        // Swarm
    COLOR_SWARM_EXPERT,
    COLOR_SWARM_EXPERT,
    COLOR_SWARM_EXPERT,
    RGB(0, 0, 255),            // Prefetch (blue)
    RGB(0, 0, 255),
    RGB(0, 0, 255),
    RGB(0, 0, 255),
    COLOR_LATENT_EXPERT,       // Latent
    COLOR_LATENT_EXPERT,
    COLOR_LATENT_EXPERT,
    COLOR_LATENT_EXPERT,
    COLOR_SHADOW_EXPERT,       // Shadow
    COLOR_SHADOW_EXPERT,
    COLOR_SHADOW_EXPERT,
    COLOR_SHADOW_EXPERT,
    COLOR_MERGE_EXPERT,        // Merge
    COLOR_MERGE_EXPERT,
    COLOR_MERGE_EXPERT,
    COLOR_MERGE_EXPERT,
    COLOR_ECHO_EXPERT,         // Echo
    COLOR_ECHO_EXPERT,
    COLOR_ECHO_EXPERT,
    COLOR_ECHO_EXPERT,
    COLOR_SPECULATIVE_EXPERT,  // Speculative
    COLOR_SPECULATIVE_EXPERT,
    COLOR_SPECULATIVE_EXPERT,
    COLOR_SPECULATIVE_EXPERT,
    RGB(128, 0, 128),          // Experimental (purple)
    RGB(128, 0, 128),
    RGB(128, 0, 128),
    RGB(128, 0, 128)
};

//==============================================================================
// Window Creation
//==============================================================================

HWND MoEPanel_Create(HWND hWndParent, HINSTANCE hInstance, 
                     int x, int y, int width, int height) {
    // Register window class
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = MoEPanel_WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SovereignMoEPanel";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    if (!RegisterClassEx(&wc)) {
        return NULL;
    }

    // Create panel window
    HWND hWnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "SovereignMoEPanel",
        "MoE Expert Monitor",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, width, height,
        hWndParent,
        NULL,
        hInstance,
        NULL
    );

    if (!hWnd) {
        return NULL;
    }

    g_hMoEPanel = hWnd;

    // Initialize fonts
    g_moePanel.hFontNormal = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    g_moePanel.hFontBold = CreateFont(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    // Create color brushes
    for (int i = 0; i < 8; i++) {
        g_moePanel.hBrushes[i] = CreateSolidBrush(g_expertColors[i * 5]);
    }

    // Create controls
    int margin = 10;
    int panelWidth = (width - margin * 3) / 2;
    int panelHeight = (height - margin * 4) / 3;

    // Left column: Expert list and heat map
    g_moePanel.hWndExpertList = CreateWindowEx(
        WS_EX_CLIENTEDGE, WC_LISTVIEW, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        margin, margin, panelWidth, panelHeight * 2,
        hWnd, (HMENU)IDC_MOE_EXPERT_LIST, hInstance, NULL);

    ListView_SetExtendedListViewStyle(g_moePanel.hWndExpertList, 
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Add columns
    LVCOLUMN lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    lvc.pszText = (LPSTR)"Expert";
    lvc.cx = 150;
    ListView_InsertColumn(g_moePanel.hWndExpertList, 0, &lvc);
    
    lvc.pszText = (LPSTR)"Activations";
    lvc.cx = 80;
    ListView_InsertColumn(g_moePanel.hWndExpertList, 1, &lvc);
    
    lvc.pszText = (LPSTR)"Confidence";
    lvc.cx = 80;
    ListView_InsertColumn(g_moePanel.hWndExpertList, 2, &lvc);

    // Right column: Trace view
    g_moePanel.hWndTraceView = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | 
        ES_AUTOVSCROLL | WS_VSCROLL,
        margin * 2 + panelWidth, margin, panelWidth, panelHeight * 2,
        hWnd, (HMENU)IDC_MOE_TRACE_VIEW, hInstance, NULL);
    SendMessage(g_moePanel.hWndTraceView, WM_SETFONT, 
        (WPARAM)g_moePanel.hFontNormal, TRUE);

    // Bottom: Prompt input and controls
    int bottomY = margin * 2 + panelHeight * 2;
    
    // Expert combo
    g_moePanel.hWndExpertCombo = CreateWindowEx(
        0, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        margin, bottomY, 150, 200,
        hWnd, (HMENU)IDC_COMBO_EXPERT_TAG, hInstance, NULL);
    SendMessage(g_moePanel.hWndExpertCombo, WM_SETFONT, 
        (WPARAM)g_moePanel.hFontNormal, TRUE);

    // Generate button
    g_moePanel.hWndGenerateBtn = CreateWindow(
        "BUTTON", "Generate",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        margin + 160, bottomY, 80, 25,
        hWnd, (HMENU)IDC_BTN_GENERATE, hInstance, NULL);

    // Prompt edit
    g_moePanel.hWndPromptEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL,
        margin, bottomY + 35, width - margin * 2, panelHeight - 35,
        hWnd, (HMENU)IDC_EDIT_PROMPT, hInstance, NULL);
    SendMessage(g_moePanel.hWndPromptEdit, WM_SETFONT, 
        (WPARAM)g_moePanel.hFontNormal, TRUE);

    // Set timer for updates
    SetTimer(hWnd, TIMER_MOE_UPDATE, MOE_UPDATE_MS, NULL);

    return hWnd;
}

void MoEPanel_Destroy(HWND hWndPanel) {
    KillTimer(hWndPanel, TIMER_MOE_UPDATE);
    
    for (int i = 0; i < 8; i++) {
        DeleteObject(g_moePanel.hBrushes[i]);
    }
    
    DestroyWindow(hWndPanel);
}

//==============================================================================
// Backend Integration
//==============================================================================

void MoEPanel_SetBackend(HWND hWndPanel, Sovereign::Inference::MoEBackend* backend) {
    g_moePanel.backend = backend;
    
    if (backend) {
        // Populate expert list
        std::vector<MoEActivation> experts;
        backend->GetExpertList(&experts);
        
        g_moePanel.expertList = experts;
        
        // Populate combo box
        SendMessage(g_moePanel.hWndExpertCombo, CB_RESETCONTENT, 0, 0);
        SendMessage(g_moePanel.hWndExpertCombo, CB_ADDSTRING, 0, (LPARAM)"Auto");
        
        for (const auto& expert : experts) {
            if (expert.expert_name) {
                SendMessage(g_moePanel.hWndExpertCombo, CB_ADDSTRING, 0, 
                    (LPARAM)expert.expert_name);
            }
        }
        
        SendMessage(g_moePanel.hWndExpertCombo, CB_SETCURSEL, 0, 0);
        
        // Set trace callback
        backend->SetTraceCallback([](const MoEActivation& act) {
            MoEPanel_AddTraceEntry(g_hMoEPanel, &act);
        });
    }
    
    MoEPanel_Refresh(hWndPanel);
}

void MoEPanel_Refresh(HWND hWndPanel) {
    if (!g_moePanel.backend) return;
    
    // Update expert list with activation counts
    ListView_DeleteAllItems(g_moePanel.hWndExpertList);
    
    for (size_t i = 0; i < g_moePanel.expertList.size(); i++) {
        const auto& expert = g_moePanel.expertList[i];
        
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.pszText = (LPSTR)(expert.expert_name ? expert.expert_name : "unknown");
        ListView_InsertItem(g_moePanel.hWndExpertList, &lvi);
        
        // Activation count
        char buf[32];
        int count = g_moePanel.activationCounts[expert.expert_id];
        snprintf(buf, sizeof(buf), "%d", count);
        ListView_SetItemText(g_moePanel.hWndExpertList, i, 1, buf);
        
        // Confidence
        snprintf(buf, sizeof(buf), "%.1f%%", expert.confidence);
        ListView_SetItemText(g_moePanel.hWndExpertList, i, 2, buf);
    }
}

//==============================================================================
// Trace Handling
//==============================================================================

void MoEPanel_AddTraceEntry(HWND hWndPanel, const MoEActivation* activation) {
    if (!activation) return;
    
    // Update activation count
    g_moePanel.activationCounts[activation->expert_id]++;
    
    // Add to recent traces
    g_moePanel.recentTraces.push_back(*activation);
    if (g_moePanel.recentTraces.size() > 100) {
        g_moePanel.recentTraces.erase(g_moePanel.recentTraces.begin());
    }
    
    // Format trace line
    char traceLine[512];
    snprintf(traceLine, sizeof(traceLine),
        "[%s] confidence=%.1f%%\r\n",
        activation->expert_name ? activation->expert_name : "unknown",
        activation->confidence);
    
    // Append to trace view
    int len = GetWindowTextLength(g_moePanel.hWndTraceView);
    SendMessage(g_moePanel.hWndTraceView, EM_SETSEL, len, len);
    SendMessage(g_moePanel.hWndTraceView, EM_REPLACESEL, 0, (LPARAM)traceLine);
    SendMessage(g_moePanel.hWndTraceView, EM_SCROLL, SB_BOTTOM, 0);
}

//==============================================================================
// Window Procedure
//==============================================================================

LRESULT CALLBACK MoEPanel_WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_TIMER:
            if (wParam == TIMER_MOE_UPDATE) {
                MoEPanel_Refresh(hWnd);
            }
            break;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_BTN_GENERATE: {
                    if (!g_moePanel.backend) break;
                    
                    // Get prompt
                    char prompt[4096];
                    GetWindowText(g_moePanel.hWndPromptEdit, prompt, sizeof(prompt));
                    
                    // Get selected expert
                    int sel = (int)SendMessage(g_moePanel.hWndExpertCombo, CB_GETCURSEL, 0, 0);
                    
                    InferenceRequest req = {0};
                    strncpy(req.prompt, prompt, sizeof(req.prompt) - 1);
                    req.max_tokens = 256;
                    
                    InferenceResponse res = {0};
                    
                    if (sel == 0) {
                        // Auto mode
                        g_moePanel.backend->Generate(&req, &res);
                    } else {
                        // Target specific expert
                        char expertTag[128];
                        SendMessage(g_moePanel.hWndExpertCombo, CB_GETLBTEXT, sel, (LPARAM)expertTag);
                        g_moePanel.backend->GenerateWithExpert(&req, expertTag, &res);
                    }
                    
                    // Append result to trace
                    if (res.success) {
                        MoEPanel_AddTraceEntry(hWnd, &(MoEActivation){
                            .expert_id = -1,
                            .expert_name = "RESULT",
                            .confidence = 100.0f
                        });
                    }
                    break;
                }
            }
            break;
            
        case WM_DESTROY:
            KillTimer(hWnd, TIMER_MOE_UPDATE);
            break;
    }
    
    return DefWindowProc(hWnd, message, wParam, lParam);
}

//==============================================================================
// Placeholder Functions
//==============================================================================

void MoEPanel_UpdateSwarm(HWND hWndPanel, const MoEActivation* swarm_members, int count) {
    if (!hWndPanel || !swarm_members || count <= 0) return;
    
    // Get the trace view window handle
    if (!g_moePanel.hWndTraceView) return;
    
    // Build visualization string
    std::string swarm_text = "=== Swarm Composition ===\r\n";
    
    float total_activation = 0.0f;
    for (int i = 0; i < count; i++) {
        total_activation += swarm_members[i].activation_level;
    }
    
    for (int i = 0; i < count; i++) {
        const MoEActivation& member = swarm_members[i];
        float percentage = (total_activation > 0.0f) ? 
            (member.activation_level / total_activation * 100.0f) : 0.0f;
        
        char line[256];
        snprintf(line, sizeof(line), "[%s] %.1f%% (%.3f)\r\n", 
                 member.expert_tag, percentage, member.activation_level);
        swarm_text += line;
        
        // Update activation counts
        g_moePanel.activationCounts[member.expert_tag] = member.activation_level;
    }
    
    // Append to trace view
    SetWindowTextA(g_moePanel.hWndTraceView, swarm_text.c_str());
    
    // Force redraw
    InvalidateRect(g_moePanel.hWndTraceView, NULL, TRUE);
}

void MoEPanel_UpdateGhostBranches(HWND hWndPanel, const MoEActivation* branches, int count) {
    if (!hWndPanel || !branches || count <= 0) return;
    if (!g_moePanel.hWndTraceView) return;
    
    // Build ghost branch visualization
    std::string branch_text = "=== Ghost Text Branches ===\r\n";
    
    // Sort branches by activation level (descending)
    std::vector<MoEActivation> sorted_branches(branches, branches + count);
    std::sort(sorted_branches.begin(), sorted_branches.end(),
              [](const MoEActivation& a, const MoEActivation& b) {
                  return a.activation_level > b.activation_level;
              });
    
    for (int i = 0; i < count && i < 10; i++) {  // Show top 10
        const MoEActivation& branch = sorted_branches[i];
        char line[256];
        
        // Create visual bar
        int bar_length = static_cast<int>(branch.activation_level * 50.0f);
        std::string bar(bar_length, '|');
        
        snprintf(line, sizeof(line), "%2d. [%s] %s %.3f\r\n", 
                 i + 1, branch.expert_tag, bar.c_str(), branch.activation_level);
        branch_text += line;
    }
    
    // Append to existing text
    char existing_text[4096];
    GetWindowTextA(g_moePanel.hWndTraceView, existing_text, sizeof(existing_text));
    
    std::string combined = std::string(existing_text) + "\r\n" + branch_text;
    SetWindowTextA(g_moePanel.hWndTraceView, combined.c_str());
    
    InvalidateRect(g_moePanel.hWndTraceView, NULL, TRUE);
}

void MoEPanel_TargetExpert(HWND hWndPanel, const char* expert_tag) {
    if (!g_moePanel.hWndExpertCombo) return;
    
    int count = (int)SendMessage(g_moePanel.hWndExpertCombo, CB_GETCOUNT, 0, 0);
    for (int i = 0; i < count; i++) {
        char buf[128];
        SendMessage(g_moePanel.hWndExpertCombo, CB_GETLBTEXT, i, (LPARAM)buf);
        if (strcmp(buf, expert_tag) == 0) {
            SendMessage(g_moePanel.hWndExpertCombo, CB_SETCURSEL, i, 0);
            break;
        }
    }
}

void MoEPanel_EnableSwarmMode(HWND hWndPanel, const char** expert_tags, int count) {
    if (!hWndPanel || !expert_tags || count <= 0) return;
    if (!g_moePanel.hWndExpertCombo) return;
    
    // Enable multi-select mode in the expert combo box
    // Change style to support multiple selection
    LONG style = GetWindowLong(g_moePanel.hWndExpertCombo, GWL_STYLE);
    SetWindowLong(g_moePanel.hWndExpertCombo, GWL_STYLE, style | CBS_MULTISELECT);
    
    // Select all specified experts
    for (int i = 0; i < count; i++) {
        int combo_count = (int)SendMessage(g_moePanel.hWndExpertCombo, CB_GETCOUNT, 0, 0);
        for (int j = 0; j < combo_count; j++) {
            char buf[128];
            SendMessage(g_moePanel.hWndExpertCombo, CB_GETLBTEXT, j, (LPARAM)buf);
            if (strcmp(buf, expert_tags[i]) == 0) {
                // Set selection for this item
                SendMessage(g_moePanel.hWndExpertCombo, CB_SETSEL, TRUE, j);
                break;
            }
        }
    }
    
    // Update panel title to indicate swarm mode
    SetWindowTextA(hWndPanel, "MoE Panel [Swarm Mode]");
    
    // Force refresh
    MoEPanel_Refresh(hWndPanel);
}

void MoEPanel_ResetStats(HWND hWndPanel) {
    g_moePanel.activationCounts.clear();
    g_moePanel.recentTraces.clear();
    SetWindowText(g_moePanel.hWndTraceView, "");
    MoEPanel_Refresh(hWndPanel);
}

void MoEPanel_SetTraceCallback(HWND hWndPanel, MoEPanelTraceCallback callback, void* user_data) {
    if (!hWndPanel) return;
    
    // Store the callback and user data in the panel's user data
    // We'll use a simple structure to hold both
    struct CallbackData {
        MoEPanelTraceCallback callback;
        void* user_data;
    };
    
    static CallbackData cb_data;  // Static to persist across calls
    cb_data.callback = callback;
    cb_data.user_data = user_data;
    
    // Store pointer to callback data in window user data
    SetWindowLongPtr(hWndPanel, GWLP_USERDATA, (LONG_PTR)&cb_data);
    
    // If callback is set, trigger it immediately with current state
    if (callback) {
        // Build current trace summary
        std::string trace_summary = "MoE Panel Initialized\r\n";
        trace_summary += "Active Experts: " + std::to_string(g_moePanel.activationCounts.size()) + "\r\n";
        trace_summary += "Recent Traces: " + std::to_string(g_moePanel.recentTraces.size()) + "\r\n";
        
        callback(trace_summary.c_str(), user_data);
    }
}
