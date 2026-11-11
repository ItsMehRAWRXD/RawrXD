//==============================================================================
// DistributedModelPanel.cpp - Phase 15C: Distributed Cluster GUI Implementation
//==============================================================================

#include "DistributedModelPanel.h"
#include "../core/RemoteCluster.h"
#include "../core/ExecutionJournal.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

//==============================================================================
// Internal State
//==============================================================================

typedef struct DistPanelState {
    HWND hWndNodeList;
    HWND hWndMetricsStatic;
    HWND hWndBenchmarkBtn;
    HWND hWndRefreshBtn;
    HWND hWndStrategyCombo;
    HWND hWndClusterTPS;
    HWND hWndActiveReqs;
    HWND hWndNodeCount;
    HFONT hFontNormal;
    HFONT hFontBold;
    NodeDisplayInfo nodes[16];
    int node_count;
} DistPanelState;

static DistPanelState g_dist_panel = {0};
static HWND g_hDistPanel = NULL;

//==============================================================================
// Window Creation
//==============================================================================

HWND DistributedPanel_Create(HWND hWndParent, HINSTANCE hInstance,
                             int x, int y, int width, int height) {
    // Register window class
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = DistributedPanel_WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SovereignDistributedPanel";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    if (!RegisterClassEx(&wc)) {
        return NULL;
    }
    
    // Create panel window
    HWND hWnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "SovereignDistributedPanel",
        "Distributed Cluster",
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
    
    g_hDistPanel = hWnd;
    
    // Initialize fonts
    g_dist_panel.hFontNormal = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    
    g_dist_panel.hFontBold = CreateFont(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    
    // Create controls
    int margin = 10;
    int listHeight = 250;
    
    // Strategy combo
    g_dist_panel.hWndStrategyCombo = CreateWindow(
        "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        margin, margin, 200, 100,
        hWnd, (HMENU)IDC_DIST_STRATEGY_COMBO, hInstance, NULL
    );
    
    // Add strategy options
    SendMessage(g_dist_panel.hWndStrategyCombo, CB_ADDSTRING, 0, (LPARAM)"Tensor Parallel");
    SendMessage(g_dist_panel.hWndStrategyCombo, CB_ADDSTRING, 0, (LPARAM)"Pipeline Parallel");
    SendMessage(g_dist_panel.hWndStrategyCombo, CB_ADDSTRING, 0, (LPARAM)"Task Parallel");
    SendMessage(g_dist_panel.hWndStrategyCombo, CB_SETCURSEL, 0, 0);
    
    // Node list (ListView)
    g_dist_panel.hWndNodeList = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEW,
        "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        margin, margin + 40, width - margin * 2, listHeight,
        hWnd, (HMENU)IDC_DIST_NODE_LIST, hInstance, NULL
    );
    
    ListView_SetExtendedListViewStyle(g_dist_panel.hWndNodeList, 
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    // Add columns
    LVCOLUMN lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = (LPSTR)"Node";
    lvc.cx = 120;
    ListView_InsertColumn(g_dist_panel.hWndNodeList, 0, &lvc);
    
    lvc.pszText = (LPSTR)"Status";
    lvc.cx = 80;
    ListView_InsertColumn(g_dist_panel.hWndNodeList, 1, &lvc);
    
    lvc.pszText = (LPSTR)"TPS";
    lvc.cx = 80;
    ListView_InsertColumn(g_dist_panel.hWndNodeList, 2, &lvc);
    
    lvc.pszText = (LPSTR)"Latency";
    lvc.cx = 80;
    ListView_InsertColumn(g_dist_panel.hWndNodeList, 3, &lvc);
    
    lvc.pszText = (LPSTR)"Memory";
    lvc.cx = 80;
    ListView_InsertColumn(g_dist_panel.hWndNodeList, 4, &lvc);
    
    lvc.pszText = (LPSTR)"Reliability";
    lvc.cx = 80;
    ListView_InsertColumn(g_dist_panel.hWndNodeList, 5, &lvc);
    
    // Metrics labels
    int metricsY = margin + 40 + listHeight + 10;
    
    g_dist_panel.hWndClusterTPS = CreateWindow(
        "STATIC", "Cluster TPS: --",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, metricsY, 150, 20,
        hWnd, (HMENU)IDC_DIST_CLUSTER_TPS, hInstance, NULL
    );
    SendMessage(g_dist_panel.hWndClusterTPS, WM_SETFONT, 
                (WPARAM)g_dist_panel.hFontBold, TRUE);
    
    g_dist_panel.hWndActiveReqs = CreateWindow(
        "STATIC", "Active: --",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin + 160, metricsY, 120, 20,
        hWnd, (HMENU)IDC_DIST_ACTIVE_REQS, hInstance, NULL
    );
    
    g_dist_panel.hWndNodeCount = CreateWindow(
        "STATIC", "Nodes: --",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin + 290, metricsY, 100, 20,
        hWnd, (HMENU)IDC_DIST_NODE_COUNT, hInstance, NULL
    );
    
    // Buttons
    int btnY = height - margin - 30;
    
    g_dist_panel.hWndBenchmarkBtn = CreateWindow(
        "BUTTON", "Benchmark",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        margin, btnY, 100, 25,
        hWnd, (HMENU)IDC_DIST_BENCHMARK_BTN, hInstance, NULL
    );
    
    g_dist_panel.hWndRefreshBtn = CreateWindow(
        "BUTTON", "Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        margin + 110, btnY, 100, 25,
        hWnd, (HMENU)IDC_DIST_REFRESH_BTN, hInstance, NULL
    );
    
    // Initial refresh
    DistributedPanel_Refresh(hWnd);
    
    // Set up timer for live updates
    SetTimer(hWnd, TIMER_DIST_UPDATE, DIST_UPDATE_MS, NULL);
    
    // Register callback for metrics updates
    DistributedInference_SetModelPanelCallback(DistributedPanel_OnMetricsUpdate);
    
    Journal_LogUserRequest("Distributed panel created", "GUI");
    
    return hWnd;
}

void DistributedPanel_Destroy(HWND hWndPanel) {
    if (g_dist_panel.hFontNormal) {
        DeleteObject(g_dist_panel.hFontNormal);
    }
    if (g_dist_panel.hFontBold) {
        DeleteObject(g_dist_panel.hFontBold);
    }
    
    DistributedInference_SetModelPanelCallback(NULL);
    
    DestroyWindow(hWndPanel);
    g_hDistPanel = NULL;
}

//==============================================================================
// Refresh and Update
//==============================================================================

void DistributedPanel_Refresh(HWND hWndPanel) {
    if (!g_dist_panel.hWndNodeList) return;
    
    // Clear list
    ListView_DeleteAllItems(g_dist_panel.hWndNodeList);
    
    // Get cluster nodes
    RemoteNodeInfo nodes[16];
    int count;
    RemoteCluster_GetHealthyNodes(nodes, 16, &count);
    
    // Also get degraded/down nodes
    RemoteNodeInfo all_nodes[32];
    int all_count;
    RemoteCluster_GetAllNodes(all_nodes, 32, &all_count);
    
    // Populate list
    for (int i = 0; i < all_count; i++) {
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        
        // Node ID
        lvi.pszText = all_nodes[i].id;
        int item = ListView_InsertItem(g_dist_panel.hWndNodeList, &lvi);
        
        // Status
        const char* status_str = "Unknown";
        switch (all_nodes[i].health_state) {
            case NODE_STATE_HEALTHY: status_str = "Healthy"; break;
            case NODE_STATE_DEGRADED: status_str = "Degraded"; break;
            case NODE_STATE_DOWN: status_str = "Down"; break;
            case NODE_STATE_MAINTENANCE: status_str = "Maint"; break;
        }
        ListView_SetItemText(g_dist_panel.hWndNodeList, item, 1, (LPSTR)status_str);
        
        // TPS
        char tps_str[32];
        snprintf(tps_str, sizeof(tps_str), "%.1f", all_nodes[i].tokens_per_second);
        ListView_SetItemText(g_dist_panel.hWndNodeList, item, 2, (LPSTR)tps_str);
        
        // Latency
        char lat_str[32];
        snprintf(lat_str, sizeof(lat_str), "%llu ms", all_nodes[i].latency_ms);
        ListView_SetItemText(g_dist_panel.hWndNodeList, item, 3, (LPSTR)lat_str);
        
        // Memory
        char mem_str[32];
        snprintf(mem_str, sizeof(mem_str), "%llu MB", all_nodes[i].memory_available_mb);
        ListView_SetItemText(g_dist_panel.hWndNodeList, item, 4, (LPSTR)mem_str);
        
        // Reliability (placeholder)
        ListView_SetItemText(g_dist_panel.hWndNodeList, item, 5, (LPSTR)"100%");
    }
    
    // Update metrics
    DistributedPanel_UpdateMetrics(hWndPanel);
    
    Journal_LogUserRequest("Distributed panel refreshed", "");
}

void DistributedPanel_UpdateMetrics(HWND hWndPanel) {
    (void)hWndPanel;
    
    // Get cluster metrics
    float total_tps;
    uint64_t avg_latency;
    int active_reqs;
    DistributedInference_GetClusterMetrics(&total_tps, &avg_latency, &active_reqs);
    
    // Update labels
    char tps_str[64];
    snprintf(tps_str, sizeof(tps_str), "Cluster TPS: %.1f", total_tps);
    SetWindowText(g_dist_panel.hWndClusterTPS, tps_str);
    
    char active_str[64];
    snprintf(active_str, sizeof(active_str), "Active: %d", active_reqs);
    SetWindowText(g_dist_panel.hWndActiveReqs, active_str);
    
    RemoteNodeInfo nodes[32];
    int count;
    RemoteCluster_GetAllNodes(nodes, 32, &count);
    
    char node_str[64];
    snprintf(node_str, sizeof(node_str), "Nodes: %d", count);
    SetWindowText(g_dist_panel.hWndNodeCount, node_str);
}

//==============================================================================
// Window Procedure
//==============================================================================

LRESULT CALLBACK DistributedPanel_WndProc(HWND hWnd, UINT message, 
                                          WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            return 0;
            
        case WM_SIZE: {
            // Resize controls
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            
            int margin = 10;
            int listHeight = height - 150;
            
            SetWindowPos(g_dist_panel.hWndNodeList, NULL,
                        margin, margin + 40,
                        width - margin * 2, listHeight,
                        SWP_NOZORDER);
            
            return 0;
        }
        
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            
            switch (wmId) {
                case IDC_DIST_BENCHMARK_BTN:
                    DistributedPanel_RunBenchmark(hWnd);
                    break;
                    
                case IDC_DIST_REFRESH_BTN:
                    DistributedPanel_Refresh(hWnd);
                    break;
                    
                case IDC_DIST_STRATEGY_COMBO: {
                    if (HIWORD(wParam) == CBN_SELCHANGE) {
                        int sel = SendMessage(g_dist_panel.hWndStrategyCombo, 
                                             CB_GETCURSEL, 0, 0);
                        DistributedInference_SetStrategy(sel);
                    }
                    break;
                }
            }
            return 0;
        }
        
        case WM_TIMER: {
            if (wParam == TIMER_DIST_UPDATE) {
                DistributedPanel_UpdateMetrics(hWnd);
            }
            return 0;
        }
        
        case WM_DESTROY: {
            KillTimer(hWnd, TIMER_DIST_UPDATE);
            return 0;
        }
        
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
}

//==============================================================================
// Benchmark Integration
//==============================================================================

void DistributedPanel_RunBenchmark(HWND hWndPanel) {
    (void)hWndPanel;
    
    // Show dialog to select model
    MessageBox(hWndPanel, 
        "Running cluster benchmark...\n\nThis will test all healthy nodes.",
        "Benchmark", MB_OK | MB_ICONINFORMATION);
    
    // Run benchmark
    BenchmarkResult results[16];
    int count;
    
    DistributedInference_BenchmarkCluster(
        "llama-3.2-1b",  // Default test model
        "Hello, this is a benchmark test prompt.",
        results, 16, &count);
    
    // Show results
    DistributedPanel_ShowBenchmarkResults(hWndPanel, results, count);
    
    // Refresh display
    DistributedPanel_Refresh(hWndPanel);
    
    Journal_LogUserRequest("Cluster benchmark completed", "");
}

void DistributedPanel_ShowBenchmarkResults(HWND hWndPanel,
                                           const BenchmarkResult* results,
                                           int count) {
    (void)hWndPanel;
    
    // Build results string
    char msg[4096];
    int pos = snprintf(msg, sizeof(msg), 
        "Benchmark Results:\n\n"
        "%-20s %10s %10s %10s\n"
        "------------------------------------------------\n",
        "Node", "TPS", "Latency", "Memory");
    
    for (int i = 0; i < count && pos < (int)sizeof(msg) - 100; i++) {
        if (results[i].success) {
            pos += snprintf(msg + pos, sizeof(msg) - pos,
                "%-20s %10.1f %7llu ms %7llu MB\n",
                results[i].node_id,
                results[i].tokens_per_second,
                results[i].latency_ms,
                results[i].memory_used_mb);
        } else {
            pos += snprintf(msg + pos, sizeof(msg) - pos,
                "%-20s FAILED: %s\n",
                results[i].node_id,
                results[i].error_message);
        }
    }
    
    MessageBox(hWndPanel, msg, "Benchmark Results", MB_OK | MB_ICONINFORMATION);
}

//==============================================================================
// Strategy Selection
//==============================================================================

void DistributedPanel_SetStrategy(HWND hWndPanel, int strategy) {
    (void)hWndPanel;
    SendMessage(g_dist_panel.hWndStrategyCombo, CB_SETCURSEL, strategy, 0);
}

int DistributedPanel_GetStrategy(HWND hWndPanel) {
    (void)hWndPanel;
    return (int)SendMessage(g_dist_panel.hWndStrategyCombo, CB_GETCURSEL, 0, 0);
}

//==============================================================================
// Metrics Callback
//==============================================================================

void DistributedPanel_OnMetricsUpdate(const char* node_id,
                                       float tokens_per_sec,
                                       uint64_t latency_ms,
                                       int status) {
    (void)node_id;
    (void)tokens_per_sec;
    (void)latency_ms;
    (void)status;
    
    // Update specific node in list (could optimize to only update changed row)
    if (g_hDistPanel) {
        PostMessage(g_hDistPanel, WM_USER + 1, 0, 0);
    }
}
