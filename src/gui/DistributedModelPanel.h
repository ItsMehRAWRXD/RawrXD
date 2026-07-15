//==============================================================================
// DistributedModelPanel.h - Phase 15C: Distributed Cluster GUI Panel
//
// Real-time visualization of distributed inference cluster:
// - Node status grid with live metrics
// - Cluster throughput graph
// - Request distribution visualization
// - Benchmark results display
// - Node selection for targeting
//==============================================================================

#ifndef DISTRIBUTED_MODEL_PANEL_H
#define DISTRIBUTED_MODEL_PANEL_H

#include <windows.h>
#include <commctrl.h>
#include "../core/DistributedInference.h"

// Panel dimensions
#define DISTPANEL_WIDTH        600
#define DISTPANEL_HEIGHT       500

// Control IDs
#define IDC_DIST_NODE_LIST      3001
#define IDC_DIST_METRICS_GRAPH  3002
#define IDC_DIST_BENCHMARK_BTN  3003
#define IDC_DIST_REFRESH_BTN    3004
#define IDC_DIST_STRATEGY_COMBO 3005
#define IDC_DIST_CLUSTER_TPS    3006
#define IDC_DIST_ACTIVE_REQS    3007
#define IDC_DIST_NODE_COUNT     3008
#define IDC_DIST_TARGET_CHECK   3009

// Timer for live updates
#define TIMER_DIST_UPDATE       300
#define DIST_UPDATE_MS          2000

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Panel Functions
//==============================================================================

// Create distributed cluster panel
HWND DistributedPanel_Create(HWND hWndParent, HINSTANCE hInstance, 
                             int x, int y, int width, int height);

// Destroy panel
void DistributedPanel_Destroy(HWND hWndPanel);

// Refresh node list
void DistributedPanel_Refresh(HWND hWndPanel);

// Update metrics display
void DistributedPanel_UpdateMetrics(HWND hWndPanel);

// Window procedure
LRESULT CALLBACK DistributedPanel_WndProc(HWND hWnd, UINT message, 
                                          WPARAM wParam, LPARAM lParam);

//==============================================================================
// Node Display
//==============================================================================

typedef struct NodeDisplayInfo {
    char node_id[64];
    float tps;
    uint64_t latency;
    uint64_t memory_mb;
    float reliability;
    int status;  // 1=healthy, 0=degraded, -1=down
    int is_targeted;
} NodeDisplayInfo;

void DistributedPanel_SetNodeData(HWND hWndPanel, const NodeDisplayInfo* nodes, 
                                  int count);

//==============================================================================
// Benchmark Integration
//==============================================================================

void DistributedPanel_RunBenchmark(HWND hWndPanel);
void DistributedPanel_ShowBenchmarkResults(HWND hWndPanel, 
                                             const BenchmarkResult* results,
                                             int count);

//==============================================================================
// Strategy Selection
//==============================================================================

void DistributedPanel_SetStrategy(HWND hWndPanel, int strategy);
int DistributedPanel_GetStrategy(HWND hWndPanel);

//==============================================================================
// Callback for metrics updates
//==============================================================================

void DistributedPanel_OnMetricsUpdate(const char* node_id, 
                                      float tokens_per_sec,
                                      uint64_t latency_ms,
                                      int status);

#ifdef __cplusplus
}
#endif

#endif // DISTRIBUTED_MODEL_PANEL_H
