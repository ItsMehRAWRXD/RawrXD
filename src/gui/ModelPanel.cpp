//==============================================================================
// ModelPanel.cpp - Phase 15A: GUI Model Panel Implementation
//
// Win32-based model management panel with:
// - ListView for model list
// - RichEdit for details display
// - Performance metrics
// - Hot-swap controls
// - ExecutionJournal integration
//==============================================================================

#include "ModelPanel.h"
#include "../core/ExecutionJournal.h"
#include <cstdio>
#include <cstring>
#include <commctrl.h>
#include <richedit.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "riched20.lib")

//==============================================================================
// Internal State
//==============================================================================

typedef struct ModelPanelState {
    HWND hWndList;           // Model list
    HWND hWndDetails;      // Details rich edit
    HWND hWndBtnDefault;     // Set default button
    HWND hWndBtnSwitch;      // Switch button
    HWND hWndBtnRefresh;     // Refresh button
    HWND hWndBtnBenchmark;   // Benchmark button
    HWND hWndStaticActive;   // Active model label
    HWND hWndStaticPerf;     // Performance label
    HWND hWndProgress;       // Loading progress
    HIMAGELIST hImageList;   // Model icons
    char selected_model[64]; // Currently selected model ID
    char active_model[64];   // Currently active model ID
    HFONT hFontNormal;       // Normal font
    HFONT hFontBold;         // Bold font
} ModelPanelState;

static ModelPanelState g_panel_state = {0};

//==============================================================================
// Helper Functions
//==============================================================================

static void FormatBytes(char* buf, size_t buf_size, size_t bytes) {
    if (bytes >= 1024 * 1024 * 1024) {
        snprintf(buf, buf_size, "%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024 * 1024) {
        snprintf(buf, buf_size, "%.1f MB", bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024) {
        snprintf(buf, buf_size, "%.1f KB", bytes / 1024.0);
    } else {
        snprintf(buf, buf_size, "%zu B", bytes);
    }
}

static void FormatNumber(char* buf, size_t buf_size, size_t num) {
    if (num >= 1000000000) {
        snprintf(buf, buf_size, "%.1fB", num / 1000000000.0);
    } else if (num >= 1000000) {
        snprintf(buf, buf_size, "%.1fM", num / 1000000.0);
    } else if (num >= 1000) {
        snprintf(buf, buf_size, "%.1fK", num / 1000.0);
    } else {
        snprintf(buf, buf_size, "%zu", num);
    }
}

static const char* GetCapabilityName(unsigned int cap) {
    switch (cap) {
        case CAP_CODE_GENERATION: return "Code Gen";
        case CAP_CODE_FIXING: return "Code Fix";
        case CAP_OPTIMIZATION: return "Optimize";
        case CAP_TRANSLATION: return "Translate";
        case CAP_REASONING: return "Reasoning";
        case CAP_CHAT: return "Chat";
        case CAP_EMBEDDINGS: return "Embeddings";
        case CAP_RAG: return "RAG";
        case CAP_MULTILINGUAL: return "Multi-lang";
        case CAP_MATH: return "Math";
        default: return "Unknown";
    }
}

static void BuildCapabilityString(char* buf, size_t buf_size, unsigned int caps) {
    buf[0] = '\0';
    size_t pos = 0;
    
    for (int i = 0; i < 32; i++) {
        unsigned int cap = 1u << i;
        if (caps & cap) {
            const char* name = GetCapabilityName(cap);
            if (pos > 0) {
                strncat(buf + pos, ", ", buf_size - pos - 1);
                pos += 2;
            }
            strncat(buf + pos, name, buf_size - pos - 1);
            pos += strlen(name);
        }
    }
}

//==============================================================================
// Window Creation
//==============================================================================

HWND ModelPanel_Create(HWND hWndParent, HINSTANCE hInstance, int x, int y, int width, int height) {
    // Register window class
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = ModelPanel_WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SovereignModelPanel";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    if (!RegisterClassEx(&wc)) {
        return NULL;
    }
    
    // Create panel window
    HWND hWnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "SovereignModelPanel",
        "Model Registry",
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
    
    // Initialize fonts
    g_panel_state.hFontNormal = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    
    g_panel_state.hFontBold = CreateFont(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    
    // Create controls
    int margin = 10;
    int listWidth = width / 2 - margin * 2;
    int detailWidth = width / 2 - margin * 2;
    int btnHeight = 25;
    int btnWidth = 80;
    
    // Active model label
    g_panel_state.hWndStaticActive = CreateWindow(
        "STATIC", "Active: None",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, margin, width - margin * 2, 20,
        hWnd, (HMENU)IDC_STATIC_ACTIVE, hInstance, NULL
    );
    SendMessage(g_panel_state.hWndStaticActive, WM_SETFONT, (WPARAM)g_panel_state.hFontBold, TRUE);
    
    // Model list
    g_panel_state.hWndList = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEW,
        "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        margin, margin + 30, listWidth, height - margin * 3 - 100,
        hWnd, (HMENU)IDC_MODEL_LIST, hInstance, NULL
    );
    
    ListView_SetExtendedListViewStyle(g_panel_state.hWndList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    // Add columns
    LVCOLUMN lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = (LPSTR)"Model";
    lvc.cx = listWidth - 60;
    ListView_InsertColumn(g_panel_state.hWndList, 0, &lvc);
    
    lvc.pszText = (LPSTR)"Status";
    lvc.cx = 50;
    ListView_InsertColumn(g_panel_state.hWndList, 1, &lvc);
    
    // Create image list
    g_panel_state.hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 5, 5);
    
    // Add placeholder icons (would load real icons in production)
    HICON hIconDefault = LoadIcon(NULL, IDI_APPLICATION);
    HICON hIconActive = LoadIcon(NULL, IDI_INFORMATION);
    HICON hIconLocal = LoadIcon(NULL, IDI_WINLOGO);
    HICON hIconRemote = LoadIcon(NULL, IDI_NETWORK);
    
    ImageList_AddIcon(g_panel_state.hImageList, hIconDefault);
    ImageList_AddIcon(g_panel_state.hImageList, hIconActive);
    ImageList_AddIcon(g_panel_state.hImageList, hIconLocal);
    ImageList_AddIcon(g_panel_state.hImageList, hIconRemote);
    
    ListView_SetImageList(g_panel_state.hWndList, g_panel_state.hImageList, LVSIL_SMALL);
    
    // Details rich edit
    g_panel_state.hWndDetails = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        RICHEDIT_CLASS,
        "",
        WS_CHILD | WS_VISIBLE | ES_READONLY | ES_MULTILINE | WS_VSCROLL,
        margin + listWidth + margin, margin + 30, detailWidth, height - margin * 3 - 100,
        hWnd, (HMENU)IDC_MODEL_DETAILS, hInstance, NULL
    );
    SendMessage(g_panel_state.hWndDetails, WM_SETFONT, (WPARAM)g_panel_state.hFontNormal, TRUE);
    
    // Buttons
    int btnY = height - margin - btnHeight;
    int btnX = margin;
    
    g_panel_state.hWndBtnDefault = CreateWindow(
        "BUTTON", "Set Default",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BTN_SET_DEFAULT, hInstance, NULL
    );
    EnableWindow(g_panel_state.hWndBtnDefault, FALSE);
    
    btnX += btnWidth + margin;
    g_panel_state.hWndBtnSwitch = CreateWindow(
        "BUTTON", "Switch",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BTN_SWITCH, hInstance, NULL
    );
    EnableWindow(g_panel_state.hWndBtnSwitch, FALSE);
    
    btnX += btnWidth + margin;
    g_panel_state.hWndBtnRefresh = CreateWindow(
        "BUTTON", "Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BTN_REFRESH, hInstance, NULL
    );
    
    btnX += btnWidth + margin;
    g_panel_state.hWndBtnBenchmark = CreateWindow(
        "BUTTON", "Benchmark",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth + 20, btnHeight,
        hWnd, (HMENU)IDC_BTN_BENCHMARK, hInstance, NULL
    );
    
    btnX += btnWidth + 20 + margin;
    HWND hWndBtnDownload = CreateWindow(
        "BUTTON", "Download",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BTN_DOWNLOAD, hInstance, NULL
    );
    
    btnX += btnWidth + margin;
    HWND hWndBtnDistributed = CreateWindow(
        "BUTTON", "Distributed",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth + 20, btnHeight,
        hWnd, (HMENU)IDC_BTN_DISTRIBUTED, hInstance, NULL
    );
    
    // Performance label
    g_panel_state.hWndStaticPerf = CreateWindow(
        "STATIC", "Performance: --",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, btnY - 25, width - margin * 2, 20,
        hWnd, (HMENU)IDC_STATIC_PERFORMANCE, hInstance, NULL
    );
    SendMessage(g_panel_state.hWndStaticPerf, WM_SETFONT, (WPARAM)g_panel_state.hFontNormal, TRUE);
    
    // Initial refresh
    ModelPanel_Refresh(hWnd);
    
    // Set up performance timer
    SetTimer(hWnd, TIMER_PERFORMANCE_UPDATE, PERFORMANCE_UPDATE_MS, NULL);
    
    return hWnd;
}

void ModelPanel_Destroy(HWND hWndPanel) {
    if (g_panel_state.hFontNormal) {
        DeleteObject(g_panel_state.hFontNormal);
    }
    if (g_panel_state.hFontBold) {
        DeleteObject(g_panel_state.hFontBold);
    }
    if (g_panel_state.hImageList) {
        ImageList_Destroy(g_panel_state.hImageList);
    }
    DestroyWindow(hWndPanel);
}

//==============================================================================
// Refresh and Update
//==============================================================================

void ModelPanel_Refresh(HWND hWndPanel) {
    if (!g_panel_state.hWndList) return;
    
    // Clear list
    ListView_DeleteAllItems(g_panel_state.hWndList);
    
    // Get models from registry
    ModelInfo models[MAX_MODELS];
    int count;
    ModelRegistry_ListModels(models, MAX_MODELS, &count);
    
    // Get active model
    ModelInfo active_model;
    BOOL has_active = (ModelRegistry_GetActiveModel(&active_model) == 0);
    if (has_active) {
        strncpy(g_panel_state.active_model, active_model.id, sizeof(g_panel_state.active_model) - 1);
    }
    
    // Populate list
    for (int i = 0; i < count; i++) {
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT | LVIF_IMAGE;
        lvi.iItem = i;
        
        // Determine icon
        if (strcmp(models[i].id, g_panel_state.active_model) == 0) {
            lvi.iImage = ICON_MODEL_ACTIVE;
        } else if (models[i].is_local) {
            lvi.iImage = ICON_MODEL_LOCAL;
        } else {
            lvi.iImage = ICON_MODEL_REMOTE;
        }
        
        // Model name with params
        char name_buf[128];
        char param_buf[32];
        FormatNumber(param_buf, sizeof(param_buf), models[i].parameter_count);
        snprintf(name_buf, sizeof(name_buf), "%s (%s)", models[i].name, param_buf);
        lvi.pszText = name_buf;
        
        int item = ListView_InsertItem(g_panel_state.hWndList, &lvi);
        
        // Status
        char status_buf[32];
        if (strcmp(models[i].id, g_panel_state.active_model) == 0) {
            strcpy(status_buf, "Active");
        } else if (models[i].is_default) {
            strcpy(status_buf, "Default");
        } else {
            strcpy(status_buf, "");
        }
        ListView_SetItemText(g_panel_state.hWndList, item, 1, status_buf);
        
        // Store model ID as item data
        ListView_SetItemData(g_panel_state.hWndList, item, (LPARAM)i);
    }
    
    // Update active label
    if (has_active) {
        char label[256];
        snprintf(label, sizeof(label), "Active: %s", active_model.name);
        SetWindowText(g_panel_state.hWndStaticActive, label);
    }
    
    // Log refresh
    Journal_LogUserRequest("Model panel refreshed", "GUI update");
}

void ModelPanel_UpdatePerformance(HWND hWndPanel) {
    if (!g_panel_state.hWndStaticPerf) return;
    
    ModelInfo active_model;
    if (ModelRegistry_GetActiveModel(&active_model) != 0) {
        SetWindowText(g_panel_state.hWndStaticPerf, "Performance: No active model");
        return;
    }
    
    char perf_buf[256];
    char mem_buf[32];
    FormatBytes(mem_buf, sizeof(mem_buf), active_model.memory_required_mb * 1024 * 1024);
    
    snprintf(perf_buf, sizeof(perf_buf),
        "Performance: %.1f tok/s | Memory: %s | Context: %dK",
        active_model.tokens_per_second,
        mem_buf,
        active_model.context_window / 1024);
    
    SetWindowText(g_panel_state.hWndStaticPerf, perf_buf);
}

void ModelPanel_ShowModelDetails(HWND hWndPanel, const ModelInfo* model) {
    if (!g_panel_state.hWndDetails || !model) return;
    
    char details[2048];
    char params_buf[32];
    char mem_buf[32];
    char caps_buf[256];
    
    FormatNumber(params_buf, sizeof(params_buf), model->parameter_count);
    FormatBytes(mem_buf, sizeof(mem_buf), model->memory_required_mb * 1024 * 1024);
    BuildCapabilityString(caps_buf, sizeof(caps_buf), model->capabilities);
    
    snprintf(details, sizeof(details),
        "Model: %s\r\n"
        "ID: %s\r\n"
        "Parameters: %s\r\n"
        "Context Window: %d tokens\r\n"
        "Embedding: %d dims\r\n"
        "Layers: %d\r\n"
        "Heads: %d\r\n"
        "\r\n"
        "Backend: %s\r\n"
        "Path: %s\r\n"
        "\r\n"
        "Capabilities:\r\n%s\r\n"
        "\r\n"
        "Performance:\r\n"
        "  Tokens/sec: %.1f\r\n"
        "  Memory: %s\r\n"
        "\r\n"
        "Status: %s%s\r\n",
        model->name,
        model->id,
        params_buf,
        model->context_window,
        model->embedding_dim,
        model->num_layers,
        model->num_heads,
        model->backend_type,
        model->path,
        caps_buf[0] ? caps_buf : "None",
        model->tokens_per_second,
        mem_buf,
        model->is_default ? "Default " : "",
        model->is_loaded ? "Loaded" : "Not Loaded"
    );
    
    SetWindowText(g_panel_state.hWndDetails, details);
}

void ModelPanel_OnModelSelected(HWND hWndPanel, int index) {
    if (index < 0) {
        EnableWindow(g_panel_state.hWndBtnDefault, FALSE);
        EnableWindow(g_panel_state.hWndBtnSwitch, FALSE);
        SetWindowText(g_panel_state.hWndDetails, "");
        return;
    }
    
    // Get model info
    int model_idx = (int)ListView_GetItemData(g_panel_state.hWndList, index);
    ModelInfo models[MAX_MODELS];
    int count;
    ModelRegistry_ListModels(models, MAX_MODELS, &count);
    
    if (model_idx >= 0 && model_idx < count) {
        ModelPanel_ShowModelDetails(hWndPanel, &models[model_idx]);
        strncpy(g_panel_state.selected_model, models[model_idx].id, sizeof(g_panel_state.selected_model) - 1);
        
        // Enable buttons
        EnableWindow(g_panel_state.hWndBtnDefault, TRUE);
        EnableWindow(g_panel_state.hWndBtnSwitch, TRUE);
        
        // Log selection
        char desc[256];
        snprintf(desc, sizeof(desc), "Selected model: %s", models[model_idx].name);
        Journal_LogUserRequest(desc, "GUI");
    }
}

//==============================================================================
// Window Procedure
//==============================================================================

LRESULT CALLBACK ModelPanel_WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            return 0;
        }
        
        case WM_SIZE: {
            // Resize controls
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            
            // TODO: Implement proper resizing
            return 0;
        }
        
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            
            switch (wmId) {
                case IDC_BTN_SET_DEFAULT: {
                    if (g_panel_state.selected_model[0]) {
                        ModelRegistry_SetDefaultModel(g_panel_state.selected_model);
                        ModelPanel_Refresh(hWnd);
                        
                        char msg[256];
                        snprintf(msg, sizeof(msg), "Set default model: %s", g_panel_state.selected_model);
                        Journal_LogUserRequest(msg, "GUI");
                    }
                    break;
                }
                
                case IDC_BTN_SWITCH: {
                    if (g_panel_state.selected_model[0]) {
                        ModelRegistry_SwitchModel(g_panel_state.selected_model);
                        ModelPanel_Refresh(hWnd);
                        ModelPanel_UpdatePerformance(hWnd);
                        
                        char msg[256];
                        snprintf(msg, sizeof(msg), "Switched to model: %s", g_panel_state.selected_model);
                        Journal_LogUserRequest(msg, "GUI");
                    }
                    break;
                }
                
                case IDC_BTN_REFRESH: {
                    ModelPanel_Refresh(hWnd);
                    break;
                }
                
                case IDC_BTN_BENCHMARK: {
                    if (g_panel_state.selected_model[0]) {
                        // TODO: Run benchmark
                        MessageBox(hWnd, "Benchmark not yet implemented", "Info", MB_OK);
                    }
                    break;
                }
                
                case IDC_BTN_DOWNLOAD: {
                    // Open download dialog
                    extern BOOL ModelDownloadDialog_Show(HWND hWndParent, HINSTANCE hInstance);
                    ModelDownloadDialog_Show(hWnd, GetModuleHandle(NULL));
                    // Refresh after dialog closes
                    ModelPanel_Refresh(hWnd);
                    break;
                }
                
                case IDC_BTN_DISTRIBUTED: {
                    // Open distributed cluster panel
                    extern HWND DistributedPanel_Create(HWND hWndParent, HINSTANCE hInstance,
                                                         int x, int y, int width, int height);
                    HWND hDistPanel = DistributedPanel_Create(hWnd, GetModuleHandle(NULL),
                                                              10, 10, 580, 480);
                    ShowWindow(hDistPanel, SW_SHOW);
                    break;
                }
            }
            return 0;
        }
        
        case WM_NOTIFY: {
            LPNMHDR pnmh = (LPNMHDR)lParam;
            
            if (pnmh->idFrom == IDC_MODEL_LIST && pnmh->code == LVN_ITEMCHANGED) {
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                if (pnmv->uNewState & LVIS_SELECTED) {
                    ModelPanel_OnModelSelected(hWnd, pnmv->iItem);
                }
            }
            return 0;
        }
        
        case WM_TIMER: {
            if (wParam == TIMER_PERFORMANCE_UPDATE) {
                ModelPanel_UpdatePerformance(hWnd);
            }
            return 0;
        }
        
        case WM_DESTROY: {
            KillTimer(hWnd, TIMER_PERFORMANCE_UPDATE);
            return 0;
        }
        
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
}

//==============================================================================
// Integration Functions
//==============================================================================

void ModelPanel_AddMenuItem(HWND hWndMenu) {
    // Add "View -> Model Panel" menu item
    AppendMenu(hWndMenu, MF_STRING, 1000, "Model Panel\tCtrl+M");
}

void ModelPanel_Show(HWND hWndPanel, BOOL show) {
    ShowWindow(hWndPanel, show ? SW_SHOW : SW_HIDE);
}

BOOL ModelPanel_IsVisible(HWND hWndPanel) {
    return IsWindowVisible(hWndPanel);
}

void ModelPanel_Toggle(HWND hWndPanel) {
    if (ModelPanel_IsVisible(hWndPanel)) {
        ModelPanel_Show(hWndPanel, FALSE);
    } else {
        ModelPanel_Show(hWndPanel, TRUE);
        ModelPanel_Refresh(hWndPanel);
    }
}

void ModelPanel_InitControls(HINSTANCE hInstance) {
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = {0};
    iccex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    iccex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&iccex);
    
    // Load RichEdit
    LoadLibrary("riched20.dll");
}

HIMAGELIST ModelPanel_CreateImageList(HINSTANCE hInstance) {
    HIMAGELIST img = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 5, 5);
    
    // TODO: Load icons from resources
    // ImageList_Add(img, LoadIcon(...), NULL);
    
    return img;
}

void ModelPanel_SetActiveModel(HWND hWndPanel, const char* model_id) {
    if (!model_id) return;
    
    strncpy(g_panel_state.active_model, model_id, sizeof(g_panel_state.active_model) - 1);
    g_panel_state.active_model[sizeof(g_panel_state.active_model) - 1] = '\0';
    
    // Update the active model label
    ModelInfo model;
    if (ModelRegistry_GetModel(model_id, &model) == 0) {
        char label[256];
        snprintf(label, sizeof(label), "Active: %s", model.name);
        SetWindowText(g_panel_state.hWndStaticActive, label);
    }
    
    // Refresh the list to update icons
    ModelPanel_Refresh(hWndPanel);
}
