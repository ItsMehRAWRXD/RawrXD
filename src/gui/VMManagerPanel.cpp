//==============================================================================
// VMManagerPanel.cpp - Phase 16: VM Management GUI Implementation
//==============================================================================

#include "VMManagerPanel.h"
#include "../core/SovereignHypervisor.h"
#include "../core/ExecutionJournal.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

//==============================================================================
// Internal State
//==============================================================================

typedef struct VMPanelState {
    HWND hWndVMList;
    HWND hWndCreateBtn;
    HWND hWndStartBtn;
    HWND hWndStopBtn;
    HWND hWndDestroyBtn;
    HWND hWndCheckpointBtn;
    HWND hWndRefreshBtn;
    HWND hWndTypeCombo;
    HWND hWndMemoryEdit;
    HWND hWndCPUEdit;
    HWND hWndSandboxSlider;
    HWND hWndTenantCombo;
    HWND hWndMetricsList;
    HFONT hFontNormal;
    HFONT hFontBold;
    char selected_vm[MAX_VM_ID];
} VMPanelState;

static VMPanelState g_vm_panel = {0};
static HWND g_hVMPanel = NULL;

//==============================================================================
// Window Creation
//==============================================================================

HWND VMManagerPanel_Create(HWND hWndParent, HINSTANCE hInstance,
                           int x, int y, int width, int height) {
    // Register window class
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = VMManagerPanel_WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SovereignVMPanel";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    if (!RegisterClassEx(&wc)) {
        return NULL;
    }

    // Create panel window
    HWND hWnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "SovereignVMPanel",
        "VM Manager",
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

    g_hVMPanel = hWnd;

    // Initialize fonts
    g_vm_panel.hFontNormal = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    g_vm_panel.hFontBold = CreateFont(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    // Create controls
    int margin = 10;
    int listHeight = 200;

    // VM list (ListView)
    g_vm_panel.hWndVMList = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEW,
        "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        margin, margin, width - margin * 2, listHeight,
        hWnd, (HMENU)IDC_VM_LIST, hInstance, NULL
    );

    ListView_SetExtendedListViewStyle(g_vm_panel.hWndVMList,
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Add columns
    LVCOLUMN lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.pszText = (LPSTR)"VM ID";
    lvc.cx = 80;
    ListView_InsertColumn(g_vm_panel.hWndVMList, 0, &lvc);

    lvc.pszText = (LPSTR)"Name";
    lvc.cx = 120;
    ListView_InsertColumn(g_vm_panel.hWndVMList, 1, &lvc);

    lvc.pszText = (LPSTR)"State";
    lvc.cx = 80;
    ListView_InsertColumn(g_vm_panel.hWndVMList, 2, &lvc);

    lvc.pszText = (LPSTR)"Type";
    lvc.cx = 70;
    ListView_InsertColumn(g_vm_panel.hWndVMList, 3, &lvc);

    lvc.pszText = (LPSTR)"Memory";
    lvc.cx = 70;
    ListView_InsertColumn(g_vm_panel.hWndVMList, 4, &lvc);

    lvc.pszText = (LPSTR)"CPU";
    lvc.cx = 50;
    ListView_InsertColumn(g_vm_panel.hWndVMList, 5, &lvc);

    lvc.pszText = (LPSTR)"Sandbox";
    lvc.cx = 60;
    ListView_InsertColumn(g_vm_panel.hWndVMList, 6, &lvc);

    lvc.pszText = (LPSTR)"Tenant";
    lvc.cx = 80;
    ListView_InsertColumn(g_vm_panel.hWndVMList, 7, &lvc);

    // Control buttons
    int btnY = margin + listHeight + 10;
    int btnX = margin;
    int btnWidth = 80;
    int btnHeight = 25;

    g_vm_panel.hWndCreateBtn = CreateWindow(
        "BUTTON", "Create",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_VM_CREATE_BTN, hInstance, NULL
    );

    btnX += btnWidth + margin;
    g_vm_panel.hWndStartBtn = CreateWindow(
        "BUTTON", "Start",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_VM_START_BTN, hInstance, NULL
    );

    btnX += btnWidth + margin;
    g_vm_panel.hWndStopBtn = CreateWindow(
        "BUTTON", "Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_VM_STOP_BTN, hInstance, NULL
    );

    btnX += btnWidth + margin;
    g_vm_panel.hWndDestroyBtn = CreateWindow(
        "BUTTON", "Destroy",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_VM_DESTROY_BTN, hInstance, NULL
    );

    btnX += btnWidth + margin;
    g_vm_panel.hWndCheckpointBtn = CreateWindow(
        "BUTTON", "Checkpoint",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth + 20, btnHeight,
        hWnd, (HMENU)IDC_VM_CHECKPOINT_BTN, hInstance, NULL
    );

    btnX += btnWidth + 30;
    g_vm_panel.hWndRefreshBtn = CreateWindow(
        "BUTTON", "Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, btnY, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_VM_REFRESH_BTN, hInstance, NULL
    );

    // Configuration section
    int configY = btnY + btnHeight + 20;

    // Type combo
    HWND lblType = CreateWindow("STATIC", "Type:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, configY, 50, 20, hWnd, NULL, hInstance, NULL);

    g_vm_panel.hWndTypeCombo = CreateWindow("COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        margin + 60, configY, 100, 100,
        hWnd, (HMENU)IDC_VM_TYPE_COMBO, hInstance, NULL);

    SendMessage(g_vm_panel.hWndTypeCombo, CB_ADDSTRING, 0, (LPARAM)"Micro");
    SendMessage(g_vm_panel.hWndTypeCombo, CB_ADDSTRING, 0, (LPARAM)"Standard");
    SendMessage(g_vm_panel.hWndTypeCombo, CB_ADDSTRING, 0, (LPARAM)"Heavy");
    SendMessage(g_vm_panel.hWndTypeCombo, CB_SETCURSEL, 1, 0);

    // Memory edit
    HWND lblMem = CreateWindow("STATIC", "Memory (MB):",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin + 180, configY, 80, 20, hWnd, NULL, hInstance, NULL);

    g_vm_panel.hWndMemoryEdit = CreateWindow("EDIT", "512",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
        margin + 270, configY, 60, 20,
        hWnd, (HMENU)IDC_VM_MEMORY_EDIT, hInstance, NULL);

    // CPU edit
    HWND lblCPU = CreateWindow("STATIC", "CPU:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin + 350, configY, 40, 20, hWnd, NULL, hInstance, NULL);

    g_vm_panel.hWndCPUEdit = CreateWindow("EDIT", "2",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
        margin + 400, configY, 40, 20,
        hWnd, (HMENU)IDC_VM_CPU_EDIT, hInstance, NULL);

    // Sandbox slider
    HWND lblSandbox = CreateWindow("STATIC", "Sandbox Level:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, configY + 30, 100, 20, hWnd, NULL, hInstance, NULL);

    g_vm_panel.hWndSandboxSlider = CreateWindow(TRACKBAR_CLASS, "",
        WS_CHILD | WS_VISIBLE | TBS_AUTOTICKS | TBS_HORZ,
        margin + 110, configY + 30, 150, 30,
        hWnd, (HMENU)IDC_VM_SANDBOX_SLIDER, hInstance, NULL);

    SendMessage(g_vm_panel.hWndSandboxSlider, TBM_SETRANGE, TRUE, MAKELPARAM(0, 3));
    SendMessage(g_vm_panel.hWndSandboxSlider, TBM_SETPOS, TRUE, 1);
    SendMessage(g_vm_panel.hWndSandboxSlider, TBM_SETTICFREQ, 1, 0);

    // Initial refresh
    VMManagerPanel_Refresh(hWnd);

    // Set up timer for live updates
    SetTimer(hWnd, TIMER_VM_UPDATE, VM_UPDATE_MS, NULL);

    Journal_LogUserRequest("VM Manager panel created", "GUI");

    return hWnd;
}

void VMManagerPanel_Destroy(HWND hWndPanel) {
    if (g_vm_panel.hFontNormal) {
        DeleteObject(g_vm_panel.hFontNormal);
    }
    if (g_vm_panel.hFontBold) {
        DeleteObject(g_vm_panel.hFontBold);
    }

    DestroyWindow(hWndPanel);
    g_hVMPanel = NULL;
}

//==============================================================================
// Refresh and Update
//==============================================================================

void VMManagerPanel_Refresh(HWND hWndPanel) {
    if (!g_vm_panel.hWndVMList) return;

    // Clear list
    ListView_DeleteAllItems(g_vm_panel.hWndVMList);

    // Get all VMs
    VMInfo vms[32];
    int count;
    SovereignVM_List(vms, 32, &count);

    // Populate list
    for (int i = 0; i < count; i++) {
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;

        // VM ID
        lvi.pszText = vms[i].id;
        int item = ListView_InsertItem(g_vm_panel.hWndVMList, &lvi);

        // Name
        ListView_SetItemText(g_vm_panel.hWndVMList, item, 1, (LPSTR)vms[i].name);

        // State
        ListView_SetItemText(g_vm_panel.hWndVMList, item, 2,
                            (LPSTR)SovereignVM_StateToString(vms[i].state));

        // Type
        ListView_SetItemText(g_vm_panel.hWndVMList, item, 3,
                            (LPSTR)SovereignVM_TypeToString(vms[i].type));

        // Memory
        char memStr[32];
        snprintf(memStr, sizeof(memStr), "%u MB", vms[i].memory_mb);
        ListView_SetItemText(g_vm_panel.hWndVMList, item, 4, (LPSTR)memStr);

        // CPU
        char cpuStr[32];
        snprintf(cpuStr, sizeof(cpuStr), "%u", vms[i].cpu_count);
        ListView_SetItemText(g_vm_panel.hWndVMList, item, 5, (LPSTR)cpuStr);

        // Sandbox
        char sbStr[32];
        snprintf(sbStr, sizeof(sbStr), "L%d", vms[i].sandbox_level);
        ListView_SetItemText(g_vm_panel.hWndVMList, item, 6, (LPSTR)sbStr);

        // Tenant
        ListView_SetItemText(g_vm_panel.hWndVMList, item, 7,
                            (LPSTR)(vms[i].tenant[0] ? vms[i].tenant : "-"));
    }

    Journal_LogUserRequest("VM panel refreshed", "");
}

void VMManagerPanel_UpdateMetrics(HWND hWndPanel) {
    (void)hWndPanel;
    // Update resource usage for selected VM
}

//==============================================================================
// Window Procedure
//==============================================================================

LRESULT CALLBACK VMManagerPanel_WndProc(HWND hWnd, UINT message,
                                        WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            return 0;

        case WM_SIZE: {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);

            int margin = 10;
            int listHeight = height - 200;

            SetWindowPos(g_vm_panel.hWndVMList, NULL,
                        margin, margin,
                        width - margin * 2, listHeight,
                        SWP_NOZORDER);

            return 0;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);

            switch (wmId) {
                case IDC_VM_CREATE_BTN:
                    VMManagerPanel_CreateVM(hWnd);
                    break;

                case IDC_VM_START_BTN:
                    VMManagerPanel_StartVM(hWnd);
                    break;

                case IDC_VM_STOP_BTN:
                    VMManagerPanel_StopVM(hWnd);
                    break;

                case IDC_VM_DESTROY_BTN:
                    VMManagerPanel_DestroyVM(hWnd);
                    break;

                case IDC_VM_CHECKPOINT_BTN:
                    VMManagerPanel_CheckpointVM(hWnd);
                    break;

                case IDC_VM_REFRESH_BTN:
                    VMManagerPanel_Refresh(hWnd);
                    break;
            }
            return 0;
        }

        case WM_NOTIFY: {
            LPNMHDR pnmh = (LPNMHDR)lParam;

            if (pnmh->idFrom == IDC_VM_LIST && pnmh->code == LVN_ITEMCHANGED) {
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                if (pnmv->uNewState & LVIS_SELECTED) {
                    // Get selected VM ID
                    LVITEM lvi = {0};
                    lvi.iItem = pnmv->iItem;
                    lvi.pszText = g_vm_panel.selected_vm;
                    lvi.cchTextMax = sizeof(g_vm_panel.selected_vm);
                    lvi.mask = LVIF_TEXT;
                    ListView_GetItem(g_vm_panel.hWndVMList, &lvi);
                }
            }
            return 0;
        }

        case WM_TIMER: {
            if (wParam == TIMER_VM_UPDATE) {
                VMManagerPanel_UpdateMetrics(hWnd);
            }
            return 0;
        }

        case WM_DESTROY: {
            KillTimer(hWnd, TIMER_VM_UPDATE);
            return 0;
        }

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
}

//==============================================================================
// VM Operations
//==============================================================================

void VMManagerPanel_CreateVM(HWND hWndPanel) {
    (void)hWndPanel;

    // Get configuration from controls
    char name[64];
    GetWindowText(g_vm_panel.hWndMemoryEdit, name, sizeof(name));

    int typeIdx = SendMessage(g_vm_panel.hWndTypeCombo, CB_GETCURSEL, 0, 0);
    VMType type = (VMType)typeIdx;

    char memStr[32];
    GetWindowText(g_vm_panel.hWndMemoryEdit, memStr, sizeof(memStr));
    uint32_t memory = atoi(memStr);

    char cpuStr[32];
    GetWindowText(g_vm_panel.hWndCPUEdit, cpuStr, sizeof(cpuStr));
    uint32_t cpu = atoi(cpuStr);

    int sandbox = SendMessage(g_vm_panel.hWndSandboxSlider, TBM_GETPOS, 0, 0);

    // Create VM config
    VMConfig config = {0};
    snprintf(config.name, sizeof(config.name), "vm-%s", name);
    config.type = type;
    config.memory_mb = memory;
    config.cpu_count = cpu;
    config.enable_seccomp = (sandbox >= 2);
    config.read_only_root = (sandbox >= 3);

    // Create VM
    char vm_id[32];
    if (SovereignVM_Create(&config, vm_id, sizeof(vm_id)) == 0) {
        // Set sandbox level
        SovereignVM_SetSandboxLevel(vm_id, sandbox);

        // Start VM
        SovereignVM_Start(vm_id);

        MessageBox(hWndPanel, "VM created and started successfully!",
                    "Success", MB_OK | MB_ICONINFORMATION);

        VMManagerPanel_Refresh(hWndPanel);
    } else {
        MessageBox(hWndPanel, "Failed to create VM",
                    "Error", MB_OK | MB_ICONERROR);
    }
}

void VMManagerPanel_StartVM(HWND hWndPanel) {
    if (g_vm_panel.selected_vm[0] == '\0') {
        MessageBox(hWndPanel, "Please select a VM", "Error", MB_OK | MB_ICONWARNING);
        return;
    }

    if (SovereignVM_Start(g_vm_panel.selected_vm) == 0) {
        VMManagerPanel_Refresh(hWndPanel);
    } else {
        MessageBox(hWndPanel, "Failed to start VM", "Error", MB_OK | MB_ICONERROR);
    }
}

void VMManagerPanel_StopVM(HWND hWndPanel) {
    if (g_vm_panel.selected_vm[0] == '\0') {
        MessageBox(hWndPanel, "Please select a VM", "Error", MB_OK | MB_ICONWARNING);
        return;
    }

    if (SovereignVM_Stop(g_vm_panel.selected_vm, 5000) == 0) {
        VMManagerPanel_Refresh(hWndPanel);
    } else {
        MessageBox(hWndPanel, "Failed to stop VM", "Error", MB_OK | MB_ICONERROR);
    }
}

void VMManagerPanel_DestroyVM(HWND hWndPanel) {
    if (g_vm_panel.selected_vm[0] == '\0') {
        MessageBox(hWndPanel, "Please select a VM", "Error", MB_OK | MB_ICONWARNING);
        return;
    }

    int result = MessageBox(hWndPanel,
        "Are you sure you want to destroy this VM?\nThis action cannot be undone.",
        "Confirm Destroy", MB_YESNO | MB_ICONWARNING);

    if (result == IDYES) {
        if (SovereignVM_Destroy(g_vm_panel.selected_vm) == 0) {
            g_vm_panel.selected_vm[0] = '\0';
            VMManagerPanel_Refresh(hWndPanel);
        } else {
            MessageBox(hWndPanel, "Failed to destroy VM", "Error", MB_OK | MB_ICONERROR);
        }
    }
}

void VMManagerPanel_CheckpointVM(HWND hWndPanel) {
    if (g_vm_panel.selected_vm[0] == '\0') {
        MessageBox(hWndPanel, "Please select a VM", "Error", MB_OK | MB_ICONWARNING);
        return;
    }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "checkpoints/%s.chk", g_vm_panel.selected_vm);

    if (SovereignVM_Checkpoint(g_vm_panel.selected_vm, path) == 0) {
        MessageBox(hWndPanel, "Checkpoint created successfully!",
                    "Success", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBox(hWndPanel, "Failed to create checkpoint",
                    "Error", MB_OK | MB_ICONERROR);
    }
}

void VMManagerPanel_RestoreVM(HWND hWndPanel) {
    // Implementation for restore
    (void)hWndPanel;
}

//==============================================================================
// Sandbox Controls
//==============================================================================

void VMManagerPanel_SetSandboxLevel(HWND hWndPanel, int level) {
    if (g_vm_panel.selected_vm[0] == '\0') {
        MessageBox(hWndPanel, "Please select a VM", "Error", MB_OK | MB_ICONWARNING);
        return;
    }

    SovereignVM_SetSandboxLevel(g_vm_panel.selected_vm, level);
    VMManagerPanel_Refresh(hWndPanel);
}

void VMManagerPanel_ApplySecurityProfile(HWND hWndPanel, const char* profile) {
    (void)hWndPanel;
    (void)profile;
    // Apply security profile
}

//==============================================================================
// Tenant Management
//==============================================================================

void VMManagerPanel_CreateTenant(HWND hWndPanel) {
    (void)hWndPanel;
    // Create tenant dialog
}

void VMManagerPanel_AssignTenant(HWND hWndPanel, const char* vm_id, const char* tenant) {
    (void)hWndPanel;
    SovereignVM_SetTenant(vm_id, tenant);
}

void VMManagerPanel_ShowTenantUsage(HWND hWndPanel, const char* tenant) {
    (void)hWndPanel;
    (void)tenant;
    // Show tenant usage dialog
}
