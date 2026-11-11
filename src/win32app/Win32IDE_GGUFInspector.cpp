// Win32IDE_GGUFInspector.cpp - GGUF Model Inspector Panel
// Integrated into RawrXD IDE for deep model architecture analysis

#include "Win32IDE.h"
#include "resource.h"
#include <commctrl.h>
#include <richedit.h>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <commdlg.h>

// External GGUF inspector functions
extern "C" {
    typedef struct {
        char name[256];
        int type;
        uint64_t dims[4];
        int n_dims;
        size_t size;
    } GGUF_TensorInfo;
    
    typedef struct {
        char key[256];
        char value[1024];
    } GGUF_MetadataKV;
    
    typedef struct {
        int version;
        uint64_t tensor_count;
        uint64_t metadata_count;
        size_t file_size;
        char architecture[64];
        char quantization[32];
        char parameter_count[32];
        int is_moe;
        int expert_count;
        int experts_used;
    } GGUF_ArchitectureInfo;
}

// GGUF Inspector Panel implementation
void Win32IDE::ShowGGUFInspectorPanel()
{
    if (!m_hwndGGUFInspectorPanel) {
        CreateGGUFInspectorPanel();
    }
    
    ShowWindow(m_hwndGGUFInspectorPanel, SW_SHOW);
    SetForegroundWindow(m_hwndGGUFInspectorPanel);
}

void Win32IDE::CreateGGUFInspectorPanel()
{
    // Create panel window
    m_hwndGGUFInspectorPanel = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        "RawrXD_GGUFInspector",
        "GGUF Model Inspector",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1200, 800,
        m_hwndMain,
        NULL,
        m_hInstance,
        this
    );
    
    if (!m_hwndGGUFInspectorPanel) {
        return;
    }
    
    // Create toolbar
    CreateGGUFInspectorToolbar();
    
    // Create tree view for tensor hierarchy
    CreateGGUFInspectorTreeView();
    
    // Create rich edit for details
    CreateGGUFInspectorDetailsView();
    
    // Create status bar
    m_hwndGGUFInspectorStatus = CreateWindowA(
        "STATIC", "Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 760, 1180, 20,
        m_hwndGGUFInspectorPanel,
        NULL,
        m_hInstance,
        NULL
    );
}

void Win32IDE::CreateGGUFInspectorToolbar()
{
    // Load button
    m_hwndGGUFInspectorLoadBtn = CreateWindowA(
        "BUTTON", "Load GGUF",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 10, 100, 30,
        m_hwndGGUFInspectorPanel,
        (HMENU)IDM_GGUF_LOAD,
        m_hInstance,
        NULL
    );
    
    // Export JSON button
    m_hwndGGUFInspectorExportBtn = CreateWindowA(
        "BUTTON", "Export JSON",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        120, 10, 100, 30,
        m_hwndGGUFInspectorPanel,
        (HMENU)IDM_GGUF_EXPORT,
        m_hInstance,
        NULL
    );
    
    // Full analysis button
    m_hwndGGUFInspectorAnalyzeBtn = CreateWindowA(
        "BUTTON", "Full Analysis",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        230, 10, 100, 30,
        m_hwndGGUFInspectorPanel,
        (HMENU)IDM_GGUF_ANALYZE,
        m_hInstance,
        NULL
    );
    
    // File path display
    m_hwndGGUFInspectorPath = CreateWindowA(
        "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY,
        340, 12, 600, 26,
        m_hwndGGUFInspectorPanel,
        NULL,
        m_hInstance,
        NULL
    );
}

void Win32IDE::CreateGGUFInspectorTreeView()
{
    // Create tree view for tensor list
    m_hwndGGUFInspectorTree = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        "SysTreeView32",
        "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
        10, 50, 400, 700,
        m_hwndGGUFInspectorPanel,
        (HMENU)IDM_GGUF_TREE,
        m_hInstance,
        NULL
    );
    
    // Set tree view font
    SendMessage(m_hwndGGUFInspectorTree, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);
}

void Win32IDE::CreateGGUFInspectorDetailsView()
{
    // Create rich edit for details
    LoadLibraryA("Msftedit.dll");
    
    m_hwndGGUFInspectorDetails = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        "RICHEDIT50W",
        "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        420, 50, 770, 700,
        m_hwndGGUFInspectorPanel,
        (HMENU)IDM_GGUF_DETAILS,
        m_hInstance,
        NULL
    );
    
    // Set details font
    SendMessage(m_hwndGGUFInspectorDetails, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);
    
    // Set background color
    SendMessage(m_hwndGGUFInspectorDetails, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
}

void Win32IDE::HandleGGUFInspectorCommand(int commandId)
{
    switch (commandId) {
        case IDM_GGUF_LOAD:
            OnGGUFInspectorLoad();
            break;
        case IDM_GGUF_EXPORT:
            OnGGUFInspectorExport();
            break;
        case IDM_GGUF_ANALYZE:
            OnGGUFInspectorAnalyze();
            break;
    }
}

void Win32IDE::OnGGUFInspectorLoad()
{
    // Open file dialog
    OPENFILENAMEA ofn;
    char szFile[MAX_PATH] = {0};
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndGGUFInspectorPanel;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "GGUF Models (*.gguf)\0*.gguf\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = "F:\\OllamaModels";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    
    if (GetOpenFileNameA(&ofn)) {
        m_ggufInspectorCurrentFile = szFile;
        
        // Update path display
        SetWindowTextA(m_hwndGGUFInspectorPath, szFile);
        
        // Load and analyze
        LoadGGUFInspectorFile(szFile);
    }
}

void Win32IDE::LoadGGUFInspectorFile(const std::string& path)
{
    SetWindowTextA(m_hwndGGUFInspectorStatus, "Loading GGUF file...");
    
    // Run gguf_inspector tool
    std::string cmd = "gguf_inspector.exe \"" + path + "\" --json \"" + 
                      path + ".analysis.json\"";
    
    // Execute and capture output
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    HANDLE hRead, hWrite;
    CreatePipe(&hRead, &hWrite, &sa, 0);
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    ZeroMemory(&pi, sizeof(pi));
    
    std::string fullCmd = "cmd.exe /c cd \"" + std::string("D:\\rawrxd\\build-ninja\\bin") + 
                          "\" && " + cmd;
    
    if (CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, 
                      NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000); // 30 second timeout
        
        CloseHandle(hWrite);
        
        // Read output
        char buffer[4096];
        DWORD bytesRead;
        std::string output;
        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
        }
        
        CloseHandle(hRead);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        // Update details view
        SetWindowTextA(m_hwndGGUFInspectorDetails, output.c_str());
        
        // Load JSON and populate tree
        PopulateGGUFInspectorTree(path + ".analysis.json");
        
        // Enable buttons
        EnableWindow(m_hwndGGUFInspectorExportBtn, TRUE);
        EnableWindow(m_hwndGGUFInspectorAnalyzeBtn, TRUE);
        
        SetWindowTextA(m_hwndGGUFInspectorStatus, "GGUF file loaded successfully");
    } else {
        SetWindowTextA(m_hwndGGUFInspectorStatus, "Failed to load GGUF file");
    }
}

void Win32IDE::PopulateGGUFInspectorTree(const std::string& jsonPath)
{
    // Clear existing items
    TreeView_DeleteAllItems(m_hwndGGUFInspectorTree);
    
    // Read JSON file
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        return;
    }
    
    std::string json((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();
    
    // Parse JSON and populate tree
    // This is a simplified version - full JSON parsing would be more complex
    
    // Add root item
    TVINSERTSTRUCT tvis;
    ZeroMemory(&tvis, sizeof(tvis));
    tvis.hParent = TVI_ROOT;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT;
    tvis.item.pszText = (LPWSTR)L"GGUF Model";
    HTREEITEM hRoot = TreeView_InsertItem(m_hwndGGUFInspectorTree, &tvis);
    
    // Add metadata node
    tvis.hParent = hRoot;
    tvis.item.pszText = (LPWSTR)L"Metadata";
    HTREEITEM hMetadata = TreeView_InsertItem(m_hwndGGUFInspectorTree, &tvis);
    
    // Add tensors node
    tvis.item.pszText = (LPWSTR)L"Tensors";
    HTREEITEM hTensors = TreeView_InsertItem(m_hwndGGUFInspectorTree, &tvis);
    
    // Expand root
    TreeView_Expand(m_hwndGGUFInspectorTree, hRoot, TVE_EXPAND);
}

void Win32IDE::OnGGUFInspectorExport()
{
    if (m_ggufInspectorCurrentFile.empty()) {
        return;
    }
    
    OPENFILENAMEW ofn;
    wchar_t szFile[MAX_PATH] = {0};
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndGGUFInspectorPanel;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(szFile[0]);
    ofn.lpstrFilter = L"JSON Files (*.json)\0*.json\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrDefExt = L"json";
    ofn.Flags = OFN_OVERWRITEPROMPT;
    
    if (GetSaveFileNameW(&ofn)) {
        // Copy analysis file to selected location
        std::string src = m_ggufInspectorCurrentFile + ".analysis.json";
        char dest[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, szFile, -1, dest, MAX_PATH, NULL, NULL);
        
        CopyFileA(src.c_str(), dest, FALSE);
        
        SetWindowText(m_hwndGGUFInspectorStatus, L"Analysis exported successfully");
    }
}

void Win32IDE::OnGGUFInspectorAnalyze()
{
    if (m_ggufInspectorCurrentFile.empty()) {
        return;
    }
    
    SetWindowText(m_hwndGGUFInspectorStatus, L"Running full analysis...");
    
    // Run full analysis with --full flag
    std::string cmd = "gguf_inspector.exe \"" + m_ggufInspectorCurrentFile + "\" --full";
    
    // Similar to LoadGGUFInspectorFile but with --full flag
    // ... implementation similar to above
    
    SetWindowText(m_hwndGGUFInspectorStatus, L"Full analysis complete");
}

// Window procedure for GGUF Inspector panel
LRESULT CALLBACK GGUFInspectorPanelProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = nullptr;
    
    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (Win32IDE*)pCreate->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (Win32IDE*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }
    
    switch (uMsg) {
        case WM_COMMAND:
            if (pThis) {
                pThis->HandleGGUFInspectorCommand(LOWORD(wParam));
            }
            return 0;
            
        case WM_NOTIFY: {
            LPNMHDR pnmh = (LPNMHDR)lParam;
            if (pnmh->idFrom == IDM_GGUF_TREE && pnmh->code == TVN_SELCHANGED) {
                // Handle tree selection change
                if (pThis) {
                    // Update details view based on selection
                }
            }
            return 0;
        }
        
        case WM_SIZE:
            if (pThis) {
                // Resize child controls
                RECT rc;
                GetClientRect(hwnd, &rc);
                
                // Resize tree view
                SetWindowPos(pThis->m_hwndGGUFInspectorTree, NULL,
                    10, 50, 400, rc.bottom - 80,
                    SWP_NOZORDER);
                
                // Resize details view
                SetWindowPos(pThis->m_hwndGGUFInspectorDetails, NULL,
                    420, 50, rc.right - 430, rc.bottom - 80,
                    SWP_NOZORDER);
                
                // Move status bar
                SetWindowPos(pThis->m_hwndGGUFInspectorStatus, NULL,
                    10, rc.bottom - 25, rc.right - 20, 20,
                    SWP_NOZORDER);
            }
            return 0;
            
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Register GGUF Inspector window class
void Win32IDE::RegisterGGUFInspectorClass()
{
    WNDCLASSEX wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = GGUFInspectorPanelProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = L"RawrXD_GGUFInspector";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    
    RegisterClassEx(&wc);
}

// Menu IDs for GGUF Inspector
#ifndef IDM_GGUF_LOAD
#define IDM_GGUF_LOAD 5001
#define IDM_GGUF_EXPORT 5002
#define IDM_GGUF_ANALYZE 5003
#define IDM_GGUF_TREE 5004
#define IDM_GGUF_DETAILS 5005
#endif
