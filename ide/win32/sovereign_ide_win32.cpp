// Sovereign IDE - Win32 Native UI Shell
// High-performance IDE frontend using Direct2D/Skia
// No Electron, no Qt, no bloat - just bare metal performance

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <d2d1.h>
#include <dwrite.h>
#include <string.h>
#include <stdio.h>

#include "sovereign_sdk.h"

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "comctl32.lib")

// ============================================================================
// Constants
// ============================================================================

#define WM_SOVEREIGN_NOTIFY (WM_USER + 1)
#define IDT_STATUS_UPDATE   1001
#define IDT_PERF_MONITOR    1002

#define MAX_LOADSTRING      100
#define MAX_OPEN_FILES      256
#define MIN_WINDOW_WIDTH    800
#define MIN_WINDOW_HEIGHT   600

// Colors (Dark theme)
#define COLOR_BG_DARK       RGB(30, 30, 30)
#define COLOR_BG_LIGHT      RGB(45, 45, 45)
#define COLOR_TEXT          RGB(220, 220, 220)
#define COLOR_ACCENT        RGB(0, 120, 212)
#define COLOR_SUCCESS       RGB(0, 200, 100)
#define COLOR_WARNING       RGB(255, 200, 0)
#define COLOR_ERROR         RGB(255, 80, 80)

// ============================================================================
// Structures
// ============================================================================

typedef struct {
    wchar_t file_path[MAX_PATH];
    wchar_t file_name[MAX_PATH];
    bool modified;
    void* content;              // Memory-mapped file content
    size_t content_size;
    uint32_t cursor_line;
    uint32_t cursor_column;
} OpenFile;

typedef struct {
    HWND hwndMain;
    HWND hwndEditor;
    HWND hwndSidebar;
    HWND hwndStatusBar;
    HWND hwndCommandPalette;
    
    ID2D1Factory* d2dFactory;
    ID2D1HwndRenderTarget* renderTarget;
    IDWriteFactory* dwriteFactory;
    IDWriteTextFormat* textFormat;
    IDWriteTextFormat* textFormatBold;
    
    SovereignHandle sovereignEngine;
    SovereignGraphHandle codeGraph;
    
    OpenFile openFiles[MAX_OPEN_FILES];
    int activeFileIndex;
    int openFileCount;
    
    bool showSidebar;
    bool showMinimap;
    bool showStatusBar;
    int sidebarWidth;
    
    // Performance metrics
    float tokensPerSecond;
    float latencyMs;
    uint64_t memoryUsed;
    
    // Command palette
    bool commandPaletteVisible;
    wchar_t commandBuffer[256];
    
} IDEState;

// Global state
static IDEState g_ide = {0};
static HINSTANCE g_hInst = NULL;
static wchar_t g_szTitle[MAX_LOADSTRING];
static wchar_t g_szWindowClass[MAX_LOADSTRING];

// Forward declarations
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

void                InitializeSovereignEngine(void);
void                ShutdownSovereignEngine(void);
void                RenderEditor(HWND hwnd);
void                RenderSidebar(HWND hwnd);
void                RenderStatusBar(HWND hwnd);
void                UpdatePerformanceMetrics(void);
void                ShowCommandPalette(void);
void                HideCommandPalette(void);
void                ExecuteCommand(const wchar_t* command);

// ============================================================================
// Entry Point
// ============================================================================

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = { sizeof(iccex), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&iccex);

    // Load strings
    LoadStringW(hInstance, IDS_APP_TITLE, g_szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_SOVEREIGNIDE, g_szWindowClass, MAX_LOADSTRING);
    
    MyRegisterClass(hInstance);

    // Initialize Sovereign Engine
    InitializeSovereignEngine();

    // Perform application initialization
    if (!InitInstance(hInstance, nCmdShow))
    {
        return FALSE;
    }

    // Main message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!IsDialogMessage(g_ide.hwndCommandPalette, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    // Cleanup
    ShutdownSovereignEngine();

    return (int)msg.wParam;
}

// ============================================================================
// Window Registration
// ============================================================================

ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex = {0};
    
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SOVEREIGNIDE));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_SOVEREIGNIDE);
    wcex.lpszClassName  = g_szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));
    
    return RegisterClassExW(&wcex);
}

// ============================================================================
// Instance Initialization
// ============================================================================

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    g_hInst = hInstance;

    // Create main window
    HWND hWnd = CreateWindowW(
        g_szWindowClass,
        L"Sovereign IDE - Native Performance",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, 0,
        1600, 900,
        nullptr,
        nullptr,
        hInstance,
        nullptr
    );

    if (!hWnd)
    {
        return FALSE;
    }

    g_ide.hwndMain = hWnd;
    
    // Initialize Direct2D
    D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &g_ide.d2dFactory);
    
    // Initialize DirectWrite
    DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, 
        __uuidof(IDWriteFactory), 
        (IUnknown**)&g_ide.dwriteFactory);
    
    // Create text formats
    g_ide.dwriteFactory->CreateTextFormat(
        L"Consolas", NULL, DWRITE_FONT_WEIGHT_NORMAL, 
        DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
        14.0f, L"en-US", &g_ide.textFormat);
    
    g_ide.dwriteFactory->CreateTextFormat(
        L"Segoe UI", NULL, DWRITE_FONT_WEIGHT_BOLD,
        DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
        12.0f, L"en-US", &g_ide.textFormatBold);
    
    // Set default state
    g_ide.showSidebar = true;
    g_ide.showStatusBar = true;
    g_ide.sidebarWidth = 250;
    
    // Create child windows
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);
    
    // Sidebar (file explorer, symbols, etc.)
    g_ide.hwndSidebar = CreateWindowW(
        L"STATIC", L"Sidebar",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, g_ide.sidebarWidth, rcClient.bottom - 30,
        hWnd, (HMENU)100, hInstance, NULL
    );
    
    // Editor area
    g_ide.hwndEditor = CreateWindowW(
        L"STATIC", L"Editor",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        g_ide.sidebarWidth, 0, 
        rcClient.right - g_ide.sidebarWidth, rcClient.bottom - 30,
        hWnd, (HMENU)101, hInstance, NULL
    );
    
    // Status bar
    g_ide.hwndStatusBar = CreateWindowW(
        STATUSCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hWnd, (HMENU)102, hInstance, NULL
    );
    
    // Set status bar parts
    int parts[] = { 200, 400, 600, -1 };
    SendMessage(g_ide.hwndStatusBar, SB_SETPARTS, 4, (LPARAM)parts);
    
    // Set timers
    SetTimer(hWnd, IDT_STATUS_UPDATE, 1000, NULL);
    SetTimer(hWnd, IDT_PERF_MONITOR, 5000, NULL);
    
    // Show and update window
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    
    return TRUE;
}

// ============================================================================
// Sovereign Engine Integration
// ============================================================================

void InitializeSovereignEngine(void)
{
    // Configure node (single-node IDE mode)
    SovereignNodeConfig config = {
        .node_id = 0,
        .total_nodes = 1,
        .is_head = true,
        .enable_gpu = true,
        .enable_amx = Sovereign_HasAMX(),
        .thread_pool_size = Sovereign_GetOptimalThreadCount(),
        .kv_cache_size = 16ULL * 1024 * 1024 * 1024,  // 16GB
        .head_node_ip = "127.0.0.1",
        .router_port = 5555,
        .pub_port = 5556
    };
    
    g_ide.sovereignEngine = Sovereign_Init(&config);
    
    if (!g_ide.sovereignEngine) {
        MessageBoxW(NULL, 
            L"Failed to initialize Sovereign Engine.\n"
            L"The IDE will run in limited mode.",
            L"Sovereign IDE",
            MB_OK | MB_ICONWARNING);
    }
    
    // Load code graph for current workspace
    // In real implementation, this would scan the project directory
    g_ide.codeGraph = NULL; // Will be loaded when workspace is opened
}

void ShutdownSovereignEngine(void)
{
    if (g_ide.sovereignEngine) {
        Sovereign_Shutdown(g_ide.sovereignEngine);
        g_ide.sovereignEngine = NULL;
    }
}

void UpdatePerformanceMetrics(void)
{
    if (!g_ide.sovereignEngine) return;
    
    SovereignStatus status;
    if (Sovereign_GetStatus(g_ide.sovereignEngine, &status) == 0) {
        g_ide.tokensPerSecond = status.throughput_tps;
        g_ide.latencyMs = status.avg_latency_ms;
        g_ide.memoryUsed = status.memory_used;
    }
}

// ============================================================================
// Window Procedure
// ============================================================================

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        return 0;
        
    case WM_SIZE:
    {
        // Resize child windows
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);
        
        int statusHeight = 30;
        int editorWidth = rcClient.right - (g_ide.showSidebar ? g_ide.sidebarWidth : 0);
        int editorHeight = rcClient.bottom - statusHeight;
        
        if (g_ide.showSidebar) {
            SetWindowPos(g_ide.hwndSidebar, NULL,
                0, 0, g_ide.sidebarWidth, editorHeight,
                SWP_NOZORDER);
        }
        
        SetWindowPos(g_ide.hwndEditor, NULL,
            g_ide.showSidebar ? g_ide.sidebarWidth : 0, 0,
            editorWidth, editorHeight,
            SWP_NOZORDER);
        
        SetWindowPos(g_ide.hwndStatusBar, NULL,
            0, rcClient.bottom - statusHeight,
            rcClient.right, statusHeight,
            SWP_NOZORDER);
        
        // Recreate render target
        if (g_ide.renderTarget) {
            g_ide.renderTarget->Resize(D2D1::SizeU(rcClient.right, rcClient.bottom));
        }
        
        return 0;
    }
    
    case WM_TIMER:
        switch (wParam)
        {
        case IDT_STATUS_UPDATE:
            // Update status bar
            if (g_ide.sovereignEngine) {
                wchar_t buf[256];
                swprintf_s(buf, 256, 
                    L"Sovereign: %.1f t/s | %.1f ms | Memory: %.1f GB",
                    g_ide.tokensPerSecond,
                    g_ide.latencyMs,
                    g_ide.memoryUsed / (1024.0 * 1024 * 1024));
                SendMessage(g_ide.hwndStatusBar, SB_SETTEXT, 0, (LPARAM)buf);
            }
            break;
            
        case IDT_PERF_MONITOR:
            UpdatePerformanceMetrics();
            break;
        }
        return 0;
        
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        
        // Render editor content
        RenderEditor(g_ide.hwndEditor);
        
        EndPaint(hWnd, &ps);
        return 0;
    }
    
    case WM_KEYDOWN:
        switch (wParam)
        {
        case VK_F1:
            ShowCommandPalette();
            return 0;
            
        case VK_F5:
            // Run/Build
            ExecuteCommand(L"build");
            return 0;
            
        case 'P':
            if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
                ShowCommandPalette();
                return 0;
            }
            break;
            
        case 'B':
            if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
                ExecuteCommand(L"build");
                return 0;
            }
            break;
        }
        break;
        
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDM_ABOUT:
            DialogBox(g_hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
            
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
            
        case ID_VIEW_SIDEBAR:
            g_ide.showSidebar = !g_ide.showSidebar;
            ShowWindow(g_ide.hwndSidebar, g_ide.showSidebar ? SW_SHOW : SW_HIDE);
            InvalidateRect(hWnd, NULL, TRUE);
            break;
            
        case ID_FILE_OPEN:
            // Open file dialog
            ExecuteCommand(L"open");
            break;
            
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
    }
    break;
    
    case WM_DESTROY:
        KillTimer(hWnd, IDT_STATUS_UPDATE);
        KillTimer(hWnd, IDT_PERF_MONITOR);
        PostQuitMessage(0);
        return 0;
        
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// ============================================================================
// Rendering
// ============================================================================

void RenderEditor(HWND hwnd)
{
    if (!g_ide.d2dFactory) return;
    
    // Create render target if needed
    if (!g_ide.renderTarget) {
        RECT rc;
        GetClientRect(hwnd, &rc);
        
        D2D1_SIZE_U size = D2D1::SizeU(rc.right - rc.left, rc.bottom - rc.top);
        
        g_ide.d2dFactory->CreateHwndRenderTarget(
            D2D1::RenderTargetProperties(),
            D2D1::HwndRenderTargetProperties(hwnd, size),
            &g_ide.renderTarget);
    }
    
    if (!g_ide.renderTarget) return;
    
    // Begin drawing
    g_ide.renderTarget->BeginDraw();
    g_ide.renderTarget->Clear(D2D1::ColorF(D2D1::ColorF::Black));
    
    // Draw placeholder text
    if (g_ide.textFormat) {
        ID2D1SolidColorBrush* brush = NULL;
        g_ide.renderTarget->CreateSolidColorBrush(
            D2D1::ColorF(D2D1::ColorF::White),
            &brush);
        
        if (brush) {
            const wchar_t* text = L"Sovereign IDE - Ready for code...\n"
                                   L"\n"
                                   L"Press Ctrl+P for Command Palette\n"
                                   L"Press Ctrl+B to Build\n"
                                   L"Press F5 to Run";
            
            g_ide.renderTarget->DrawTextW(
                text, (UINT32)wcslen(text),
                g_ide.textFormat,
                D2D1::RectF(20, 20, 600, 200),
                brush);
            
            brush->Release();
        }
    }
    
    g_ide.renderTarget->EndDraw();
}

// ============================================================================
// Command Palette
// ============================================================================

void ShowCommandPalette(void)
{
    if (!g_ide.commandPaletteVisible) {
        // Create command palette window
        RECT rc;
        GetWindowRect(g_ide.hwndMain, &rc);
        
        int width = 600;
        int height = 400;
        int x = rc.left + (rc.right - rc.left - width) / 2;
        int y = rc.top + 100;
        
        g_ide.hwndCommandPalette = CreateWindowW(
            L"EDIT", L"",
            WS_OVERLAPPED | WS_CAPTION | WS_THICKFRAME | WS_VISIBLE,
            x, y, width, height,
            g_ide.hwndMain, NULL, g_hInst, NULL
        );
        
        g_ide.commandPaletteVisible = true;
        SetFocus(g_ide.hwndCommandPalette);
    }
}

void HideCommandPalette(void)
{
    if (g_ide.commandPaletteVisible) {
        DestroyWindow(g_ide.hwndCommandPalette);
        g_ide.commandPaletteVisible = false;
        SetFocus(g_ide.hwndEditor);
    }
}

void ExecuteCommand(const wchar_t* command)
{
    if (wcscmp(command, L"build") == 0) {
        // Trigger build via Sovereign Engine
        if (g_ide.sovereignEngine) {
            // TaskParams params = {0};
            // params.type = SOVEREIGN_TASK_ANALYSIS;
            // params.input = "build";
            // Sovereign_SubmitTask(g_ide.sovereignEngine, NULL, &params);
        }
        MessageBoxW(g_ide.hwndMain, L"Build command executed", L"Sovereign IDE", MB_OK);
    }
    else if (wcscmp(command, L"open") == 0) {
        // Open file dialog
        OPENFILENAMEW ofn = {0};
        wchar_t fileName[MAX_PATH] = {0};
        
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_ide.hwndMain;
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrFilter = L"All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        
        if (GetOpenFileNameW(&ofn)) {
            // Load file into editor
            MessageBoxW(g_ide.hwndMain, fileName, L"Opened", MB_OK);
        }
    }
}

// ============================================================================
// About Dialog
// ============================================================================

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;
        
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}