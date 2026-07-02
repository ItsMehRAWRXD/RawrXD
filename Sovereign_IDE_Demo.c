/* ==============================================================================
   Sovereign_IDE_Demo.c — Minimal Win32 Text Editor with Ghost Text Overlay
   ==============================================================================
   Build: cl.exe /O2 /TC /W3 /nologo /Fe:Sovereign_IDE_Demo.exe Sovereign_IDE_Demo.c
   Run:   .\Sovereign_IDE_Demo.exe
   
   Demonstrates:
     - LoadLibrary("sovereign.dll")
     - SovereignInitAll() + StreamerInit()
     - PushGhostPrediction() with real text
     - RenderGhostPredictive(hWnd) in WM_PAINT
     - GhostHeartbeat(hWnd) on WM_TIMER
   ==============================================================================*/

#include <windows.h>
#include <stdio.h>

/* ------------------------------------------------------------------------------
   Sovereign DLL function pointers
   ------------------------------------------------------------------------------ */
typedef int  (*fn_SovereignInitAll)(void);
typedef void (*fn_SovereignShutdown)(void);
typedef int  (*fn_InitGhostBuffer)(void);
typedef int  (*fn_PushGhostPrediction)(const char*, size_t, unsigned int);
typedef int  (*fn_RenderGhostPredictive)(HWND);
typedef int  (*fn_GhostHeartbeat)(HWND);
typedef int  (*fn_FlushGhostBuffer)(void);
typedef int  (*fn_StreamerInit)(void);
typedef int  (*fn_StreamerPushToken)(unsigned char, unsigned int);
typedef int  (*fn_StreamerFlush)(void);

static HMODULE g_hSovereign = NULL;
static fn_SovereignInitAll    g_pfnInitAll = NULL;
static fn_SovereignShutdown   g_pfnShutdown = NULL;
static fn_InitGhostBuffer     g_pfnGhostInit = NULL;
static fn_PushGhostPrediction g_pfnGhostPush = NULL;
static fn_RenderGhostPredictive g_pfnGhostRender = NULL;
static fn_GhostHeartbeat      g_pfnGhostHeartbeat = NULL;
static fn_FlushGhostBuffer    g_pfnGhostFlush = NULL;
static fn_StreamerInit        g_pfnStreamerInit = NULL;
static fn_StreamerPushToken   g_pfnStreamerPush = NULL;
static fn_StreamerFlush       g_pfnStreamerFlush = NULL;

static int g_demoPhase = 0;

/* ------------------------------------------------------------------------------
   Load Sovereign DLL
   ------------------------------------------------------------------------------ */
static int LoadSovereign(void)
{
    g_hSovereign = LoadLibraryA("sovereign.dll");
    if (!g_hSovereign) {
        MessageBoxA(NULL, "Failed to load sovereign.dll", "Error", MB_OK);
        return 0;
    }

    g_pfnInitAll       = (fn_SovereignInitAll)GetProcAddress(g_hSovereign, "SovereignInitAll");
    g_pfnShutdown      = (fn_SovereignShutdown)GetProcAddress(g_hSovereign, "SovereignShutdown");
    g_pfnGhostInit     = (fn_InitGhostBuffer)GetProcAddress(g_hSovereign, "InitGhostBuffer");
    g_pfnGhostPush     = (fn_PushGhostPrediction)GetProcAddress(g_hSovereign, "PushGhostPrediction");
    g_pfnGhostRender   = (fn_RenderGhostPredictive)GetProcAddress(g_hSovereign, "RenderGhostPredictive");
    g_pfnGhostHeartbeat= (fn_GhostHeartbeat)GetProcAddress(g_hSovereign, "GhostHeartbeat");
    g_pfnGhostFlush    = (fn_FlushGhostBuffer)GetProcAddress(g_hSovereign, "FlushGhostBuffer");
    g_pfnStreamerInit  = (fn_StreamerInit)GetProcAddress(g_hSovereign, "StreamerInit");
    g_pfnStreamerPush  = (fn_StreamerPushToken)GetProcAddress(g_hSovereign, "StreamerPushToken");
    g_pfnStreamerFlush = (fn_StreamerFlush)GetProcAddress(g_hSovereign, "StreamerFlush");

    if (!g_pfnInitAll || !g_pfnGhostPush || !g_pfnGhostRender) {
        MessageBoxA(NULL, "Failed to resolve core exports", "Error", MB_OK);
        return 0;
    }

    if (g_pfnInitAll() != 0) {
        MessageBoxA(NULL, "SovereignInitAll failed", "Error", MB_OK);
        return 0;
    }

    if (g_pfnGhostInit) g_pfnGhostInit();
    if (g_pfnStreamerInit) g_pfnStreamerInit();

    return 1;
}

/* ------------------------------------------------------------------------------
   Demo: Push predictions through Model Streamer
   ------------------------------------------------------------------------------ */
static void PushDemoPrediction(void)
{
    const char* predictions[] = {
        "Hello, World!",
        "int main(void) {",
        "return 0;",
        "}",
        "// Sovereign Framework",
        "printf(\"Ghost text active\\n\");",
        "for (int i = 0; i < n; i++)",
        "if (latency < budget) {",
        "    render_prediction();",
        "}",
    };
    static int idx = 0;

    if (!g_pfnGhostPush) return;

    const char* text = predictions[idx % 10];
    idx++;

    /* 0.95f confidence as raw bits */
    g_pfnGhostPush(text, strlen(text), 0x3F733333);
}

/* ------------------------------------------------------------------------------
   Window Procedure
   ------------------------------------------------------------------------------ */
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        SetTimer(hWnd, 1, 2000, NULL); /* Push new prediction every 2s */
        SetTimer(hWnd, 2, 100, NULL);  /* Render heartbeat every 100ms */
        PushDemoPrediction();
        return 0;

    case WM_TIMER:
        if (wParam == 1) {
            PushDemoPrediction();
        } else if (wParam == 2) {
            if (g_pfnGhostHeartbeat) {
                g_pfnGhostHeartbeat(hWnd);
            }
            InvalidateRect(hWnd, NULL, FALSE);
        }
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        /* Background */
        RECT rc;
        GetClientRect(hWnd, &rc);
        FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));

        /* Title */
        SetTextColor(hdc, RGB(0, 255, 0));
        SetBkMode(hdc, TRANSPARENT);
        TextOutA(hdc, 10, 10, "SOVEREIGN IDE DEMO — Ghost Text Overlay", 41);

        /* Instructions */
        SetTextColor(hdc, RGB(128, 128, 128));
        TextOutA(hdc, 10, 40, "Predictions pushed every 2 seconds via Model Streamer", 53);
        TextOutA(hdc, 10, 60, "Ghost text renders at confidence > 0.8 (YOLO mode)", 50);

        /* Render ghost predictions */
        if (g_pfnGhostRender) {
            int rendered = g_pfnGhostRender(hWnd);
            if (rendered) {
                SetTextColor(hdc, RGB(0, 204, 255));
                TextOutA(hdc, 10, 100, "[GHOST TEXT RENDERED]", 21);
            }
        }

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_KEYDOWN:
        if (wParam == VK_SPACE) {
            PushDemoPrediction();
            InvalidateRect(hWnd, NULL, FALSE);
        } else if (wParam == VK_ESCAPE) {
            PostQuitMessage(0);
        }
        return 0;

    case WM_DESTROY:
        if (g_pfnGhostFlush) g_pfnGhostFlush();
        if (g_pfnShutdown) g_pfnShutdown();
        if (g_hSovereign) FreeLibrary(g_hSovereign);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------------------
   Main Entry Point
   ------------------------------------------------------------------------------ */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrev;
    (void)lpCmdLine;

    /* Load DLL */
    if (!LoadSovereign()) {
        return 1;
    }

    /* Register window class */
    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = "SovereignIDEDemo";
    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, "RegisterClass failed", "Error", MB_OK);
        return 1;
    }

    /* Create window */
    HWND hWnd = CreateWindowExA(
        0,
        "SovereignIDEDemo",
        "Sovereign Framework :: IDE Ghost Text Demo",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        NULL, NULL, hInst, NULL
    );

    if (!hWnd) {
        MessageBoxA(NULL, "CreateWindow failed", "Error", MB_OK);
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    /* Message loop */
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}
