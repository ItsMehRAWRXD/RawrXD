#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <string>

#include "SovereignHealthPanel.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/SovereignEventBus.hpp"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// Global instances
static SovereignHealthPanel* g_healthPanel = nullptr;
static HWND g_hwndMain = nullptr;

// Window class name
static constexpr wchar_t MAIN_WINDOW_CLASS[] = L"RawrXD_IDE_Main";

// Forward declarations
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool InitializeIDE(HWND hwndMain);
void ShutdownIDE();
void PollBeaconism();

/**
 * @brief IDE Entry Point
 */
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex{};
    iccex.dwSize = sizeof(iccex);
    iccex.dwICC = ICC_BAR_CLASSES | ICC_TREEVIEW_CLASSES;
    InitCommonControlsEx(&iccex);

    // Register main window class
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = MAIN_WINDOW_CLASS;
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Failed to register window class", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Create main window
    g_hwndMain = CreateWindowExW(
        0,
        MAIN_WINDOW_CLASS,
        L"RawrXD IDE - Sovereign Edition",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1400, 900,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hwndMain) {
        MessageBoxW(nullptr, L"Failed to create main window", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Initialize IDE components
    if (!InitializeIDE(g_hwndMain)) {
        MessageBoxW(nullptr, L"Failed to initialize IDE", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hwndMain, nCmdShow);
    UpdateWindow(g_hwndMain);

    // Main message loop with Beaconism polling
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);

        // Poll Beaconism every frame
        PollBeaconism();
    }

    ShutdownIDE();
    return static_cast<int>(msg.wParam);
}

/**
 * @brief Initialize all IDE components
 */
bool InitializeIDE(HWND hwndMain) {
    // Initialize Beaconism first
    if (!Sovereign::Beaconism::Initialize()) {
        OutputDebugStringW(L"Failed to initialize Beaconism\n");
        return false;
    }

    Sovereign::Beaconism::Emit(Sovereign::BeaconID::IDE_Start, 0);

    // Create health panel
    g_healthPanel = new SovereignHealthPanel();
    if (!g_healthPanel->Create(hwndMain)) {
        OutputDebugStringW(L"Failed to create health panel\n");
        delete g_healthPanel;
        g_healthPanel = nullptr;
        return false;
    }

    // Position health panel on the right side
    RECT rcClient;
    GetClientRect(hwndMain, &rcClient);
    int panelWidth = 350;
    SetWindowPos(
        g_healthPanel->GetHWND(),
        nullptr,
        rcClient.right - panelWidth, 0,
        panelWidth, rcClient.bottom,
        SWP_NOZORDER
    );

    // Subscribe to Beaconism events
    Sovereign::SovereignEventBus::Subscribe(
        Sovereign::SovereignEventType::BeaconismEvent,
        [](const Sovereign::SovereignEvent& evt) {
            if (g_healthPanel) {
                g_healthPanel->OnBeacon(evt.beacon);
            }
        }
    );

    Sovereign::Beaconism::Emit(Sovereign::BeaconID::IDE_Initialized, 0);
    return true;
}

/**
 * @brief Shutdown all IDE components
 */
void ShutdownIDE() {
    Sovereign::Beaconism::Emit(Sovereign::BeaconID::IDE_Shutdown, 0);

    if (g_healthPanel) {
        g_healthPanel->Destroy();
        delete g_healthPanel;
        g_healthPanel = nullptr;
    }

    Sovereign::Beaconism::Shutdown();
}

/**
 * @brief Poll Beaconism for new events
 */
void PollBeaconism() {
    Sovereign::Beaconism::Poll();
}

/**
 * @brief Main window procedure
 */
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            return 0;

        case WM_SIZE:
            // Resize health panel when main window resizes
            if (g_healthPanel) {
                RECT rcClient;
                GetClientRect(hwnd, &rcClient);
                int panelWidth = 350;
                SetWindowPos(
                    g_healthPanel->GetHWND(),
                    nullptr,
                    rcClient.right - panelWidth, 0,
                    panelWidth, rcClient.bottom,
                    SWP_NOZORDER
                );
            }
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_KEYDOWN:
            // F5 = Run Smoketest
            if (wParam == VK_F5) {
                Sovereign::Beaconism::Emit(Sovereign::BeaconID::SmoketestStart, 0);
                OutputDebugStringW(L"F5 pressed - Smoketest triggered\n");
            }
            return 0;

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}
