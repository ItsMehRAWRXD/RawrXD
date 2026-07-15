#include <windows.h>
#include <commctrl.h>
#include <richedit.h>

#pragma comment(lib, "comctl32.lib")

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    switch (msg) {
    case WM_CREATE:
        hEdit = CreateWindowEx(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            0, 0, 800, 600, hwnd, (HMENU)1, GetModuleHandle(NULL), NULL);
        if (!hEdit) {
            MessageBox(hwnd, L"Failed to create RichEdit control", L"Error", MB_OK);
        }
        return 0;
    case WM_SIZE:
        MoveWindow(hEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    WNDCLASSEX wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"RawrXDMinimal";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    if (!RegisterClassEx(&wc)) {
        MessageBox(NULL, L"Failed to register window class", L"Error", MB_OK);
        return 1;
    }
    
    HWND hwnd = CreateWindowEx(0, L"RawrXDMinimal", L"RawrXD Minimal Baseline",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 1024, 768,
        NULL, NULL, hInstance, NULL);
    
    if (!hwnd) {
        MessageBox(NULL, L"Failed to create window", L"Error", MB_OK);
        return 1;
    }
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
