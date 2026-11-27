#include <windows.h>
#include <vector>
#include <iostream>

using namespace std;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SysMonApp";
    RegisterClass(&wc);

    HWND hwnd = CreateWindow("SysMonApp", "System Monitor", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, hInstance, NULL);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hStatus;
    switch (msg) {
        case WM_CREATE:
            hStatus = CreateWindow("static", "", WS_VISIBLE | WS_CHILD, 10, 10, 380, 250, hwnd, (HMENU)1, NULL, NULL);
            SetTimer(hwnd, 1, 1000, NULL);
            return 0;
        case WM_TIMER:
            {
                FILETIME cpuTime;
                GetSystemTimes(&cpuTime, NULL, NULL);
                MEMORYSTATUSEX memStatus = {0};
                memStatus.dwLength = sizeof(memStatus);
                GlobalMemoryStatusEx(&memStatus);
                LARGE_INTEGER diskFree;
                GetDiskFreeSpaceExW(NULL, reinterpret_cast<PULARGE_INTEGER>(&diskFree), NULL, NULL);
                
                wchar_t buffer[1024];
                swprintf(buffer, L"CPU: %llu ns\nMem: %llu KB\nDisk: %llu KB\nGPU: ", (unsigned long long)cpuTime.dwLowDateTime, (unsigned long long)memStatus.ullAvailPhys / 1024, (unsigned long long)diskFree.QuadPart / 1024);
                
                DISPLAY_DEVICEW dev;
                DWORD index = 0;
                while (EnumDisplayDevicesW(NULL, index, &dev, 0)) {
                    wcsncat(buffer, dev.DeviceName, wcslen(dev.DeviceName));
                    wcsncat(buffer, L"\n", 2);
                    index++;
                }
                
                SetWindowTextW(hStatus, buffer);
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}