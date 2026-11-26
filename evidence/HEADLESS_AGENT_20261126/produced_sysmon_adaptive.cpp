#include <windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <cmath>
#include <format>

using namespace std;

#define TIMER_ID 1

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SysMon";

    if (!RegisterClass(&wc)) {
        MessageBox(NULL, "Failed to register window class.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    HWND hWnd = CreateWindow("SysMon", "System Monitor", WS_OVERLAPPEDWINDOW, 
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 400, NULL, NULL, hInstance, NULL);

    if (!hWnd) {
        MessageBox(NULL, "Failed to create window.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(hWnd, iCmdShow);
    UpdateWindow(hWnd);

    SetTimer(hWnd, TIMER_ID, 1000, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HWND hCPU, hMem, hDisk, hGPU;
    static double lastCPU = 0;

    switch (message) {
        case WM_CREATE: {
            hCPU = CreateWindow("STATIC", "CPU: 0.00%", WS_VISIBLE | WS_CHILD, 10, 10, 280, 20, hWnd, (HMENU)1, NULL, NULL);
            hMem = CreateWindow("STATIC", "Memory: 0/0 MB", WS_VISIBLE | WS_CHILD, 10, 35, 28,0, 20, hWnd, (HMENU)2, NULL, NULL);
            hDisk = CreateWindow("STATIC", "Disk: 0/0 GB", WS_VISIBLE | WS_CHILD, 10, 60, 280, 20, hWnd, (HMENU)3, NULL, NULL);
            hGPU = CreateWindow("STATIC", "GPU: None", WS_VISIBLE | WS_CHILD, 10, 85, 280, 20, hWnd, (HMENU)4, NULL, NULL);
            return 0;
        }
        case WM_TIMER: {
            FILETIME ftSys, ftUser, ftIdle;
            GetSystemTimes(&ftSys, &ftUser, &ftIdle);
            ULARGE_INTEGER sys, user, idle;
            sys.LowPart = ftSys.dwLowDateTime;
            sys.HighPart = ftSys.dwHighDateTime;
            user.LowPart = ftUser.dwLowDateTime;
            user.HighPart = ftUser.dwHighDateTime;
            idle.LowPart = ftIdle.dwLowDateTime;
            idle.HighPart = ftIdle.dwHighDateTime;

            ULARGE_INTEGER now;
            now.QuadPart = sys.QuadPart + user.QuadPart + idle.QuadPart;
            ULARGE_INTEGER diff = now - ULARGE_INTEGER{0, 0};
            double elapsed = diff.QuadPart / (double)10000000;
            double cpu = (user.QuadPart / elapsed) * 100;

            MEMORYSTATUSEX mem;
            mem.dwLength = sizeof(mem);
            GlobalMemoryStatusEx(&mem);
            string memStr = format("Memory: {0:.1f}/{1:.1f} MB", mem.ullAvailPhys / 1024.0 / 1024.0, mem.ullTotalPhys / 1024.0 / 1024.0);

            ULARGE_INTEGER disk;
            GetDiskFreeSpaceExW(L"C:\\", &disk, NULL, NULL);
            string diskStr = format("Disk: {0:.1f}/{1:.1f} GB", disk.QuadPart / 1024.0 / 1024.0 / 1024.0, disk.QuadPart / 1024.0 / 1024.0 / 1024.0);

            vector<wchar_t> gpuName(256);
            EnumDisplayDevicesW(NULL, 0, (PDISPLAY_DEVICEW)&gpuName[0], 0);
            string gpuStr = format("GPU: {0}", wstring(gpuName.begin(), gpuName.end()));

            SetWindowText(hCPU, format("CPU: {0:.2f}%", cpu).c_str());
            SetWindowText(hMem, memStr.c_str());
            SetWindowText(hDisk, diskStr.c_str());
            SetWindowText(hGPU, gpuStr.c_str());
            return 0;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProc(hWnd, message, wParam, lParam);
}