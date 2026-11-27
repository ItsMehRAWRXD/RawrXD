#include <windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <shellapi.h>
#include <windowsx.h>
#include <setupapi.h>

#define TIMER_ID 1

struct SystemInfo {
    double cpuUsage;
    ULARGE_INTEGER totalMem, availMem;
    std::wstring diskFree;
    std::vector<std::string> gpus;
};

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, PSTR, int) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SysMon";
    RegisterClass(&wc);

    HWND hwnd = CreateWindow("SysMon", "System Monitor", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 400, NULL, NULL, hInstance, NULL);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static SystemInfo info;
    static ULARGE_INTEGER prevCPUTimes;
    HDC hdc;
    PAINTSTRUCT ps;
    RECT rect;

    switch (msg) {
        case WM_CREATE:
            SetTimer(hwnd, TIMER_ID, 1000, NULL);
            GetSystemTimes((PFILETIME)&prevCPUTimes, NULL, NULL);
            return 0;
        case WM_TIMER:
            {
                FILETIME currCPUTimes;
                GetSystemTimes((PFILETIME)&currCPUTimes, NULL, NULL);
                ULARGE_INTEGER curr;
                curr.LowPart = currCPUTimes.dwLowDateTime;
                curr.HighPart = currCPUTimes.dwHighDateTime;
                double cpuUsage = ((curr.QuadPart - prevCPUTimes.QuadPart) * 100.0) / (10000000.0);
                prevCPUTimes = curr;

                MEMORYSTATUSEX memStat = {0};
                memStat.dwLength = sizeof(memStat);
                GlobalMemoryStatusEx(&memStat);
                info.totalMem.QuadPart = memStat.ullTotalPhys;
                info.availMem.QuadPart = memStat.ullAvailPhys;

                info.diskFree.clear();
                for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
                    std::wstring path = L"";
                    path += drive;
                    path += L":\";
                    if (GetDriveTypeW(path.c_str()) == DRIVE_FIXED) {
                        ULARGE_INTEGER freeSpace;
                        GetDiskFreeSpaceExW(path.c_str(), &freeSpace, NULL, NULL);
                        info.diskFree += std::to_wstring(static_cast<int>(drive)) + L": Free: " + std::to_wstring(freeSpace.QuadPart / 1024 / 1024) + L" GB\n";
                    }
                }

                info.gpus.clear();
                ENUMDISPLAYDEVICESW dev = {0};
                dev.cb = sizeof(dev);
                EnumDisplayDevicesW(NULL, 0, &dev, 0);
                while (dev.dwDeviceName[0]) {
                    wchar_t gpuName[256];
                    wcsncpy_s(gpuName, sizeof(gpuName), dev.dwDeviceName, wcslen(dev.dwDeviceName));
                    std::string narrowGpuName;
                    WideCharToMultiByte(CP_ACP, 0, gpuName, -1, &narrowGpuName[0], narrowGpuName.capacity(), NULL, NULL);
                    info.gpus.push_back(narrowGpuName);
                    EnumDisplayDevicesW(NULL, dev.dwPrivateData, &dev, 0);
                }

                InvalidateRect(hwnd, NULL, TRUE);
            }
            return 0;
        case WM_PAINT:
            hdc = BeginPaint(hwnd, &ps);
            GetClientRect(hwnd, &rect);
            HDC memDC = CreateCompatibleDC(hdc);
            HGDIOBJ oldBrush = SelectObject(memDC, GetStockObject(BLACK_BRUSH));
            RECT textRect = rect;
            textRect.top = 10;
            textRect.left = 10;
            textRect.right = 580;
            textRect.bottom = 380;
            FillRect(memDC, &textRect, (HBRUSH)oldBrush);
            SelectObject(memDC, GetStockObject(WHITE_BRUSH));
            SetBkMode(memDC, TRANSPARENT);
            HFONT font = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
            HGDIOBJ oldFont = SelectObject(memDC, font);
            SetTextColor(memDC, RGB(0, 0, 255));
            DrawTextW(memDC, (LPCWSTR)(L"CPU Usage: " + std::to_wstring(static_cast<int>(info.cpuUsage)) + L"%"), -1, &textRect);
            textRect.top += 20;
            SetTextColor(memDC, RGB(0, 255, 0));
            DrawTextW(memDC, (LPCWSTR)(L"Memory: " + std::to_wstring(info.totalMem.QuadPart / 1024 / 1024) + L" MB / " + std::to_wstring(info.availMem.QuadPart / 1024 / 1024) + L" MB"), -1, &textRect);
            textRect.top += 20;
            SetTextColor(memDC, RGB(255, 0, 0));
            DrawTextW(memDC, info.diskFree.c_str(), -1, &textRect);
            textRect.top += 20;
            SetTextColor(memDC, RGB(0, 0, 0));
            for (const auto& gpu : info.gpus) {
                DrawTextW(memDC, gpu.c_str(), -1, &textRect);
                textRect.top += 20;
            }
            DeleteObject(font);
            DeleteDC(memDC);
            EndPaint(hwnd, &ps);
            return 0;
        case WM_DESTROY:
            KillTimer(hwnd, TIMER_ID);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}