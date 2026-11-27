#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

struct SystemInfo {
    std::wstring cpu;
    std::wstring memory;
    std::wstring disk;
    std::wstring gpu;
};

static SystemInfo g_info;
static FILETIME prevIdle = {0}, prevKernel = {0}, prevUser = {0};
static bool first = true;

void UpdateSystemInfo() {
    // CPU: GetSystemTimes
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        if (!first) {
            ULARGE_INTEGER dKernel, dUser, dIdle, dTotal;
            dKernel.HighPart = kernelTime.dwHighDateTime;
            dKernel.LowPart = kernelTime.dwLowDateTime;
            dUser.HighPart = userTime.dwHighDateTime;
            dUser.LowPart = userTime.dwLowDateTime;
            dIdle.HighPart = idleTime.dwHighDateTime;
            dIdle.LowPart = idleTime.dwLowDateTime;
            dTotal.QuadPart = dKernel.QuadPart + dUser.QuadPart + dIdle.QuadPart;
            if (dTotal.QuadPart > 0) {
                double pct = 100.0 * (dKernel.QuadPart + dUser.QuadPart) / dTotal.QuadPart;
                std::wstringstream ss;
                ss << L"CPU: " << std::fixed << std::setprecision(1) << pct << L"%";
                g_info.cpu = ss.str();
            }
        }
        prevIdle = idleTime;
        prevKernel = kernelTime;
        prevUser = userTime;
        first = false;
    } else {
        g_info.cpu = L"CPU: Error";
    }

    // Memory: GlobalMemoryStatusEx
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    std::wstringstream memSS;
    memSS << L"Memory: Total " << (memStatus.ullTotalPhys / (1024 * 1024)) << L" MB, Available " << (memStatus.ullAvailPhys / (1024 * 1024)) << L" MB";
    g_info.memory = memSS.str();

    // Disk: GetDiskFreeSpaceExW
    ULARGE_INTEGER freeBytes, totalBytes;
    if (GetDiskFreeSpaceExW(L"C:", &freeBytes, &totalBytes, nullptr)) {
        std::wstringstream diskSS;
        diskSS << L"Disk C: Total " << (totalBytes.QuadPart / (1024 * 1024 * 1024)) << L" GB, Free " << (freeBytes.QuadPart / (1024 * 1024 * 1024)) << L" GB";
        g_info.disk = diskSS.str();
    } else {
        g_info.disk = L"Disk: Error";
    }

    // GPU: EnumDisplayDevicesW
    DISPLAY_DEVICEW dev = { sizeof(dev), 0 };
    if (EnumDisplayDevicesW(nullptr, 0, &dev, 0)) {
        g_info.gpu = dev.DeviceName;
    } else {
        g_info.gpu = L"GPU: Error";
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        SetTimer(hwnd, 1, 1000, NULL);
        return 0;
    case WM_TIMER:
        UpdateSystemInfo();
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));
        RECT rect = { 10, 10, 500, 300 };
        DrawTextW(hdc, g_info.cpu.c_str(), -1, &rect, DT_LEFT);
        rect.top += 20;
        DrawTextW(hdc, g_info.memory.c_str(), -1, &rect, DT_LEFT);
        rect.top += 20;
        DrawTextW(hdc, g_info.disk.c_str(), -1, &rect, DT_LEFT);
        rect.top += 20;
        DrawTextW(hdc, g_info.gpu.c_str(), -1, &rect, DT_LEFT);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"SysMonClass";
    wc.hbrBackground = NULL;
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(wc.lpszClassName, L"System Monitor", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 400, NULL, NULL, hInstance, NULL);

    if (!hwnd) return 1;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
