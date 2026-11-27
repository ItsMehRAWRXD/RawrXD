#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

// Global variables for CPU calculation
static FILETIME prevIdleTime = {0, 0};
static FILETIME prevKernelTime = {0, 0};
static FILETIME prevUserTime = {0, 0};

// Helper to convert FILETIME to ULARGE_INTEGER
static ULARGE_INTEGER FileTimeToULarge(const FILETIME &ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli;
}

static double GetCpuUsage() {
    FILETIME idleTime, kernelTime, userTime;
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        return -1.0; // error
    }

    ULARGE_INTEGER idle = FileTimeToULarge(idleTime);
    ULARGE_INTEGER kernel = FileTimeToULarge(kernelTime);
    ULARGE_INTEGER user = FileTimeToULarge(userTime);

    ULARGE_INTEGER prevIdle = FileTimeToULarge(prevIdleTime);
    ULARGE_INTEGER prevKernel = FileTimeToULarge(prevKernelTime);
    ULARGE_INTEGER prevUser = FileTimeToULarge(prevUserTime);

    ULONGLONG idleDiff = idle.QuadPart - prevIdle.QuadPart;
    ULONGLONG kernelDiff = kernel.QuadPart - prevKernel.QuadPart;
    ULONGLONG userDiff = user.QuadPart - prevUser.QuadPart;

    ULONGLONG total = kernelDiff + userDiff;
    double cpu = 0.0;
    if (total != 0) {
        cpu = (double)(total - idleDiff) / (double)total * 100.0;
    }

    // Update previous times
    prevIdleTime = idleTime;
    prevKernelTime = kernelTime;
    prevUserTime = userTime;

    return cpu;
}

static std::string GetMemoryUsage() {
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    if (!GlobalMemoryStatusEx(&mem)) {
        return "Memory: N/A";
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    double used = (double)(mem.ullTotalPhys - mem.ullAvailPhys) / (1024 * 1024 * 1024);
    double total = (double)mem.ullTotalPhys / (1024 * 1024 * 1024);
    oss << "Memory: " << used << " GB / " << total << " GB";
    return oss.str();
}

static std::string GetDiskUsage() {
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (!GetDiskFreeSpaceExW(L"\\\\.\\C:", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        return "Disk: N/A";
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    double used = (double)(totalNumberOfBytes.QuadPart - totalNumberOfFreeBytes.QuadPart) / (1024.0 * 1024.0 * 1024.0);
    double total = (double)totalNumberOfBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
    oss << "Disk: " << used << " GB / " << total << " GB";
    return oss.str();
}

static std::string GetGpuInfo() {
    DISPLAY_DEVICEW dd;
    dd.cb = sizeof(dd);
    if (EnumDisplayDevicesW(NULL, 0, &dd, 0)) {
        std::wstring wname(dd.DeviceString);
        std::string name(wname.begin(), wname.end());
        return "GPU: " + name;
    }
    return "GPU: N/A";
}

static void UpdateWindowText(HWND hwnd) {
    double cpu = GetCpuUsage();
    std::string mem = GetMemoryUsage();
    std::string disk = GetDiskUsage();
    std::string gpu = GetGpuInfo();

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    if (cpu >= 0.0) {
        oss << "CPU: " << cpu << "%\n";
    } else {
        oss << "CPU: N/A\n";
    }
    oss << mem << "\n";
    oss << disk << "\n";
    oss << gpu;

    std::string text = oss.str();
    SetWindowTextA(hwnd, text.c_str());
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            // Initialize previous times
            GetSystemTimes(&prevIdleTime, &prevKernelTime, &prevUserTime);
            SetTimer(hwnd, 1, 1000, NULL);
            return 0;
        case WM_TIMER:
            if (wParam == 1) {
                UpdateWindowText(hwnd);
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    const char *className = "SysMonWindow";
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, className, "SysMon", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, 400, 200,
                                NULL, NULL, hInstance, NULL);
    if (!hwnd) return -1;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
