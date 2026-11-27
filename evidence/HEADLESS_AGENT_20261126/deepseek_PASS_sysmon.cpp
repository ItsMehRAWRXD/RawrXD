#include <windows.h>
#include <psapi.h>
#include <sysinfoapi.h>
#include <iostream>

void UpdateSystemInfo() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    std::cout << "Total physical memory: " << memInfo.ullTotalPhys / (1024 * 1024) << " MB" << std::endl;
    std::cout << "Available physical memory: " << memInfo.ullAvailPhys / (1024 * 1024) << " MB" << std::endl;

    ULARGE_INTEGER li;
    GetDiskFreeSpaceExW(NULL, &li, NULL, NULL);
    std::cout << "Total disk space: " << li.QuadPart / (1024 * 1024 * 1024) << " GB" << std::endl;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    std::cout << "Number of processors: " << si.dwNumberOfProcessors << std::endl;

    DISPLAY_DEVICEW dd;
    dd.cb = sizeof(dd);
    EnumDisplayDevicesW(NULL, 0, &dd, 0);
    std::cout << "Display device: " << dd.DeviceName << std::endl;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    UpdateSystemInfo();
    while (true) {
        // Wait for 1 second
        Sleep(1000);
        // Update and display system information
        UpdateSystemInfo();
    }
    return 0;
}
