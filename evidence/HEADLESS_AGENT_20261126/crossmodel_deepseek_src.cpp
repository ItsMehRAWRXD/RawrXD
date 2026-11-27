#include <windows.h>
#include <iostream>

void UpdateSystemInfo() {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    std::cout << "Total physical memory: " << memStatus.ullTotalPhys / (1024 * 1024) << " MB" << std::endl;
    std::cout << "Available physical memory: " << memStatus.ullAvailPhys / (1024 * 1024) << " MB" << std::endl;

    ULARGE_INTEGER liFreeBytesAvailable, liTotalBytes, liTotalFreeBytes;
    GetDiskFreeSpaceExW(L"C:", &liFreeBytesAvailable, &liTotalBytes, &liTotalFreeBytes);
    std::cout << "Total C: drive space: " << liTotalBytes.QuadPart / (1024 * 1024) << " MB" << std::endl;
    std::cout << "Available C: drive space: " << liFreeBytesAvailable.QuadPart / (1024 * 1024) << " MB" << std::endl;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    std::cout << "Number of processors: " << si.dwNumberOfProcessors << std::endl;

    DISPLAY_DEVICEW dd;
    dd.cb = sizeof(dd);
    EnumDisplayDevicesW(NULL, 0, &dd, 0);
    std::cout << "Display device: " << dd.DeviceName << std::endl;
}

int main() {
    UpdateSystemInfo();
    while (true) {
        Sleep(1000);
        UpdateSystemInfo();
    }
    return 0;
}
