// RawrXD-ExtensionHost.exe — real child process for host_pid.
#include <windows.h>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, L"Local\\RawrXD_ExtensionHost_Stop");
    if (!stop) {
        for (;;) Sleep(60000);
        return 0;
    }
    WaitForSingleObject(stop, INFINITE);
    CloseHandle(stop);
    return 0;
}
