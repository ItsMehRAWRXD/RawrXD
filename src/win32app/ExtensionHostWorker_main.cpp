// RawrXD-ExtensionHost.exe — real child process for host_pid.
#include <windows.h>
#include <string>

static std::string Arg(int argc, char** argv, const char* name) {
    for (int i = 1; i + 1 < argc; ++i)
        if (lstrcmpiA(argv[i], name) == 0) return argv[i + 1];
    return {};
}

int main(int argc, char** argv) {
    const std::string readyName = Arg(argc, argv, "--ready-event");
    const std::string stopName = Arg(argc, argv, "--stop-event");
    if (readyName.empty() || stopName.empty()) return 2;
    HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, readyName.c_str());
    HANDLE stop = OpenEventA(SYNCHRONIZE, FALSE, stopName.c_str());
    if (!ready || !stop) {
        if (ready) CloseHandle(ready);
        if (stop) CloseHandle(stop);
        return 3;
    }
    SetEvent(ready);
    WaitForSingleObject(stop, INFINITE);
    CloseHandle(ready);
    CloseHandle(stop);
    return 0;
}
