// rawr_term_host_main.cpp
#include "rawr_terminal_host.hpp"
#include "rawr_terminal_protocol.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>

int main() {
    // Single-instance: tip EnsureHostRunning may spawn while a host is live;
    // second process must exit so overlapping pipe servers do not race.
    HANDLE mtx = CreateMutexA(nullptr, TRUE, rawr::term::HostMutexName());
    if (!mtx) return 2;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mtx);
        fprintf(stderr, "rawr_terminal_host already running\n");
        return 0;
    }
    fprintf(stderr, "rawr_terminal_host listening on %s\n",
            rawr::term::HostPipeName());
    int rc = rawr::term::RunTerminalHost(0);
    CloseHandle(mtx);
    return rc;
}
