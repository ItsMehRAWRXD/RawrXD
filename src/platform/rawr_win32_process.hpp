// rawr_win32_process.hpp — CreateProcessW + pipes helpers
#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

namespace rawr {

struct WinProcess {
    HANDLE hProc = nullptr;
    HANDLE hThread = nullptr;
    HANDLE hOutR = nullptr;
    HANDLE hErrR = nullptr;
    HANDLE hInW = nullptr;
    DWORD pid = 0;
};

bool WinProcessSpawn(WinProcess& p, const std::wstring& cmdline);
void WinProcessClose(WinProcess& p);
bool WinProcessAlive(const WinProcess& p);
int WinProcessExitCode(const WinProcess& p);
bool WinProcessTerminate(WinProcess& p, UINT code = 1);
bool WinProcessWriteStdin(WinProcess& p, const char* data, DWORD n);
DWORD WinProcessPeekRead(HANDLE pipe, char* buf, DWORD cap);

std::wstring Utf8ToWide(const std::string& s);
std::string WideToUtf8(const std::wstring& w);

} // namespace rawr
#endif
