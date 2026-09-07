// rawr_win32_process.cpp
#include "rawr_win32_process.hpp"
#include <vector>

namespace rawr {

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0,
                                nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr,
                        nullptr);
    return s;
}

bool WinProcessSpawn(WinProcess& p, const std::wstring& cmdline) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE outR = 0, outW = 0, errR = 0, errW = 0, inR = 0, inW = 0;
    if (!CreatePipe(&outR, &outW, &sa, 0)) return false;
    if (!CreatePipe(&errR, &errW, &sa, 0)) return false;
    if (!CreatePipe(&inR, &inW, &sa, 0)) return false;
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outW;
    si.hStdError = errW;
    si.hStdInput = inR;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cl(cmdline.begin(), cmdline.end());
    cl.push_back(0);
    BOOL ok = CreateProcessW(nullptr, cl.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(outW);
    CloseHandle(errW);
    CloseHandle(inR);
    if (!ok) {
        CloseHandle(outR); CloseHandle(errR); CloseHandle(inW);
        return false;
    }
    p.hProc = pi.hProcess;
    p.hThread = pi.hThread;
    p.hOutR = outR;
    p.hErrR = errR;
    p.hInW = inW;
    p.pid = pi.dwProcessId;
    return true;
}

void WinProcessClose(WinProcess& p) {
    auto cl = [](HANDLE& h) {
        if (h) { CloseHandle(h); h = nullptr; }
    };
    cl(p.hOutR); cl(p.hErrR); cl(p.hInW); cl(p.hThread); cl(p.hProc);
    p.pid = 0;
}

bool WinProcessAlive(const WinProcess& p) {
    if (!p.hProc) return false;
    DWORD st = 0;
    if (!GetExitCodeProcess(p.hProc, &st)) return false;
    return st == STILL_ACTIVE;
}

int WinProcessExitCode(const WinProcess& p) {
    if (!p.hProc) return -1;
    DWORD st = 0;
    GetExitCodeProcess(p.hProc, &st);
    return st == STILL_ACTIVE ? -1 : (int)st;
}

bool WinProcessTerminate(WinProcess& p, UINT code) {
    if (!p.hProc) return false;
    BOOL ok = TerminateProcess(p.hProc, code);
    WaitForSingleObject(p.hProc, 3000);
    return ok != 0;
}

bool WinProcessWriteStdin(WinProcess& p, const char* data, DWORD n) {
    if (!p.hInW || !data || !n) return false;
    DWORD wr = 0;
    return WriteFile(p.hInW, data, n, &wr, nullptr) != 0;
}

DWORD WinProcessPeekRead(HANDLE pipe, char* buf, DWORD cap) {
    DWORD avail = 0, rd = 0;
    if (!pipe || !PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr))
        return 0;
    if (!avail) return 0;
    DWORD want = avail < cap ? avail : cap;
    if (!ReadFile(pipe, buf, want, &rd, nullptr)) return 0;
    return rd;
}

} // namespace rawr
