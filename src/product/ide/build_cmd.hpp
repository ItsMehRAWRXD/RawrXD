#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
#include <string>
namespace rawr::product {

inline bool BuildProject(const std::string& dir, std::string& out) {
    out.clear();
#ifdef _WIN32
    if (dir.empty()) return false;
    std::string cmd = "cmake --build \"" + dir + "\"";
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    char buf[1024];
    lstrcpynA(buf, cmd.c_str(), 1024);
    if (!CreateProcessA(nullptr, buf, nullptr, nullptr, FALSE, 0, nullptr,
                         dir.c_str(), &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    out = (code == 0) ? "ok" : "fail";
    return code == 0;
#else
    (void)dir;
    return false;
#endif
}

} // namespace rawr::product
