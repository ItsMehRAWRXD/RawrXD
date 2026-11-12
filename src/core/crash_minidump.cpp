#include "crash_minidump.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <string>

#pragma comment(lib, "dbghelp.lib")

namespace RawrXD {
namespace Obs {

namespace {
std::string g_dumpDir;

LONG WINAPI UnhandledFilter(EXCEPTION_POINTERS* ep) {
    if (g_dumpDir.empty() || !ep) return EXCEPTION_CONTINUE_SEARCH;
    char path[MAX_PATH];
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::snprintf(path, sizeof(path),
                  "%s\\rawr-seh-%04u%02u%02u-%02u%02u%02u.dmp", g_dumpDir.c_str(),
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return EXCEPTION_CONTINUE_SEARCH;
    MINIDUMP_EXCEPTION_INFORMATION mei{};
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;
    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file,
                      static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithThreadInfo),
                      &mei, nullptr, nullptr);
    CloseHandle(file);
    return EXCEPTION_EXECUTE_HANDLER;
}
}  // namespace

bool WriteProcessMinidump(const std::string& outPath, unsigned long pid) {
    HANDLE file = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                              FALSE, pid);
    if (!proc) {
        CloseHandle(file);
        return false;
    }
    const BOOL ok = MiniDumpWriteDump(
        proc, pid, file,
        static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithThreadInfo),
        nullptr, nullptr, nullptr);
    CloseHandle(proc);
    CloseHandle(file);
    return ok == TRUE;
}

bool WriteSelfTestMinidump(const std::string& outPath) {
    return WriteProcessMinidump(outPath, GetCurrentProcessId());
}

void InstallUnhandledExceptionFilter(const std::string& dumpDir) {
    g_dumpDir = dumpDir;
    SetUnhandledExceptionFilter(UnhandledFilter);
}

}  // namespace Obs
}  // namespace RawrXD
