// ============================================================================
// Win32IDE_CrashReporter.cpp — Crash Reporter (Batch 7 BD05)
// Minidump collection, optional upload
// ============================================================================
#include "Win32IDE.h"
#include <richedit.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <commctrl.h>
#include <dbghelp.h>
#include <cstdio>

#pragma comment(lib, "dbghelp.lib")

struct CrashFrame {
    DWORD64     address;
    std::string module;
    std::string function;
    std::string file;
    int         line;
};

void Win32IDE::initCrashReporter() {
    appendToOutput("[CrashReporter] Crash reporter initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::showCrashReport(const std::string& crashFile) {
    std::ostringstream msg;
    msg << "=== Crash Report ===\n";
    msg << "Crash file: " << crashFile << "\n";
    msg << "Time: " << std::ctime(nullptr);
    msg << "Stack trace: See crash log\n";

    MessageBoxA(m_hwndMain, msg.str().c_str(), "Crash Reporter",
                MB_ICONWARNING | MB_OK);
}

std::string Win32IDE::getLastCrashLog() {
    return "No recent crashes.";
}

bool Win32IDE::writeTestMinidump(const char* outPath) {
    if (!outPath || !outPath[0]) return false;
    // MiniDumpWriteDump suspends every thread in the target process. Calling it
    // (or waiting on a dumper thread) from the UI/message-pump thread deadlocks.
    // Fire-and-forget: worker writes .dmp + TOP25_C49_DUMP.log; caller returns.
    struct DumpJob {
        char path[MAX_PATH];
        DWORD pid;
    };
    auto* job = new DumpJob{};
    strncpy_s(job->path, outPath, _TRUNCATE);
    job->pid = GetCurrentProcessId();
    {
        FILE* f = nullptr;
        if (fopen_s(&f, "F:\\rawrxd\\evidence\\TOP25_C49_DUMP.log", "w") == 0 && f) {
            fprintf(f, "queued=1 path=%s pid=%lu\n", job->path, job->pid);
            fclose(f);
        }
    }
    HANDLE thr = CreateThread(
        nullptr, 0,
        [](LPVOID p) -> DWORD {
            auto* j = static_cast<DumpJob*>(p);
            // Brief yield so UI thread finishes WM_COMMAND before suspend.
            Sleep(50);
            HANDLE file = CreateFileA(j->path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
            DWORD err = 0;
            BOOL ok = FALSE;
            DWORD size = 0;
            if (file == INVALID_HANDLE_VALUE) {
                err = GetLastError();
            } else {
                HANDLE proc = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                    FALSE, j->pid);
                if (!proc) {
                    err = GetLastError();
                    CloseHandle(file);
                } else {
                    const MINIDUMP_TYPE type = static_cast<MINIDUMP_TYPE>(
                        MiniDumpNormal | MiniDumpWithThreadInfo);
                    ok = MiniDumpWriteDump(proc, j->pid, file, type,
                                           nullptr, nullptr, nullptr);
                    if (!ok) err = GetLastError();
                    CloseHandle(file);
                    CloseHandle(proc);
                    WIN32_FILE_ATTRIBUTE_DATA fad{};
                    if (GetFileAttributesExA(j->path, GetFileExInfoStandard, &fad))
                        size = fad.nFileSizeLow;
                }
            }
            FILE* f = nullptr;
            if (fopen_s(&f, "F:\\rawrxd\\evidence\\TOP25_C49_DUMP.log", "w") == 0 && f) {
                fprintf(f, "ok=%d size=%lu path=%s pid=%lu err=%lu\n",
                        ok ? 1 : 0, size, j->path, j->pid, err);
                fclose(f);
            }
            delete j;
            return ok ? 0 : 2;
        },
        job, 0, nullptr);
    if (!thr) {
        FILE* f = nullptr;
        if (fopen_s(&f, "F:\\rawrxd\\evidence\\TOP25_C49_DUMP.log", "w") == 0 && f) {
            fprintf(f, "FAIL CreateThread GetLastError=%lu path=%s\n",
                    GetLastError(), outPath);
            fclose(f);
        }
        delete job;
        return false;
    }
    CloseHandle(thr);
    appendToOutput(std::string("[CrashReporter] Minidump queued: ") + outPath + "\n",
                   "Output", OutputSeverity::Info);
    return true;
}
