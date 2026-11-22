// native_debug_session_test.cpp — Win32 debug session acceptance (G50/G53).
//
// Launches the debuggee under DEBUG_ONLY_THIS_PROCESS, handles debug events,
// verifies breakpoints, debug-console output, and exit code. No third-party
// debugger dependency.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: native_debug_session_test <debuggee.exe>\n");
        return 2;
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(argv[1], nullptr, nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &startup, &process)) {
        std::fprintf(stderr, "DEBUG_LAUNCH_FAILED=%lu\n", GetLastError());
        return 1;
    }
    bool processCreated = false, exited = false, consoleReady = false;
    bool consoleValue = false, unexpectedException = false, apiFailure = false;
    unsigned breakpoints = 0;
    DWORD exitCode = 0;
    const ULONGLONG start = GetTickCount64();
    while (!exited && GetTickCount64() - start < 30000) {
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, 1000)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
            apiFailure = true;
            break;
        }
        DWORD continuation = DBG_CONTINUE;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            processCreated = true;
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT: {
            const DWORD code = event.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_BREAKPOINT) ++breakpoints;
            else { unexpectedException = true; continuation = DBG_EXCEPTION_NOT_HANDLED; }
            break;
        }
        case OUTPUT_DEBUG_STRING_EVENT: {
            const auto& info = event.u.DebugString;
            const size_t length = info.nDebugStringLength;
            if (!info.fUnicode && length > 0 && length <= 65536) {
                std::vector<char> text(length + 1, '\0');
                SIZE_T received = 0;
                if (ReadProcessMemory(process.hProcess, info.lpDebugStringData,
                                      text.data(), length, &received)) {
                    text[received] = '\0';
                    std::printf("DEBUG_CONSOLE=%s\n", text.data());
                    if (std::strstr(text.data(), "RAWRXD_DEBUG_CONSOLE_READY")) consoleReady = true;
                    if (std::strstr(text.data(), "RAWRXD_DEBUG_CONSOLE_VALUE_42")) consoleValue = true;
                }
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            exitCode = event.u.ExitProcess.dwExitCode;
            exited = true;
            break;
        default: break;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)) {
            apiFailure = true;
            break;
        }
    }
    if (!exited) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 5000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    const bool passed = processCreated && exited && exitCode == 42 &&
                        breakpoints >= 2 && consoleReady && consoleValue &&
                        !unexpectedException && !apiFailure;
    std::printf("DEBUG_PROCESS_CREATED=%d\nDEBUG_BREAKPOINTS=%u\nDEBUG_CONSOLE_READY=%d\n"
                "DEBUG_CONSOLE_VALUE=%d\nDEBUG_PROCESS_EXIT=%lu\nDEBUG_API_FAILURE=%d\n"
                "DEBUG_SESSION=%s\n",
                int(processCreated), breakpoints, int(consoleReady), int(consoleValue),
                static_cast<unsigned long>(exitCode), int(apiFailure), passed ? "PASS" : "FAIL");
    return passed ? 0 : 1;
}