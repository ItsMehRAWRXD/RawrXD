// Invoke GateStub / HandleToolActionStatus(void*) inside LIVE tip process via remote thread.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static DWORD find_pid_by_exe(const wchar_t* exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static uintptr_t module_base(DWORD pid, const wchar_t* modName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modName) == 0) { base = (uintptr_t)me.modBaseAddr; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

int main(int argc, char** argv) {
    const wchar_t* tipPath = L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin\\RawrXD-Win32IDE.exe";
    const wchar_t* tipName = L"RawrXD-Win32IDE.exe";
    int port = 18766;
    if (argc > 1) port = atoi(argv[1]);

    printf("PROBE=TOOL_ACTION_STATUS_RUNTIME_001_REMOTE\n");
    printf("TIP=%ls\n", tipPath);
    printf("METHOD=CreateProcess --headless + CreateRemoteThread GateStub/void HandleToolActionStatus\n");
    printf("CMD_ID=44016 ui.toolStatus\n");

    wchar_t cmd[1024];
    _snwprintf_s(cmd, _TRUNCATE,
        L"\"%s\" --headless --local --port %d --bind 127.0.0.1 --dir G:\\~dev\\rawrxd",
        tipPath, port);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                        nullptr, L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin", &si, &pi)) {
        printf("FAIL CreateProcess err=%lu\n", GetLastError());
        return 2;
    }
    printf("SPAWNED pid=%lu\n", pi.dwProcessId);

    // Wait for main module to map
    uintptr_t base = 0;
    for (int i = 0; i < 100; ++i) {
        base = module_base(pi.dwProcessId, tipName);
        if (base) break;
        Sleep(100);
    }
    if (!base) {
        printf("FAIL module base not found\n");
        TerminateProcess(pi.hProcess, 1);
        return 3;
    }
    printf("MODULE_BASE=%p\n", (void*)base);

    // Extra settle for CRT init / server listen
    Sleep(1500);

    const uintptr_t RVA_GATE = 0x192F310ull;
    const uintptr_t RVA_VOID = 0x192F4B0ull;
    LPTHREAD_START_ROUTINE gate = (LPTHREAD_START_ROUTINE)(base + RVA_GATE);
    LPTHREAD_START_ROUTINE voidH = (LPTHREAD_START_ROUTINE)(base + RVA_VOID);

    // GateStub(Win32IDE*) and HandleToolActionStatus(void*) both take one pointer.
    // Pass nullptr — GateStub early-returns after OutputDebugStringA.
    printf("REMOTE_CALL GateStub(nullptr) @%p\n", (void*)gate);
    HANDLE t1 = CreateRemoteThread(pi.hProcess, nullptr, 0, gate, nullptr, 0, nullptr);
    if (!t1) {
        printf("FAIL CreateRemoteThread GateStub err=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }
    DWORD wr = WaitForSingleObject(t1, 10000);
    DWORD ec = 0; GetExitCodeThread(t1, &ec);
    printf("GateStub_thread wait=%lu exit=%lu\n", wr, ec);
    CloseHandle(t1);

    printf("REMOTE_CALL HandleToolActionStatus(nullptr) @%p\n", (void*)voidH);
    HANDLE t2 = CreateRemoteThread(pi.hProcess, nullptr, 0, voidH, nullptr, 0, nullptr);
    if (!t2) {
        printf("FAIL CreateRemoteThread void handler err=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 5;
    }
    wr = WaitForSingleObject(t2, 10000);
    GetExitCodeThread(t2, &ec);
    printf("VoidHandler_thread wait=%lu exit=%lu\n", wr, ec);
    CloseHandle(t2);

    // Process still alive? (did not crash)
    DWORD pec = 0;
    GetExitCodeProcess(pi.hProcess, &pec);
    int alive = (pec == STILL_ACTIVE) ? 1 : 0;
    printf("TIP_ALIVE=%d exitCode=%lu\n", alive, pec);

    // Negative static proof from tip image strings (already linked GateStub)
    // Dynamic: remote call returned without killing process = GateStub ran null-safe.
    printf("NEG_remote_gate_no_crash=%d\n", alive);
    printf("NOTE=ODS text captured separately via DebugView optional; null ide skips appendToOutput\n");

    if (alive) {
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("RUNTIME_REMOTE_REACHED=%d\n", alive);
    printf("PROMOTE=0\n");
    return alive ? 0 : 6;
}
