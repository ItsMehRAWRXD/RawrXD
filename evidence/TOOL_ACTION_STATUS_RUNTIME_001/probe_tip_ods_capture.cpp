// Start tip headless, attach DBWIN ODS capture, remote-call GateStub, seal log.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#pragma pack(push, 1)
struct DbWinBuffer {
    DWORD pid;
    char data[4096 - sizeof(DWORD)];
};
#pragma pack(pop)

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

struct OdsCollector {
    HANDLE ready = nullptr;
    HANDLE dataReady = nullptr;
    HANDLE mapping = nullptr;
    DbWinBuffer* view = nullptr;
    HANDLE thread = nullptr;
    DWORD targetPid = 0;
    std::string captured;
    volatile LONG stop = 0;

    static DWORD WINAPI thr(LPVOID p) {
        auto* self = (OdsCollector*)p;
        while (!self->stop) {
            DWORD w = WaitForSingleObject(self->dataReady, 200);
            if (w == WAIT_OBJECT_0 && self->view) {
                if (self->view->pid == self->targetPid || self->targetPid == 0) {
                    self->captured.append(self->view->data);
                    self->captured.push_back('\n');
                }
                SetEvent(self->ready);
            }
        }
        return 0;
    }

    bool start(DWORD pid) {
        targetPid = pid;
        security_attrs();
        ready = CreateEventA(nullptr, FALSE, TRUE, "DBWIN_BUFFER_READY");
        dataReady = CreateEventA(nullptr, FALSE, FALSE, "DBWIN_DATA_READY");
        mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, "DBWIN_BUFFER");
        if (!ready || !dataReady || !mapping) return false;
        view = (DbWinBuffer*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 4096);
        if (!view) return false;
        thread = CreateThread(nullptr, 0, thr, this, 0, nullptr);
        return thread != nullptr;
    }
    void security_attrs() {}
    void stop_join() {
        InterlockedExchange(&stop, 1);
        if (thread) { WaitForSingleObject(thread, 2000); CloseHandle(thread); thread = nullptr; }
        if (view) { UnmapViewOfFile(view); view = nullptr; }
        if (mapping) CloseHandle(mapping);
        if (ready) CloseHandle(ready);
        if (dataReady) CloseHandle(dataReady);
    }
};

int main() {
    const wchar_t* tipPath = L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin\\RawrXD-Win32IDE.exe";
    const wchar_t* tipName = L"RawrXD-Win32IDE.exe";
    int port = 18767;

    printf("PROBE=TOOL_ACTION_STATUS_RUNTIME_001_ODS\n");
    printf("METHOD=headless tip + DBWIN ODS + CreateRemoteThread GateStub\n");

    wchar_t cmd[1024];
    _snwprintf_s(cmd, _TRUNCATE,
        L"\"%s\" --headless --local --port %d --bind 127.0.0.1 --dir G:\\~dev\\rawrxd",
        tipPath, port);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0,
                        nullptr, L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin", &si, &pi)) {
        printf("FAIL CreateProcess %lu\n", GetLastError());
        return 2;
    }
    printf("SPAWNED pid=%lu\n", pi.dwProcessId);

    OdsCollector ods;
    if (!ods.start(pi.dwProcessId)) {
        printf("FAIL ODS collector (is DebugView holding DBWIN?)\n");
        // continue anyway
    } else {
        printf("ODS_COLLECTOR=1\n");
    }

    uintptr_t base = 0;
    for (int i = 0; i < 100; ++i) {
        base = module_base(pi.dwProcessId, tipName);
        if (base) break;
        Sleep(100);
    }
    printf("MODULE_BASE=%p\n", (void*)base);
    Sleep(1500);

    const uintptr_t RVA_GATE = 0x192F310ull;
    const uintptr_t RVA_VOID = 0x192F4B0ull;
    auto gate = (LPTHREAD_START_ROUTINE)(base + RVA_GATE);
    auto voidH = (LPTHREAD_START_ROUTINE)(base + RVA_VOID);

    // Also emit a local ODS marker so collector wiring is proven
    OutputDebugStringA("PROBE_LOCAL_MARKER_BEFORE_REMOTE\n");

    HANDLE t1 = CreateRemoteThread(pi.hProcess, nullptr, 0, gate, nullptr, 0, nullptr);
    WaitForSingleObject(t1, 10000); CloseHandle(t1);
    HANDLE t2 = CreateRemoteThread(pi.hProcess, nullptr, 0, voidH, nullptr, 0, nullptr);
    WaitForSingleObject(t2, 10000); CloseHandle(t2);

    Sleep(500);
    OutputDebugStringA("PROBE_LOCAL_MARKER_AFTER_REMOTE\n");
    Sleep(300);
    ods.stop_join();

    printf("=== ODS_CAPTURE_BEGIN ===\n");
    fwrite(ods.captured.data(), 1, ods.captured.size(), stdout);
    printf("=== ODS_CAPTURE_END ===\n");

    int hasGate = ods.captured.find("GATED_STUB") != std::string::npos;
    int hasSynthetic = ods.captured.find("SYNTHETIC=1") != std::string::npos;
    int hasFinishedToast = ods.captured.find("Finished with") != std::string::npos;
    int hasSuccessToast = ods.captured.find("success toast") != std::string::npos; // only in forbid text
    int hasForbid = ods.captured.find("FinishedAction forbidden") != std::string::npos
                 || ods.captured.find("no FinishedAction") != std::string::npos;

    printf("HAS_GATED_STUB=%d\n", hasGate);
    printf("HAS_SYNTHETIC=%d\n", hasSynthetic);
    printf("HAS_FORBID_FINISHEDACTION=%d\n", hasForbid);
    printf("HAS_FINISHED_WITH_TOAST=%d (must 0)\n", hasFinishedToast);
    printf("FABRICATED_SUCCESS_TOAST=%d (must 0)\n", hasFinishedToast);

    DWORD pec = 0; GetExitCodeProcess(pi.hProcess, &pec);
    int alive = pec == STILL_ACTIVE;
    printf("TIP_ALIVE=%d\n", alive);

    int neg = hasGate && hasSynthetic && hasForbid && !hasFinishedToast && alive;
    int pos = hasGate && hasSynthetic; // handler reached
    printf("NEG_PASS=%d\n", neg);
    printf("POS_PASS=%d\n", pos);
    printf("RUNTIME_REACHED=%d\n", (neg && pos) ? 1 : 0);
    printf("MET_CLAIM=0\n");
    printf("PROMOTE=0\n");

    if (alive) { TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000); }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return (neg && pos) ? 0 : 7;
}
