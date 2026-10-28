// AGENTIC_COMPOSER_RUNTIME_001 — tip mode/composer invoke (no tip rebuild).
// Spawns tip headless, resolves g_pMainIDE, remote-calls Ask/Plan/Agent +
// HandleAgenticComposerUX. Debug/Auto absent from tip AgenticMode enum.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string>

#pragma pack(push, 1)
struct DbWinBuffer {
    DWORD pid;
    char data[4096 - sizeof(DWORD)];
};
#pragma pack(pop)

static uintptr_t module_base(DWORD pid, const wchar_t* modName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modName) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                break;
            }
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
        ready = CreateEventA(nullptr, FALSE, TRUE, "DBWIN_BUFFER_READY");
        dataReady = CreateEventA(nullptr, FALSE, FALSE, "DBWIN_DATA_READY");
        mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, "DBWIN_BUFFER");
        if (!ready || !dataReady || !mapping) return false;
        view = (DbWinBuffer*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 4096);
        if (!view) return false;
        thread = CreateThread(nullptr, 0, thr, this, 0, nullptr);
        return thread != nullptr;
    }
    void stop_join() {
        InterlockedExchange(&stop, 1);
        if (thread) {
            WaitForSingleObject(thread, 2000);
            CloseHandle(thread);
            thread = nullptr;
        }
        if (view) {
            UnmapViewOfFile(view);
            view = nullptr;
        }
        if (mapping) CloseHandle(mapping);
        if (ready) CloseHandle(ready);
        if (dataReady) CloseHandle(dataReady);
    }
};

static int remote_call(HANDLE proc, LPTHREAD_START_ROUTINE fn, void* arg, const char* tag) {
    if (!fn) {
        printf("REMOTE_%s=SKIP_NULL_FN\n", tag);
        return -1;
    }
    HANDLE th = CreateRemoteThread(proc, nullptr, 0, fn, arg, 0, nullptr);
    if (!th) {
        printf("REMOTE_%s=CreateRemoteThread_FAIL err=%lu\n", tag, GetLastError());
        return -2;
    }
    DWORD wr = WaitForSingleObject(th, 15000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    printf("REMOTE_%s=1 wait=%lu exit=%lu\n", tag, (unsigned long)wr, (unsigned long)code);
    return (wr == WAIT_OBJECT_0) ? 0 : -3;
}

int main() {
    const wchar_t* tipPath = L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin\\RawrXD-Win32IDE.exe";
    const wchar_t* tipName = L"RawrXD-Win32IDE.exe";
    const wchar_t* model = L"G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    const int port = 18771; // avoid ToolActionStatus 18767 / swarm conflicts

    // Map (preferred base 0x140000000) — tip SHA 6832F439…
    const uintptr_t RVA_ASK = 0x5A8850ull;
    const uintptr_t RVA_AGENT = 0x5A8840ull;
    const uintptr_t RVA_PLAN = 0x5A8870ull;
    const uintptr_t RVA_COMPOSER = 0x5C0C40ull; // HandleAgenticComposerUX
    const uintptr_t RVA_G_PMAINIDE = 0x13ADAFE0ull;

    printf("PROBE=AGENTIC_COMPOSER_RUNTIME_001\n");
    printf("TIP_SHA_EXPECT=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2\n");
    printf("METHOD=headless tip + g_pMainIDE RPM + CreateRemoteThread Ask/Plan/Agent/ComposerUX\n");
    printf("PORT=%d\n", port);
    printf("DEBUG_MODE=NOT_ON_TIP_ENUM\n");
    printf("AUTO_MODE=NOT_ON_TIP_ENUM\n");

    SetEnvironmentVariableW(L"RAWRXD_PRODUCT_MODEL", model);

    wchar_t cmd[1400];
    _snwprintf_s(cmd, _TRUNCATE,
                 L"\"%s\" --headless --local --port %d --bind 127.0.0.1 "
                 L"--dir G:\\~dev\\rawrxd --model \"%s\"",
                 tipPath, port, model);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, nullptr,
                        L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin", &si, &pi)) {
        printf("FAIL CreateProcess %lu\n", GetLastError());
        return 2;
    }
    printf("SPAWNED pid=%lu\n", pi.dwProcessId);

    OdsCollector ods;
    if (ods.start(pi.dwProcessId))
        printf("ODS_COLLECTOR=1\n");
    else
        printf("ODS_COLLECTOR=0\n");

    uintptr_t base = 0;
    for (int i = 0; i < 150; ++i) {
        base = module_base(pi.dwProcessId, tipName);
        if (base) break;
        Sleep(100);
    }
    printf("MODULE_BASE=%p\n", (void*)base);
    if (!base) {
        printf("FAIL no module base\n");
        TerminateProcess(pi.hProcess, 1);
        return 3;
    }

    // Allow headless init + optional model open
    Sleep(4000);

    uintptr_t ide = 0;
    SIZE_T got = 0;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(base + RVA_G_PMAINIDE), &ide, sizeof(ide), &got) ||
        got != sizeof(ide)) {
        printf("FAIL ReadProcessMemory g_pMainIDE err=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }
    printf("G_PMAINIDE=%p\n", (void*)ide);
    if (!ide) {
        printf("FAIL g_pMainIDE null (headless may not bind Win32IDE*)\n");
        remote_call(pi.hProcess, (LPTHREAD_START_ROUTINE)(base + RVA_COMPOSER), nullptr, "COMPOSER_NULL");
        Sleep(300);
        ods.stop_join();
        DWORD live = WaitForSingleObject(pi.hProcess, 0);
        printf("TIP_ALIVE=%d\n", live == WAIT_TIMEOUT ? 1 : 0);
        printf("MODES_INVOKED=NONE_IDE_NULL\n");
        printf("COMPOSER_NULL_CALL=1\n");
        printf("RUNTIME_REACHED=0\n");
        printf("REASON=g_pMainIDE_null\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 5;
    }

    OutputDebugStringA("PROBE_COMPOSER_BEFORE_MODES\n");
    int ask = remote_call(pi.hProcess, (LPTHREAD_START_ROUTINE)(base + RVA_ASK), (void*)ide, "ASK");
    Sleep(200);
    int plan = remote_call(pi.hProcess, (LPTHREAD_START_ROUTINE)(base + RVA_PLAN), (void*)ide, "PLAN");
    Sleep(200);
    int agent = remote_call(pi.hProcess, (LPTHREAD_START_ROUTINE)(base + RVA_AGENT), (void*)ide, "AGENT");
    Sleep(200);
    int composer =
        remote_call(pi.hProcess, (LPTHREAD_START_ROUTINE)(base + RVA_COMPOSER), (void*)ide, "COMPOSER");
    Sleep(500);
    OutputDebugStringA("PROBE_COMPOSER_AFTER_MODES\n");
    Sleep(300);
    ods.stop_join();

    printf("=== ODS_CAPTURE_BEGIN ===\n");
    fwrite(ods.captured.data(), 1, ods.captured.size(), stdout);
    printf("=== ODS_CAPTURE_END ===\n");

    int hasChatAsk = ods.captured.find("Chat mode: Ask") != std::string::npos;
    int hasChatPlan = ods.captured.find("Chat mode: Plan") != std::string::npos;
    int hasChatAgent = ods.captured.find("Chat mode: Agent") != std::string::npos;
    int hasComposerStart = ods.captured.find("[ComposerUX] Session started") != std::string::npos;
    int hasComposerFail = ods.captured.find("[ComposerUX] FAIL_CLOSED") != std::string::npos;
    int hasDefaultModel = ods.captured.find("default-model") != std::string::npos;

    printf("HAS_CHAT_ASK=%d\n", hasChatAsk);
    printf("HAS_CHAT_PLAN=%d\n", hasChatPlan);
    printf("HAS_CHAT_AGENT=%d\n", hasChatAgent);
    printf("HAS_COMPOSER_START=%d\n", hasComposerStart);
    printf("HAS_COMPOSER_FAIL_CLOSED=%d\n", hasComposerFail);
    printf("HAS_DEFAULT_MODEL=%d (must 0)\n", hasDefaultModel);

    DWORD live = WaitForSingleObject(pi.hProcess, 0);
    int tipAlive = (live == WAIT_TIMEOUT) ? 1 : 0;
    printf("TIP_ALIVE=%d\n", tipAlive);

    int modesOk = (ask == 0 && plan == 0 && agent == 0) ? 1 : 0;
    int composerOk = (composer == 0) ? 1 : 0;
    int runtime = (tipAlive && modesOk && composerOk && !hasDefaultModel) ? 1 : 0;
    printf("MODES_REMOTE_OK=%d\n", modesOk);
    printf("COMPOSER_REMOTE_OK=%d\n", composerOk);
    printf("MODES_INVOKED=Ask,Plan,Agent\n");
    printf("MODES_NOT_INVOKED=Debug,Auto\n");
    printf("RUNTIME_REACHED=%d\n", runtime);
    printf("MET_CLAIM=0\n");
    printf("PROMOTE=0\n");

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return runtime ? 0 : 6;
}
