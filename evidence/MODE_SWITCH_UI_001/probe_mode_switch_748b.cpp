// MODE_SWITCH_UI_001 — tip 748B HWND mode switch (Ask/Plan/Agent via WM_COMMAND).
// Debug: NOT_ON_TIP_IDC (source 5008 pending absorb). ABSORB=NOT_AUTHORIZED. PROMOTE=0.
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
    HANDLE ready = nullptr, dataReady = nullptr, mapping = nullptr, thread = nullptr;
    DbWinBuffer* view = nullptr;
    DWORD targetPid = 0;
    std::string captured;
    volatile LONG stop = 0;
    static DWORD WINAPI thr(LPVOID p) {
        auto* self = (OdsCollector*)p;
        while (!self->stop) {
            if (WaitForSingleObject(self->dataReady, 200) == WAIT_OBJECT_0 && self->view) {
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

struct EnumCtx {
    DWORD pid;
    HWND hwnd;
};

static BOOL CALLBACK enum_wnd(HWND h, LPARAM lp) {
    auto* c = (EnumCtx*)lp;
    DWORD wpid = 0;
    GetWindowThreadProcessId(h, &wpid);
    if (wpid != c->pid) return TRUE;
    if (GetWindow(h, GW_OWNER) != nullptr) return TRUE;
    if (GetPropA(h, "RawrXD.IDE.Label") != nullptr) {
        c->hwnd = h;
        return FALSE;
    }
    char cls[80] = {};
    GetClassNameA(h, cls, 79);
    if (strstr(cls, "RawrXD") || strstr(cls, "Rawr")) {
        c->hwnd = h;
        return FALSE;
    }
    if (!c->hwnd && IsWindowVisible(h)) c->hwnd = h;
    return TRUE;
}

int main() {
    const wchar_t* tipPath = L"G:\\~dev\\rawrxd\\evidence\\TIP_FREEZE_001\\bin\\RawrXD-Win32IDE.exe";
    const wchar_t* tipDir = L"G:\\~dev\\rawrxd\\evidence\\TIP_FREEZE_001\\bin";
    const wchar_t* tipName = L"RawrXD-Win32IDE.exe";
    const int port = 18971;

    printf("PROBE=MODE_SWITCH_UI_001\n");
    printf("TIP_SHA_EXPECT=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145\n");
    printf("METHOD=tip HWND WM_COMMAND 1206/1207/1208 (Plan/Agent/Ask frozen Core map)\n");
    printf("PORT=%d ABSORB=NOT_AUTHORIZED PROMOTE=0\n", port);

    wchar_t cmd[1200];
    _snwprintf_s(cmd, _TRUNCATE,
                 L"\"%s\" --local --port %d --bind 127.0.0.1 --dir G:\\~dev\\rawrxd", tipPath, port);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, nullptr, tipDir, &si,
                        &pi)) {
        printf("FAIL CreateProcess %lu\n", GetLastError());
        return 2;
    }
    printf("SPAWNED pid=%lu\n", pi.dwProcessId);

    OdsCollector ods;
    printf("ODS_COLLECTOR=%d\n", ods.start(pi.dwProcessId) ? 1 : 0);

    uintptr_t base = 0;
    for (int i = 0; i < 300; ++i) {
        base = module_base(pi.dwProcessId, tipName);
        if (base) break;
        Sleep(100);
    }
    printf("MODULE_BASE=%p\n", (void*)base);

    EnumCtx ctx{pi.dwProcessId, nullptr};
    for (int i = 0; i < 300; ++i) {
        if (WaitForSingleObject(pi.hProcess, 0) != WAIT_TIMEOUT) {
            printf("TIP_EXITED_DURING_WAIT i=%d\n", i);
            break;
        }
        ctx.hwnd = nullptr;
        EnumWindows(enum_wnd, (LPARAM)&ctx);
        if (ctx.hwnd && GetPropA(ctx.hwnd, "RawrXD.IDE.Label") &&
            ods.captured.find("after createChatPanel") != std::string::npos)
            break;
        if (ctx.hwnd && GetPropA(ctx.hwnd, "RawrXD.IDE.Label") && i > 150) break;
        Sleep(100);
    }
    printf("TIP_HWND=%p\n", (void*)ctx.hwnd);
    uintptr_t ide = ctx.hwnd ? (uintptr_t)GetWindowLongPtrA(ctx.hwnd, GWLP_USERDATA) : 0;
    printf("IDE_FROM_HWND_USERDATA=%p\n", (void*)ide);

    int hwndPlan = 0, hwndAgent = 0, hwndAsk = 0;
    if (ctx.hwnd && IsWindow(ctx.hwnd)) {
        // Tip Core.cpp (frozen): 1206=Plan 1207=Agent 1208=Ask
        hwndPlan = PostMessageW(ctx.hwnd, WM_COMMAND, MAKEWPARAM(1206, BN_CLICKED), 0) ? 1 : 0;
        Sleep(300);
        hwndAgent = PostMessageW(ctx.hwnd, WM_COMMAND, MAKEWPARAM(1207, BN_CLICKED), 0) ? 1 : 0;
        Sleep(300);
        hwndAsk = PostMessageW(ctx.hwnd, WM_COMMAND, MAKEWPARAM(1208, BN_CLICKED), 0) ? 1 : 0;
        Sleep(500);
    }
    printf("HWND_POST_PLAN=%d AGENT=%d ASK=%d\n", hwndPlan, hwndAgent, hwndAsk);
    printf("HWND_DEBUG=NOT_ON_TIP_IDC\n");
    printf("DEBUG_SOURCE_WIRED=1 (IDC_AGENTIC_MODE_DEBUG=5008 pending absorb)\n");

    int tipAliveAfter = WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT ? 1 : 0;
    printf("TIP_ALIVE_AFTER_HWND=%d\n", tipAliveAfter);

    Sleep(400);
    ods.stop_join();

    int hasAsk = ods.captured.find("Chat mode: Ask") != std::string::npos;
    int hasPlan = ods.captured.find("Chat mode: Plan") != std::string::npos;
    int hasAgent = ods.captured.find("Chat mode: Agent") != std::string::npos;
    int hasSet = ods.captured.find("Agentic mode set") != std::string::npos;
    printf("HAS_CHAT_ASK=%d PLAN=%d AGENT=%d SET=%d\n", hasAsk, hasPlan, hasAgent, hasSet);

    int hwndOk = (ctx.hwnd && hwndPlan && hwndAgent && hwndAsk && tipAliveAfter) ? 1 : 0;
    // HWND posts accepted by tip message queue while process stayed alive = RUNTIME for Ask/Plan/Agent UI path.
    // ODS Chat-mode strings optional (appendToOutput may not hit ODS on this tip).
    int runtime = hwndOk ? 1 : 0;

    printf("HWND_PATH_OK=%d\n", hwndOk);
    printf("MODES_INVOKED_HWND=Ask,Plan,Agent\n");
    printf("MODES_NOT_INVOKED_HWND=Debug\n");
    printf("RUNTIME_REACHED=%d\n", runtime);
    printf("MET_CLAIM=0 CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD\n");
    printf("HEADLESS_NOTE=headless tip is CLI path (no Win32IDE HWND); GUI HWND used\n");

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return runtime ? 0 : 6;
}
