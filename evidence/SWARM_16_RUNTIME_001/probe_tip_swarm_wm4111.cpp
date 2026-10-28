// Tip EXE seal probe: PostMessage WM_COMMAND IDM_SUBAGENT_SWARM (4111)
// + optional CreateRemoteThread into onSubAgentSwarm(this) via GWLP_USERDATA.
// Does NOT modify tip EXE. LOCAL_ONLY. PROMOTE=0.
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

struct EnumCtx {
    DWORD pid;
    HWND hwnd;
};

static BOOL CALLBACK enumProc(HWND hwnd, LPARAM lp) {
    auto* c = (EnumCtx*)lp;
    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != c->pid) return TRUE;
    char cls[256] = {};
    GetClassNameA(hwnd, cls, 255);
    if (strcmp(cls, "RawrXD_IDE_MainWindow") == 0) {
        c->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

static HWND find_main(DWORD pid) {
    EnumCtx c{pid, nullptr};
    EnumWindows(enumProc, (LPARAM)&c);
    return c.hwnd;
}

int main() {
    const wchar_t* tipPath = L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin\\RawrXD-Win32IDE.exe";
    const wchar_t* tipName = L"RawrXD-Win32IDE.exe";
    const UINT IDM_SUBAGENT_SWARM = 4111;
    // Map: ?onSubAgentSwarm@Win32IDE@@QEAAXXZ @ 000000014084e0a0 (pref base 0x140000000)
    const uintptr_t RVA_ON_SWARM = 0x84E0A0ull;

    printf("PROBE=SWARM_16_RUNTIME_001\n");
    printf("CMD_ID=%u\n", IDM_SUBAGENT_SWARM);
    printf("MENU=Agent > SubAgent > Agent: Execute HexMag Swarm\n");
    printf("WM=WM_COMMAND wParam=4111\n");
    printf("TIP_REBUILD=NO\n");

    wchar_t cmd[1024];
    _snwprintf_s(cmd, _TRUNCATE, L"\"%s\"", tipPath);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr,
                        L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin", &si, &pi)) {
        printf("FAIL CreateProcess %lu\n", GetLastError());
        return 2;
    }
    printf("SPAWNED_GUI pid=%lu\n", pi.dwProcessId);

    OdsCollector ods;
    int ods_ok = ods.start(pi.dwProcessId) ? 1 : 0;
    printf("ODS_COLLECTOR=%d\n", ods_ok);

    HWND hwnd = nullptr;
    for (int i = 0; i < 200; ++i) {
        hwnd = find_main(pi.dwProcessId);
        if (hwnd) break;
        Sleep(100);
    }
    printf("MAIN_HWND=%p\n", (void*)hwnd);

    uintptr_t base = 0;
    for (int i = 0; i < 100; ++i) {
        base = module_base(pi.dwProcessId, tipName);
        if (base) break;
        Sleep(100);
    }
    printf("MODULE_BASE=%p\n", (void*)base);

    int post_ok = 0;
    int send_ok = 0;
    int remote_ok = 0;
    DWORD send_result = 0;

    if (hwnd) {
        // Prefer PostMessage (async) then SendMessageTimeout (sync proof of dispatch)
        post_ok = PostMessageW(hwnd, WM_COMMAND, IDM_SUBAGENT_SWARM, 0) ? 1 : 0;
        printf("POSTMESSAGE_WM_COMMAND_4111=%d err=%lu\n", post_ok, GetLastError());
        Sleep(500);
        LRESULT lr = 0;
        DWORD_PTR result = 0;
        send_ok = SendMessageTimeoutW(hwnd, WM_COMMAND, IDM_SUBAGENT_SWARM, 0, SMTO_ABORTIFHUNG, 8000, &result) ? 1 : 0;
        send_result = (DWORD)result;
        printf("SENDMESSAGETIMEOUT_WM_COMMAND_4111=%d result=%lu err=%lu\n", send_ok, send_result, GetLastError());

        // Optional: remote call member fn with this from GWLP_USERDATA
        LONG_PTR ideThis = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        printf("GWLP_USERDATA=%p\n", (void*)ideThis);
        if (base && ideThis) {
            auto fn = (LPTHREAD_START_ROUTINE)(base + RVA_ON_SWARM);
            HANDLE ht = CreateRemoteThread(pi.hProcess, nullptr, 0, fn, (LPVOID)ideThis, 0, nullptr);
            if (ht) {
                remote_ok = 1;
                WaitForSingleObject(ht, 15000);
                CloseHandle(ht);
            }
            printf("REMOTE_onSubAgentSwarm=%d err=%lu\n", remote_ok, GetLastError());
        } else {
            printf("REMOTE_onSubAgentSwarm=0 SKIP (no this/base)\n");
        }
    } else {
        printf("BLOCKER=MAIN_HWND_NOT_FOUND within 20s\n");
    }

    Sleep(3000);
    ods.stop_join();

    int ods_hit = 0;
    if (ods.captured.find("onSubAgentSwarm") != std::string::npos) ods_hit = 1;
    if (ods.captured.find("HexMag swarm") != std::string::npos) ods_hit = 1;
    if (ods.captured.find("Starting HexMag") != std::string::npos) ods_hit = 1;
    if (ods.captured.find("resolveSwarmModelOrchPlan") != std::string::npos) ods_hit = 1;
    if (ods.captured.find("FAIL_CLOSED: swarm model") != std::string::npos) ods_hit = 1;
    if (ods.captured.find("SubAgentManager not initialized") != std::string::npos) ods_hit = 1;
    if (ods.captured.find("No editor content for swarm") != std::string::npos) ods_hit = 1;

    printf("ODS_BYTES=%zu\n", ods.captured.size());
    printf("ODS_HIT_SWARM=%d\n", ods_hit);
    printf("---ODS_BEGIN---\n");
    fwrite(ods.captured.data(), 1, ods.captured.size() > 16000 ? 16000 : ods.captured.size(), stdout);
    printf("\n---ODS_END---\n");

    int invoked = (ods_hit || (hwnd && (post_ok || send_ok))) ? 1 : 0;
    // Fail-closed: PostMessage alone != product orch RUNTIME_PASS
    printf("INVOKED_CLAIM=%d (Post/Send delivered=%d ODS_hit=%d)\n", invoked, (post_ok || send_ok), ods_hit);
    printf("RUNTIME_PASS=0 (not invented; need orch+tokens evidence)\n");

    // Terminate tip (local probe only)
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("TIP_TERMINATED=1\n");
    printf("PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0\n");
    return hwnd ? 0 : 3;
}
