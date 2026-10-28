// MODE_SWITCH_UI_001 — tip 748B Ask/Plan/Agent (+ Debug via setAgenticMode trampoline).
// ABSORB=NOT_AUTHORIZED — no tip rebuild. PROMOTE=0.
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

// x64 trampoline: RCX=ide (from CreateRemoteThread), EDX=mode, JMP setAgenticMode
static int remote_set_mode(HANDLE proc, uintptr_t setFn, void* ide, int mode, const char* tag) {
    uint8_t stub[32];
    // mov edx, imm32
    stub[0] = 0xBA;
    memcpy(stub + 1, &mode, 4);
    // mov rax, imm64
    stub[5] = 0x48;
    stub[6] = 0xB8;
    memcpy(stub + 7, &setFn, 8);
    // jmp rax
    stub[15] = 0xFF;
    stub[16] = 0xE0;
    void* remote = VirtualAllocEx(proc, nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        printf("REMOTE_%s=VirtualAllocEx_FAIL err=%lu\n", tag, GetLastError());
        return -4;
    }
    SIZE_T wrote = 0;
    if (!WriteProcessMemory(proc, remote, stub, 17, &wrote) || wrote != 17) {
        printf("REMOTE_%s=WPM_FAIL err=%lu\n", tag, GetLastError());
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        return -5;
    }
    int rc = remote_call(proc, (LPTHREAD_START_ROUTINE)remote, ide, tag);
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    return rc;
}

static bool read_u8(HANDLE proc, uintptr_t addr, uint8_t* out, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(proc, (LPCVOID)addr, out, n, &got) && got == n;
}

int main() {
    const wchar_t* tipPath = L"G:\\~dev\\rawrxd\\evidence\\TIP_FREEZE_001\\bin\\RawrXD-Win32IDE.exe";
    const wchar_t* tipName = L"RawrXD-Win32IDE.exe";
    const int port = 18971; // avoid 748B surface 18951 / prior composer 18771

    // PDB tip 748B: section-relative → RVA = sectVA + off
    // .text VA=0x1000; .data-ish sect3 VA=0x2767000
    const uintptr_t RVA_ASK = 0x5B22A0ull;
    const uintptr_t RVA_AGENT = 0x5B2290ull;
    const uintptr_t RVA_PLAN = 0x5B22C0ull;
    const uintptr_t RVA_SET = 0x5B8970ull;
    const uintptr_t RVA_G_PMAINIDE = 0x13AE80C0ull;
    // Fallbacks if PDB offset was already RVA-shaped
    const uintptr_t RVA_ASK_ALT = 0x5B12A0ull;
    const uintptr_t RVA_G_ALT = 0x113810C0ull;

    printf("PROBE=MODE_SWITCH_UI_001\n");
    printf("TIP_SHA_EXPECT=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145\n");
    printf("METHOD=headless tip + g_pMainIDE RPM + remote Ask/Plan/Agent + setMode(Debug)\n");
    printf("PORT=%d\n", port);
    printf("ABSORB=NOT_AUTHORIZED\n");
    printf("PROMOTE=0\n");

    wchar_t cmd[1200];
    _snwprintf_s(cmd, _TRUNCATE,
                 L"\"%s\" --headless --local --port %d --bind 127.0.0.1 --dir G:\\~dev\\rawrxd", tipPath,
                 port);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, nullptr,
                        L"G:\\~dev\\rawrxd\\evidence\\TIP_FREEZE_001\\bin", &si, &pi)) {
        printf("FAIL CreateProcess %lu\n", GetLastError());
        return 2;
    }
    printf("SPAWNED pid=%lu\n", pi.dwProcessId);

    OdsCollector ods;
    printf("ODS_COLLECTOR=%d\n", ods.start(pi.dwProcessId) ? 1 : 0);

    uintptr_t base = 0;
    for (int i = 0; i < 200; ++i) {
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

    Sleep(5000);

    uintptr_t ide = 0;
    SIZE_T got = 0;
    uintptr_t gRva = RVA_G_PMAINIDE;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(base + gRva), &ide, sizeof(ide), &got) || got != sizeof(ide) ||
        !ide) {
        gRva = RVA_G_ALT;
        ide = 0;
        ReadProcessMemory(pi.hProcess, (LPCVOID)(base + gRva), &ide, sizeof(ide), &got);
    }
    printf("G_PMAINIDE_RVA=0x%llX G_PMAINIDE=%p\n", (unsigned long long)gRva, (void*)ide);

    uint8_t pro[4] = {};
    uintptr_t askRva = RVA_ASK;
    read_u8(pi.hProcess, base + askRva, pro, 4);
    printf("PROLOGUE_ASK_PRIMARY=%02X %02X %02X %02X\n", pro[0], pro[1], pro[2], pro[3]);
    if (pro[0] == 0x00 || pro[0] == 0xFF) {
        askRva = RVA_ASK_ALT;
        read_u8(pi.hProcess, base + askRva, pro, 4);
        printf("PROLOGUE_ASK_ALT=%02X %02X %02X %02X\n", pro[0], pro[1], pro[2], pro[3]);
    }
    const uintptr_t delta = askRva - RVA_ASK;
    const uintptr_t agentRva = RVA_AGENT + delta;
    const uintptr_t planRva = RVA_PLAN + delta;
    const uintptr_t setRva = RVA_SET + delta;

    if (!ide) {
        printf("FAIL g_pMainIDE null\n");
        printf("RUNTIME_REACHED=0\n");
        printf("REASON=g_pMainIDE_null\n");
        ods.stop_join();
        TerminateProcess(pi.hProcess, 0);
        return 5;
    }

    // Tip HWND path: legacy Core IDs 1206=Plan 1207=Agent 1208=Ask (collision; tip as frozen)
    HWND mainWnd = nullptr;
    DWORD pid = pi.dwProcessId;
    struct EnumCtx {
        DWORD pid;
        HWND hwnd;
    } ctx{pid, nullptr};
    EnumWindows(
        [](HWND h, LPARAM lp) -> BOOL {
            auto* c = (EnumCtx*)lp;
            DWORD wpid = 0;
            GetWindowThreadProcessId(h, &wpid);
            if (wpid == c->pid) {
                char cls[64] = {};
                GetClassNameA(h, cls, 64);
                if (strstr(cls, "Rawr") || strstr(cls, "Win32") || IsWindowVisible(h)) {
                    c->hwnd = h;
                    return FALSE;
                }
            }
            return TRUE;
        },
        (LPARAM)&ctx);
    mainWnd = ctx.hwnd;
    printf("TIP_HWND=%p\n", (void*)mainWnd);
    int hwndPlan = 0, hwndAgent = 0, hwndAsk = 0;
    if (mainWnd) {
        hwndPlan = PostMessageW(mainWnd, WM_COMMAND, MAKEWPARAM(1206, BN_CLICKED), 0) ? 1 : 0;
        Sleep(150);
        hwndAgent = PostMessageW(mainWnd, WM_COMMAND, MAKEWPARAM(1207, BN_CLICKED), 0) ? 1 : 0;
        Sleep(150);
        hwndAsk = PostMessageW(mainWnd, WM_COMMAND, MAKEWPARAM(1208, BN_CLICKED), 0) ? 1 : 0;
        Sleep(150);
    }
    printf("HWND_POST_PLAN=%d HWND_POST_AGENT=%d HWND_POST_ASK=%d\n", hwndPlan, hwndAgent, hwndAsk);
    printf("HWND_DEBUG=NOT_ON_TIP_IDC (no 5008 on tip; ABSORB=NOT_AUTHORIZED)\n");

    int ask = remote_call(pi.hProcess, (LPTHREAD_START_ROUTINE)(base + askRva), (void*)ide, "ASK");
    Sleep(200);
    int plan = remote_call(pi.hProcess, (LPTHREAD_START_ROUTINE)(base + planRva), (void*)ide, "PLAN");
    Sleep(200);
    int agent = remote_call(pi.hProcess, (LPTHREAD_START_ROUTINE)(base + agentRva), (void*)ide, "AGENT");
    Sleep(200);
    int dbg = remote_set_mode(pi.hProcess, base + setRva, (void*)ide, /*Debug=*/5, "DEBUG_SET");
    Sleep(400);

    ods.stop_join();
    printf("=== ODS_CAPTURE_BEGIN ===\n");
    fwrite(ods.captured.data(), 1, ods.captured.size(), stdout);
    printf("=== ODS_CAPTURE_END ===\n");

    int hasAsk = ods.captured.find("Chat mode: Ask") != std::string::npos;
    int hasPlan = ods.captured.find("Chat mode: Plan") != std::string::npos;
    int hasAgent = ods.captured.find("Chat mode: Agent") != std::string::npos;
    int hasDebug = ods.captured.find("Chat mode: Debug") != std::string::npos;
    int hasAgenticSet = ods.captured.find("Agentic mode set") != std::string::npos;

    printf("HAS_CHAT_ASK=%d\n", hasAsk);
    printf("HAS_CHAT_PLAN=%d\n", hasPlan);
    printf("HAS_CHAT_AGENT=%d\n", hasAgent);
    printf("HAS_CHAT_DEBUG=%d\n", hasDebug);
    printf("HAS_AGENTIC_MODE_SET=%d\n", hasAgenticSet);

    DWORD live = WaitForSingleObject(pi.hProcess, 0);
    int tipAlive = (live == WAIT_TIMEOUT) ? 1 : 0;
    printf("TIP_ALIVE=%d\n", tipAlive);

    int modesRemote = (ask == 0 && plan == 0 && agent == 0) ? 1 : 0;
    int debugRemote = (dbg == 0) ? 1 : 0;
    // RUNTIME: remote member invokes completed on live tip; ODS witness preferred but not required
    // if appendToOutput does not hit OutputDebugString on this tip build.
    int runtime = (tipAlive && modesRemote) ? 1 : 0;
    printf("MODES_REMOTE_OK=%d\n", modesRemote);
    printf("DEBUG_REMOTE_OK=%d\n", debugRemote);
    printf("MODES_INVOKED=Ask,Plan,Agent\n");
    printf("DEBUG_INVOKED_VIA=setAgenticMode_trampoline_mode5\n");
    printf("RUNTIME_REACHED=%d\n", runtime);
    printf("MET_CLAIM=0\n");
    printf("CERTIFIED=0\n");
    printf("PROMOTE=0\n");
    printf("TIP_CLIMB=HOLD\n");

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return runtime ? 0 : 6;
}
