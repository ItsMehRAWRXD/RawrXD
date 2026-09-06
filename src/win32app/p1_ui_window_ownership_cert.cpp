// ============================================================================
// p1_ui_window_ownership_cert.cpp — P1_UI_WINDOW_OWNERSHIP_001 live product cert
// Launch RawrXD-Win32IDE, drive max/restore/min/restore, assert single shell + dock roots.
// Exit: 0 PASS, 1 FAIL
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <sstream>

static constexpr const char* kIdeClass = "RawrXD_IDE_MainWindow";
static constexpr const char* kLegacyClass = "RawrXD_Win32IDE";
static constexpr int kReadyTimeoutMs = 180000;
static constexpr int kPhaseSettleMs = 1500;

struct PaneHit {
    HWND explorer = nullptr;
    HWND editor = nullptr;
    HWND chat = nullptr;
    HWND output = nullptr;
    HWND terminal = nullptr;
    HWND status = nullptr;
};

struct PhaseResult {
    const char* name = "";
    HWND mainHwnd = nullptr;
    int productShells = 0;
    bool rootsOk = false;
    bool noPopup = false;
    bool processAlive = false;
    std::string detail;
};

static std::wstring DefaultIdeExe()
{
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring dir(self);
    const size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        dir.resize(slash + 1);
    return dir + L"RawrXD-Win32IDE.exe";
}

static bool ClassIsProduct(const char* cls)
{
    return cls && (_stricmp(cls, kIdeClass) == 0 || _stricmp(cls, kLegacyClass) == 0);
}

static int CountProductShells(DWORD pid)
{
    struct Ctx {
        DWORD pid;
        int n;
    } ctx{pid, 0};
    EnumWindows(
        [](HWND h, LPARAM lp) -> BOOL {
            auto* c = reinterpret_cast<Ctx*>(lp);
            DWORD w = 0;
            GetWindowThreadProcessId(h, &w);
            if (w != c->pid)
                return TRUE;
            char cls[128] = {};
            GetClassNameA(h, cls, 128);
            if (ClassIsProduct(cls))
                ++c->n;
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&ctx));
    return ctx.n;
}

static HWND FindMain(DWORD pid)
{
    struct Ctx {
        DWORD pid;
        HWND hwnd;
    } ctx{pid, nullptr};
    EnumWindows(
        [](HWND h, LPARAM lp) -> BOOL {
            auto* c = reinterpret_cast<Ctx*>(lp);
            DWORD w = 0;
            GetWindowThreadProcessId(h, &w);
            if (w != c->pid)
                return TRUE;
            char cls[128] = {};
            GetClassNameA(h, cls, 128);
            if (_stricmp(cls, kIdeClass) == 0) {
                c->hwnd = h;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&ctx));
    return ctx.hwnd;
}

static void Pump(DWORD ms)
{
    const auto end = GetTickCount64() + ms;
    MSG msg{};
    while (GetTickCount64() < end) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(50);
    }
}

static BOOL CALLBACK EnumChildCb(HWND hwnd, LPARAM lp)
{
    auto* panes = reinterpret_cast<PaneHit*>(lp);
    char cls[160] = {};
    char title[256] = {};
    GetClassNameA(hwnd, cls, 159);
    GetWindowTextA(hwnd, title, 255);

    if (!panes->explorer &&
        (_stricmp(cls, "SysTreeView32") == 0 || strstr(title, "Explorer") ||
         strstr(title, "RawrXD.IDE.Sidebar") || strstr(title, "Sidebar")))
        panes->explorer = hwnd;

    if (!panes->editor &&
        (_stricmp(cls, "RichEdit50W") == 0 || _stricmp(cls, "RichEdit20W") == 0 ||
         _stricmp(cls, "Scintilla") == 0 || strstr(cls, "RichEdit") ||
         strstr(title, "Monaco") || strstr(cls, "Chrome_WidgetWin")))
        panes->editor = hwnd;

    if (!panes->chat &&
        (strstr(title, "AI Chat") || strstr(title, "Copilot Chat") ||
         strstr(title, "GitHub Copilot")))
        panes->chat = hwnd;

    if (!panes->output &&
        (_stricmp(cls, "SysTabControl32") == 0 || strstr(title, "Output") ||
         strstr(title, "Problems")))
        panes->output = hwnd;

    if (!panes->terminal &&
        (strstr(title, "PowerShell") || strstr(title, "Terminal") ||
         strstr(cls, "ConsoleWindowClass")))
        panes->terminal = hwnd;

    if (!panes->status && _stricmp(cls, "msctls_statusbar32") == 0)
        panes->status = hwnd;

    EnumChildWindows(hwnd, EnumChildCb, lp);
    return TRUE;
}

static PaneHit DiscoverPanes(HWND main)
{
    PaneHit p{};
    if (main)
        EnumChildWindows(main, EnumChildCb, reinterpret_cast<LPARAM>(&p));
    // Chat hit is often the header STATIC — promote to host if parent is under main.
    if (p.chat) {
        HWND parent = GetParent(p.chat);
        if (parent && GetAncestor(parent, GA_ROOT) == main)
            p.chat = parent;
    }
    return p;
}

static bool RootEqMain(HWND pane, HWND main)
{
    if (!pane || !IsWindow(pane))
        return true; // missing optional pane: do not fail root if not created yet
    return GetAncestor(pane, GA_ROOT) == main;
}

static bool RequiredRootEqMain(HWND pane, HWND main)
{
    if (!pane || !IsWindow(pane))
        return false;
    return GetAncestor(pane, GA_ROOT) == main;
}

static bool IsDockPopup(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd))
        return false;
    const LONG_PTR style = GetWindowLongPtrA(hwnd, GWL_STYLE);
    if (style & WS_CHILD)
        return (style & WS_POPUP) != 0;
    return true; // non-child while "docked" expectation fails
}

static bool ProcessAlive(HANDLE proc)
{
    DWORD code = STILL_ACTIVE;
    if (!GetExitCodeProcess(proc, &code))
        return false;
    return code == STILL_ACTIVE;
}

static PhaseResult Evaluate(const char* name, HWND main, HANDLE proc, DWORD pid, bool requireAllPanes)
{
    PhaseResult r{};
    r.name = name;
    r.mainHwnd = main;
    r.processAlive = ProcessAlive(proc);
    r.productShells = CountProductShells(pid);

    PaneHit panes = DiscoverPanes(main);
    std::ostringstream oss;
    oss << "explorer=" << (void*)panes.explorer << " editor=" << (void*)panes.editor
        << " chat=" << (void*)panes.chat << " output=" << (void*)panes.output
        << " terminal=" << (void*)panes.terminal << " status=" << (void*)panes.status;

    const bool ex = RequiredRootEqMain(panes.explorer, main);
    const bool ed = RequiredRootEqMain(panes.editor, main);
    const bool ch = RequiredRootEqMain(panes.chat, main);
    const bool ou = RequiredRootEqMain(panes.output, main);
    const bool te = RequiredRootEqMain(panes.terminal, main);
    const bool st = RequiredRootEqMain(panes.status, main);

    if (!requireAllPanes) {
        // Soft: only assert roots for panes that exist; still require explorer+status for "ready"
        r.rootsOk = RootEqMain(panes.explorer, main) && RootEqMain(panes.editor, main) &&
                    RootEqMain(panes.chat, main) && RootEqMain(panes.output, main) &&
                    RootEqMain(panes.terminal, main) && RootEqMain(panes.status, main) &&
                    panes.explorer && panes.status;
    } else {
        r.rootsOk = ex && ed && ch && ou && te && st;
    }

    r.noPopup = !IsDockPopup(panes.chat);
    oss << " roots[E/Ed/C/O/T/S]=" << ex << ed << ch << ou << te << st
        << " popup=" << (r.noPopup ? 0 : 1);
    r.detail = oss.str();
    return r;
}

static void DumpPhase(FILE* out, const PhaseResult& r)
{
    const bool topOk = r.productShells == 1;
    std::fprintf(out, "=== phase=%s MAIN_HWND=%p ===\n", r.name, (void*)r.mainHwnd);
    std::fprintf(out, "RAWRXD_TOPLEVEL_PRODUCT_WINDOWS=%d\n", r.productShells);
    std::fprintf(out, "MAIN_TOPLEVEL_COUNT=%s\n", topOk ? "PASS" : "FAIL");
    std::fprintf(out, "NO_SECOND_PRODUCT_SHELL=%s\n", r.productShells <= 1 ? "PASS" : "FAIL");
    std::fprintf(out, "PROCESS_SURVIVES=%s\n", r.processAlive ? "PASS" : "FAIL");
    std::fprintf(out, "NO_DOCK_PANE_WS_POPUP=%s\n", r.noPopup ? "PASS" : "FAIL");
    std::fprintf(out, "DETAIL %s\n", r.detail.c_str());

    PaneHit panes = DiscoverPanes(r.mainHwnd);
    auto line = [&](const char* n, HWND h) {
        const bool ok = RequiredRootEqMain(h, r.mainHwnd);
        std::fprintf(out, "%s_ROOT_EQ_MAIN=%s hwnd=%p root=%p\n", n, ok ? "PASS" : "FAIL",
                     (void*)h, h ? (void*)GetAncestor(h, GA_ROOT) : nullptr);
    };
    line("EXPLORER", panes.explorer);
    line("EDITOR", panes.editor);
    line("CHAT", panes.chat);
    line("OUTPUT", panes.output);
    line("TERMINAL", panes.terminal);
    line("STATUS", panes.status);
    std::fflush(out);
}

static bool PhasePass(const PhaseResult& r, bool requireAllPanes)
{
    if (!r.processAlive || r.productShells != 1 || !r.mainHwnd)
        return false;
    if (!r.noPopup)
        return false;
    if (requireAllPanes && !r.rootsOk)
        return false;
    if (!requireAllPanes && !r.rootsOk)
        return false;
    return true;
}

static bool StaticImageAudit(const std::wstring& ideExe, FILE* out, bool* forceMultiplePresent,
                             bool* windowCppCompiled)
{
    *forceMultiplePresent = false;
    *windowCppCompiled = false;

    // Map next to exe
    std::wstring mapPath = ideExe;
    const size_t slash = mapPath.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        mapPath.resize(slash + 1);
    mapPath += L"RawrXD-Win32IDE.map";

    std::ifstream map(std::string(mapPath.begin(), mapPath.end()), std::ios::binary);
    if (!map) {
        // try build-ninja relative known path via env
        const char* overrideMap = std::getenv("RAWRXD_IDE_MAP");
        if (overrideMap)
            map.open(overrideMap, std::ios::binary);
    }
    if (!map) {
        std::fprintf(out, "MAP_AUDIT=FAIL (map not found)\n");
        return false;
    }
    std::stringstream ss;
    ss << map.rdbuf();
    const std::string content = ss.str();
    *windowCppCompiled = content.find("Win32IDE_Window.cpp.obj") != std::string::npos;

    const char* ninja = std::getenv("RAWRXD_BUILD_NINJA");
    std::string ninjaPath = ninja ? ninja : "";
    if (ninjaPath.empty()) {
        // sibling ../build.ninja unlikely; try env default
        ninjaPath = "F:/~dev/rawrxd/build-ninja/build.ninja";
    }
    std::ifstream bn(ninjaPath, std::ios::binary);
    if (bn) {
        std::stringstream ns;
        ns << bn.rdbuf();
        const std::string n = ns.str();
        *forceMultiplePresent = n.find("/FORCE:MULTIPLE") != std::string::npos;
    }

    std::fprintf(out, "DUPLICATE_WINDOW_IMPL_COMPILED=%s\n", *windowCppCompiled ? "YES" : "NO");
    std::fprintf(out, "FORCE_MULTIPLE_IN_LINK=%s\n", *forceMultiplePresent ? "YES" : "NO");
    std::fprintf(out, "FORCE_MULTIPLE_REQUIRED=%s\n",
                 *forceMultiplePresent ? "FAIL_STILL_PRESENT" : "NO");
    return true;
}

int main(int argc, char** argv)
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_UI_WINDOW_OWNERSHIP_001 LIVE CERT ===\n");

    std::wstring ideExe = DefaultIdeExe();
    if (argc >= 2) {
        int n = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, nullptr, 0);
        ideExe.assign((size_t)n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, ideExe.data(), n);
        if (!ideExe.empty() && ideExe.back() == L'\0')
            ideExe.pop_back();
    }

    const char* evidenceDir = std::getenv("RAWRXD_OWNERSHIP_EVIDENCE");
    std::string evidence =
        evidenceDir ? evidenceDir : "F:/~dev/rawrxd/evidence/P1_UI_WINDOW_OWNERSHIP_001";
    CreateDirectoryA(evidence.c_str(), nullptr);
    const std::string runLog = evidence + "/run.log";
    const std::string dumpLog = evidence + "/ownership_dumps.txt";
    FILE* dump = nullptr;
    fopen_s(&dump, dumpLog.c_str(), "w");
    if (!dump)
        dump = stdout;

    bool forcePresent = false;
    bool windowCompiled = false;
    StaticImageAudit(ideExe, dump, &forcePresent, &windowCompiled);
    std::printf("DUPLICATE_WINDOW_IMPL_COMPILED=%s\n", windowCompiled ? "YES" : "NO");
    std::printf("FORCE_MULTIPLE_IN_LINK=%s\n", forcePresent ? "YES" : "NO");

    // Kill stale IDE instances for this image path (best-effort)
    // Launch
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + ideExe + L"\"";
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    wchar_t workDir[MAX_PATH] = {};
    wcsncpy_s(workDir, ideExe.c_str(), _TRUNCATE);
    wchar_t* slash = wcsrchr(workDir, L'\\');
    if (slash)
        *slash = 0;

    SetEnvironmentVariableA("RAWRXD_P1_UI_WINDOW_OWNERSHIP", "1");

    if (!CreateProcessW(ideExe.c_str(), cmdBuf.data(), nullptr, nullptr, FALSE, 0, nullptr,
                        workDir, &si, &pi)) {
        std::printf("FAIL CreateProcess err=%lu\n", GetLastError());
        if (dump && dump != stdout)
            fclose(dump);
        return 1;
    }

    HWND main = nullptr;
    PhaseResult afterChildren{};
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kReadyTimeoutMs);

    // 1-3: launch + wait full UI + dump
    while (std::chrono::steady_clock::now() < deadline) {
        if (!ProcessAlive(pi.hProcess)) {
            std::printf("FAIL process died during ready wait\n");
            break;
        }
        main = FindMain(pi.dwProcessId);
        if (main) {
            afterChildren = Evaluate("AFTER_CHILDREN", main, pi.hProcess, pi.dwProcessId, true);
            if (PhasePass(afterChildren, true))
                break;
            // tolerate partial for a while — require shells==1 always once main exists
            if (afterChildren.productShells != 1) {
                DumpPhase(dump, afterChildren);
                std::printf("FAIL early TOPLEVEL_COUNT=%d\n", afterChildren.productShells);
                break;
            }
        }
        Pump(400);
    }

    HWND hwndAtCreate = main;
    DumpPhase(dump, afterChildren);
    std::printf("MAIN_HWND_AT_CREATE=%p\n", (void*)hwndAtCreate);
    std::printf("MAIN_HWND_AFTER_CHILDREN=%p\n", (void*)afterChildren.mainHwnd);

    auto failClose = [&](int code) {
        if (main && IsWindow(main))
            PostMessageW(main, WM_CLOSE, 0, 0);
        WaitForSingleObject(pi.hProcess, 15000);
        if (ProcessAlive(pi.hProcess))
            TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (dump && dump != stdout)
            fclose(dump);
        return code;
    };

    if (!PhasePass(afterChildren, true)) {
        std::printf("FAIL ready/ownership after children (%s)\n", afterChildren.detail.c_str());
        // Still try soft pass path: if shells==1 but panes missing, report FAIL with localization
        return failClose(1);
    }

    // 4-5 maximize
    ShowWindow(main, SW_SHOWMAXIMIZED);
    Pump(kPhaseSettleMs);
    main = FindMain(pi.dwProcessId);
    PhaseResult maximized = Evaluate("SIZE_MAXIMIZED", main, pi.hProcess, pi.dwProcessId, true);
    DumpPhase(dump, maximized);
    std::printf("MAIN_HWND_MAXIMIZED=%p\n", (void*)maximized.mainHwnd);

    // 6-7 restore
    ShowWindow(main, SW_RESTORE);
    Pump(kPhaseSettleMs);
    main = FindMain(pi.dwProcessId);
    PhaseResult restored = Evaluate("SIZE_RESTORED", main, pi.hProcess, pi.dwProcessId, true);
    DumpPhase(dump, restored);
    std::printf("MAIN_HWND_RESTORED=%p\n", (void*)restored.mainHwnd);

    // 8-10 minimize + restore
    ShowWindow(main, SW_MINIMIZE);
    Pump(800);
    ShowWindow(main, SW_RESTORE);
    Pump(kPhaseSettleMs);
    main = FindMain(pi.dwProcessId);
    PhaseResult afterMin = Evaluate("AFTER_MINIMIZE_RESTORE", main, pi.hProcess, pi.dwProcessId, true);
    DumpPhase(dump, afterMin);
    std::printf("MAIN_HWND_AFTER_MINIMIZE_RESTORE=%p\n", (void*)afterMin.mainHwnd);

    // 11 close
    PostMessageW(main, WM_CLOSE, 0, 0);
    const DWORD wait = WaitForSingleObject(pi.hProcess, 30000);
    const bool closedClean = (wait == WAIT_OBJECT_0);
    if (!closedClean)
        TerminateProcess(pi.hProcess, 1);

    const bool hwndStable =
        hwndAtCreate && hwndAtCreate == afterChildren.mainHwnd &&
        hwndAtCreate == maximized.mainHwnd && hwndAtCreate == restored.mainHwnd &&
        hwndAtCreate == afterMin.mainHwnd;

    const bool runtimeOk = PhasePass(afterChildren, true) && PhasePass(maximized, true) &&
                           PhasePass(restored, true) && PhasePass(afterMin, true) && hwndStable;

    const bool staticOk = !windowCompiled && !forcePresent;
    // Clean close is recorded but does not exonerate ownership; hang-on-exit is separate.
    const bool pass = runtimeOk && staticOk;

    std::fprintf(dump, "\nMAIN_HWND_AT_CREATE=%p\n", (void*)hwndAtCreate);
    std::fprintf(dump, "MAIN_HWND_AFTER_CHILDREN=%p\n", (void*)afterChildren.mainHwnd);
    std::fprintf(dump, "MAIN_HWND_MAXIMIZED=%p\n", (void*)maximized.mainHwnd);
    std::fprintf(dump, "MAIN_HWND_RESTORED=%p\n", (void*)restored.mainHwnd);
    std::fprintf(dump, "MAIN_HWND_AFTER_MINIMIZE_RESTORE=%p\n", (void*)afterMin.mainHwnd);
    std::fprintf(dump, "MAIN_HWND_STABLE=%s\n", hwndStable ? "PASS" : "FAIL");
    std::fprintf(dump, "CLOSE_NORMALLY=%s\n", closedClean ? "PASS" : "FAIL");
    std::fprintf(dump, "RUNTIME_OWNERSHIP=%s\n", runtimeOk ? "PASS" : "FAIL");
    std::fprintf(dump, "STATIC_IMAGE=%s\n", staticOk ? "PASS" : "FAIL");
    std::fprintf(dump, "P1_UI_WINDOW_OWNERSHIP_001=%s\n", pass ? "PASS" : "FAIL");

    std::printf("MAIN_HWND_STABLE=%s\n", hwndStable ? "PASS" : "FAIL");
    std::printf("CLOSE_NORMALLY=%s\n", closedClean ? "PASS" : "FAIL");
    std::printf("RUNTIME_OWNERSHIP=%s\n", runtimeOk ? "PASS" : "FAIL");
    std::printf("STATIC_IMAGE=%s (dupWindow=%d force=%d)\n", staticOk ? "PASS" : "FAIL",
                (int)windowCompiled, (int)forcePresent);
    std::printf("P1_UI_WINDOW_OWNERSHIP_001=%s\n", pass ? "PASS" : "FAIL");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (dump && dump != stdout)
        fclose(dump);
    return pass ? 0 : 1;
}
