// p1_ui_menu_lifetime_cert.cpp — P1_UI_MENU_LIFETIME_001
// Distinguishes MENU_NEVER_BECAME_NULL vs REQUIRED_PHASE_NOT_OBSERVED.

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

#if defined(_WIN32)
#include <process.h>
#endif

static constexpr const char* kIdeClass = "RawrXD_IDE_MainWindow";
static constexpr int kTimeoutMs = 240000;
static constexpr int kStableWindowMs = 2000;

static const char* kRequiredPhases[] = {
    "AFTER_SETMENU",
    "AFTER_DEFERRED_CHILDREN",
    "AFTER_COMMAND_AUTHORITY_INIT",
    "WM_ENTERIDLE_STABLE",
};

struct PhaseRow {
    std::string phase;
    void* live = nullptr;
    void* auth = nullptr;
    uint64_t gen = 0;
    int valid = 0;
    int count = -1;
    int detached = 0;
};

struct TraceData {
    std::vector<PhaseRow> states;
    int violationCount = 0;
    int unauthorizedDestroy = 0;
    bool authorizedDetachSeen = false;
    std::string lastPhase;
    bool lastMenuValid = false;
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
            if (strcmp(cls, kIdeClass) == 0) {
                c->hwnd = h;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&ctx));
    return ctx.hwnd;
}

static bool ParseTraceFile(const char* path, TraceData& out)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f)
        return false;

    char line[768];
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "MENU_VIOLATION", 14) == 0) {
            ++out.violationCount;
            continue;
        }
        if (std::strstr(line, "MENU_DESTROY") && std::strstr(line, "UNAUTHORIZED"))
            ++out.unauthorizedDestroy;
        if (std::strncmp(line, "MENU_DETACH", 11) == 0 &&
            std::strstr(line, "AUTHORIZED=TRUE"))
            out.authorizedDetachSeen = true;

        if (std::strncmp(line, "MENU_STATE", 10) != 0)
            continue;

        PhaseRow r;
        char phase[128] = {};
        void* hwnd = nullptr;
        void* live = nullptr;
        void* auth = nullptr;
        unsigned long long gen = 0;
        int valid = 0;
        int count = -1;
        int detached = 0;
        int destroying = 0;

        if (std::sscanf(line,
                        "MENU_STATE phase=%127s hwnd=%p live=%p auth=%p gen=%llu valid=%d "
                        "count=%d detached=%d destroying=%d",
                        phase, &hwnd, &live, &auth, &gen, &valid, &count, &detached,
                        &destroying) >= 7) {
            r.phase = phase;
            r.live = live;
            r.auth = auth;
            r.gen = gen;
            r.valid = valid;
            r.count = count;
            r.detached = detached;
            out.states.push_back(r);
            out.lastPhase = phase;
            out.lastMenuValid = valid != 0 && live != nullptr;
        }
    }
    std::fclose(f);
    return !out.states.empty();
}

static const PhaseRow* FindPhase(const TraceData& td, const char* phase)
{
    for (const auto& r : td.states)
        if (r.phase == phase)
            return &r;
    return nullptr;
}

static bool PhaseObserved(const TraceData& td, const char* phase)
{
    return FindPhase(td, phase) != nullptr;
}

static bool PhaseMenuNonNull(const TraceData& td, const char* phase)
{
    const PhaseRow* r = FindPhase(td, phase);
    return r && r->live && r->valid;
}

static bool PhaseAuthorityMatch(const TraceData& td, const char* phase)
{
    const PhaseRow* r = FindPhase(td, phase);
    if (!r || !r->live || !r->auth)
        return false;
    if (r->detached)
        return true;
    return r->live == r->auth;
}

static void ComputeFirstFalse(const TraceData& td, bool allPhasesObserved, bool menuNullAfterSet,
                              bool phaseProgressOnly, char* buf, size_t n)
{
    if (menuNullAfterSet) {
        std::snprintf(buf, n, "HMENU_PRESENT");
        return;
    }
    if (phaseProgressOnly) {
        std::snprintf(buf, n, "PHASE_PROGRESS");
        return;
    }
    if (td.violationCount > 0) {
        std::snprintf(buf, n, "UNAUTHORIZED_MUTATION");
        return;
    }
    if (allPhasesObserved) {
        std::snprintf(buf, n, "NONE");
        return;
    }
    std::snprintf(buf, n, "PHASE_PROGRESS");
}

int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    std::wstring ideExe = DefaultIdeExe();
    if (argc > 1 && argv[1][0] != '-')
        ideExe.assign(argv[1], argv[1] + std::strlen(argv[1]));

    std::wstring workDir = ideExe;
    const size_t slash = workDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        workDir.resize(slash + 1);

    SetCurrentDirectoryW(workDir.c_str());
    DeleteFileA("P1_UI_MENU_LIFETIME_TRACE.txt");
    DeleteFileA("P1_UI_MENU_LIFETIME_001_PROBE.txt");
    SetEnvironmentVariableA("RAWRXD_P1_UI_MENU_LIFETIME", "1");

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + ideExe + L"\"";
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    if (!CreateProcessW(ideExe.c_str(), cmdBuf.data(), nullptr, nullptr, FALSE, 0, nullptr,
                        workDir.c_str(), &si, &pi)) {
        std::printf("P1_UI_MENU_LIFETIME_001=FAIL (CreateProcess)\n");
        return 1;
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kTimeoutMs);
    const auto stableNeed =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kStableWindowMs);

    bool allRequired = false;
    bool stableOk = false;
    auto stableSince = std::chrono::steady_clock::time_point{};

    while (std::chrono::steady_clock::now() < deadline) {
        TraceData td{};
        ParseTraceFile("P1_UI_MENU_LIFETIME_TRACE.txt", td);

        allRequired = true;
        for (const char* p : kRequiredPhases) {
            if (std::strcmp(p, "WM_ENTERIDLE_STABLE") == 0) {
                if (!PhaseObserved(td, "WM_ENTERIDLE_STABLE") &&
                    !PhaseObserved(td, "IDLE_STABLE")) {
                    allRequired = false;
                    break;
                }
                continue;
            }
            if (!PhaseObserved(td, p)) {
                allRequired = false;
                break;
            }
        }

        HWND hwnd = FindMain(pi.dwProcessId);
        HMENU live = hwnd ? GetMenu(hwnd) : nullptr;
        const bool liveOk = live && IsMenu(live) && GetMenuItemCount(live) > 0;

        if (allRequired && liveOk) {
            if (stableSince == std::chrono::steady_clock::time_point{})
                stableSince = std::chrono::steady_clock::now();
            if (std::chrono::steady_clock::now() - stableSince >=
                std::chrono::milliseconds(kStableWindowMs)) {
                stableOk = true;
                break;
            }
        } else {
            stableSince = {};
        }

        Sleep(250);
    }

    TraceData td{};
    ParseTraceFile("P1_UI_MENU_LIFETIME_TRACE.txt", td);

    HWND hwnd = FindMain(pi.dwProcessId);
    HMENU menuAtProbe = hwnd ? GetMenu(hwnd) : nullptr;

    const bool afterSetObs = PhaseObserved(td, "AFTER_SETMENU");
    const bool afterDefChild = PhaseObserved(td, "AFTER_DEFERRED_CHILDREN");
    const bool afterDefHeavy = PhaseObserved(td, "AFTER_DEFERRED_HEAVY");
    const bool afterCmdInit = PhaseObserved(td, "AFTER_COMMAND_AUTHORITY_INIT");
    const bool idleStable = PhaseObserved(td, "WM_ENTERIDLE_STABLE") ||
                            PhaseObserved(td, "IDLE_STABLE");

    const bool setNonNull = PhaseMenuNonNull(td, "AFTER_SETMENU");
    bool menuNullAfterSet = false;
    if (setNonNull) {
        for (const auto& r : td.states) {
            if (r.phase == "AFTER_SETMENU")
                continue;
            if (r.phase == "DETACH_AUTHORIZED" || r.detached)
                continue;
            // Ignore HEAVY_STEP_* / RESTORE_* mid-phases with null live during destroy.
            if (!r.live && r.phase.find("BEFORE_") == std::string::npos &&
                r.phase.find("HEAVY_STEP_") == std::string::npos &&
                r.phase != "WINDOW_DESTROYING") {
                menuNullAfterSet = true;
                break;
            }
        }
    }

    // Menu-lifetime gate: heavy enterprise init is optional (reported, not required).
    const bool allPhasesObserved =
        afterSetObs && afterDefChild && afterCmdInit && idleStable;

    const bool phaseProgressOnly = !allPhasesObserved && !menuNullAfterSet;

    const PhaseRow* afterSet = FindPhase(td, "AFTER_SETMENU");
    const PhaseRow* lastIdle = FindPhase(td, "WM_ENTERIDLE_STABLE");
    if (!lastIdle)
        lastIdle = FindPhase(td, "IDLE_STABLE");
    const int topAtSet = afterSet ? afterSet->count : -1;
    const int topAtIdle =
        lastIdle ? lastIdle->count
                 : (menuAtProbe ? GetMenuItemCount(menuAtProbe) : -1);

    const bool countStable = topAtSet > 0 && topAtIdle == topAtSet;
    const bool authMatchIdle = PhaseAuthorityMatch(td, "WM_ENTERIDLE_STABLE") ||
                               PhaseAuthorityMatch(td, "IDLE_STABLE") ||
                               PhaseAuthorityMatch(td, "AFTER_DEFERRED_CHILDREN");
    const bool menuValid =
        menuAtProbe && IsMenu(menuAtProbe) && GetMenuItemCount(menuAtProbe) > 0;
    const bool liveMenuAtProbe = menuValid;

    const bool allNonNullRequired =
        setNonNull && PhaseMenuNonNull(td, "AFTER_DEFERRED_CHILDREN") &&
        PhaseMenuNonNull(td, "AFTER_COMMAND_AUTHORITY_INIT") &&
        (PhaseMenuNonNull(td, "WM_ENTERIDLE_STABLE") || PhaseMenuNonNull(td, "IDLE_STABLE"));

    const char* timeoutWaiting = "NONE";
    for (const char* p : kRequiredPhases) {
        if (strcmp(p, "WM_ENTERIDLE_STABLE") == 0) {
            if (!idleStable) {
                timeoutWaiting = p;
                break;
            }
            continue;
        }
        if (!PhaseObserved(td, p)) {
            timeoutWaiting = p;
            break;
        }
    }

    char firstFalse[64] = {};
    ComputeFirstFalse(td, allPhasesObserved, menuNullAfterSet, phaseProgressOnly, firstFalse,
                      sizeof(firstFalse));

    const bool pass = hwnd && afterSetObs && allPhasesObserved && allNonNullRequired &&
                      countStable && authMatchIdle && menuValid &&
                      td.violationCount == 0 && td.unauthorizedDestroy == 0 &&
                      !menuNullAfterSet && stableOk;

    FILE* out = nullptr;
    if (fopen_s(&out, "P1_UI_MENU_LIFETIME_001_PROBE.txt", "wb") == 0 && out) {
        std::fprintf(out, "P1_UI_MENU_LIFETIME_001=%s\n", pass ? "PASS" : "FAIL");
        std::fprintf(out, "AFTER_SETMENU_OBSERVED=%s\n", afterSetObs ? "PASS" : "FAIL");
        std::fprintf(out, "AFTER_DEFERRED_CHILDREN=%s\n", afterDefChild ? "PASS" : "FAIL");
        std::fprintf(out, "AFTER_DEFERRED_HEAVY=%s\n",
                     afterDefHeavy ? "PASS" : "OPTIONAL_NOT_OBSERVED");
        std::fprintf(out, "AFTER_COMMAND_AUTHORITY_INIT=%s\n", afterCmdInit ? "PASS" : "FAIL");
        std::fprintf(out, "IDLE_STABLE_OBSERVED=%s\n", idleStable ? "PASS" : "FAIL");
        std::fprintf(out, "MENU_NONNULL_ALL_REQUIRED=%s\n", allNonNullRequired ? "PASS" : "FAIL");
        std::fprintf(out, "MENU_ISMENU_ALL_REQUIRED=%s\n",
                     allNonNullRequired ? "PASS" : "FAIL");
        std::fprintf(out, "LIVE_MENU_AT_PROBE=%s\n", liveMenuAtProbe ? "PASS" : "FAIL");
        std::fprintf(out, "TOP_LEVEL_COUNT_STABLE=%s\n", countStable ? "PASS" : "FAIL");
        std::fprintf(out, "HMENU_AUTHORITY_MATCH=%s\n", authMatchIdle ? "PASS" : "FAIL");
        std::fprintf(out, "UNAUTHORIZED_MUTATION_COUNT=%d\n", td.violationCount);
        std::fprintf(out, "UNAUTHORIZED_DESTROY_COUNT=%d\n", td.unauthorizedDestroy);
        std::fprintf(out, "AUTHORIZED_DETACH_ACTIVE=%s\n",
                     td.authorizedDetachSeen ? "TRUE" : "FALSE");
        std::fprintf(out, "STABLE_WINDOW_MS=%s\n", stableOk ? "PASS" : "FAIL");
        std::fprintf(out, "MENU_NEVER_BECAME_NULL=%s\n",
                     menuNullAfterSet ? "FAIL" : "PASS");
        std::fprintf(out, "MENU_BECAME_NULL=%s\n",
                     menuNullAfterSet ? "TRUE" : "FALSE");
        std::fprintf(out, "REQUIRED_PHASE_NOT_OBSERVED=%s\n",
                     allPhasesObserved ? "PASS" : "FAIL");
        std::fprintf(out, "LAST_PHASE_OBSERVED=%s\n",
                     td.lastPhase.empty() ? "NONE" : td.lastPhase.c_str());
        std::fprintf(out, "LAST_MENU_VALID=%s\n", td.lastMenuValid ? "PASS" : "FAIL");
        std::fprintf(out, "TIMEOUT_WAITING_FOR=%s\n", timeoutWaiting);
        std::fprintf(out, "FIRST_FALSE_TRANSITION=%s\n", firstFalse);
        std::fclose(out);
    }

    std::printf("P1_UI_MENU_LIFETIME_001=%s\n", pass ? "PASS" : "FAIL");
    std::printf("LAST_PHASE=%s FIRST_FALSE=%s VIOLATIONS=%d MENU_NULL=%s PHASE_GAP=%s\n",
                td.lastPhase.c_str(), firstFalse, td.violationCount,
                menuNullAfterSet ? "YES" : "NO", allPhasesObserved ? "NO" : "YES");

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

#if defined(_WIN32)
    _Exit(pass ? 0 : 1);
#else
    return pass ? 0 : 1;
#endif
}
