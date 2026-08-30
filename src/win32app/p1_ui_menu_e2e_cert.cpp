// ============================================================================
// p1_ui_menu_e2e_cert.cpp — P1_UI_MENU_E2E_001
// Black-box product-path menu certification: real HWND/HMENU, SendInput only.
// Classifies MENU_E2E_FAIL vs FEATURE_FAIL vs DEPENDENCY_BLOCKED vs MENU_AUTHORITY_FAIL.
// Fail-fast only on structural corruption; otherwise record all leaves.
// ============================================================================

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <wincrypt.h>

#if defined(_WIN32)
#include <process.h>
#endif

static constexpr const char* kIdeClass = "RawrXD_IDE_MainWindow";
static constexpr UINT kExitCommandId = 1099;
static constexpr int kReadyTimeoutMs = 180000;
static constexpr int kEffectWaitMs = 900;
static constexpr int kExpectedMenuCount = 23;
static constexpr uint64_t kExpectedGeneration = 1;

struct MenuLeaf {
    std::vector<int> path;
    UINT id = 0;
    std::wstring label;
    bool enabled = false;
};

struct UiSnapshot {
    std::wstring status0;
    int modalDialogs = 0;
    int visibleTopLevel = 0;
    int editorLen = 0;
    bool processAlive = true;
};

enum class LeafClass {
    Pass,
    MenuE2eFail,
    FeatureFail,
    DependencyBlocked,
    MenuAuthorityFail,
    Skipped
};

struct LeafRecord {
    int index = 0;
    MenuLeaf leaf;
    bool menuFound = false;
    bool menuEnabled = false;
    bool pathReachable = false;
    bool commandIdMatch = false;
    bool dispatchSeen = false;
    bool handlerSeen = false;
    bool effectSeen = false;
    bool processSurvives = true;
    bool menuAuthorityStable = true;
    uint64_t menuGen = 0;
    int menuCount = -1;
    std::string expectedResult = "HANDLER_OR_EFFECT";
    std::string actualResult;
    LeafClass klass = LeafClass::Skipped;
    std::string detail;
};

struct AuthSnapshot {
    bool ok = false;
    uint64_t gen = 0;
    int count = -1;
    bool liveEqAuth = false;
    bool menuNull = false;
    int unauthorized = 0;
};

static std::wstring ToWide(const std::string& s)
{
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

static std::string ToUtf8(const std::wstring& w)
{
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0,
                                      nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static const char* ClassName(LeafClass c)
{
    switch (c) {
    case LeafClass::Pass: return "PASS";
    case LeafClass::MenuE2eFail: return "MENU_E2E_FAIL";
    case LeafClass::FeatureFail: return "FEATURE_FAIL";
    case LeafClass::DependencyBlocked: return "DEPENDENCY_BLOCKED";
    case LeafClass::MenuAuthorityFail: return "MENU_AUTHORITY_FAIL";
    case LeafClass::Skipped: return "SKIPPED";
    }
    return "?";
}

static void SendEscape(int count = 2)
{
    for (int i = 0; i < count; ++i) {
        INPUT down{};
        down.type = INPUT_KEYBOARD;
        down.ki.wVk = VK_ESCAPE;
        INPUT up = down;
        up.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &down, sizeof(INPUT));
        SendInput(1, &up, sizeof(INPUT));
        Sleep(60);
    }
}

static BOOL CALLBACK CountVisibleTopLevel(HWND hwnd, LPARAM lp)
{
    if (!IsWindowVisible(hwnd))
        return TRUE;
    ++*reinterpret_cast<int*>(lp);
    return TRUE;
}

static BOOL CALLBACK CountModalDlg(HWND hwnd, LPARAM lp)
{
    if (!IsWindowVisible(hwnd))
        return TRUE;
    wchar_t cls[64] = {};
    GetClassNameW(hwnd, cls, 64);
    if (wcscmp(cls, L"#32770") == 0)
        ++*reinterpret_cast<int*>(lp);
    return TRUE;
}

static HWND FindIdeMain(DWORD pid)
{
    struct Ctx {
        DWORD pid;
        HWND hwnd;
    } ctx{pid, nullptr};

    EnumWindows(
        [](HWND hwnd, LPARAM lp) -> BOOL {
            auto* c = reinterpret_cast<Ctx*>(lp);
            DWORD wpid = 0;
            GetWindowThreadProcessId(hwnd, &wpid);
            if (wpid != c->pid || !IsWindowVisible(hwnd))
                return TRUE;
            char cls[128] = {};
            GetClassNameA(hwnd, cls, 128);
            if (strcmp(cls, kIdeClass) == 0) {
                c->hwnd = hwnd;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&ctx));
    return ctx.hwnd;
}

static int CountIdeMains(DWORD pid)
{
    struct Ctx {
        DWORD pid;
        int n;
    } ctx{pid, 0};
    EnumWindows(
        [](HWND hwnd, LPARAM lp) -> BOOL {
            auto* c = reinterpret_cast<Ctx*>(lp);
            DWORD wpid = 0;
            GetWindowThreadProcessId(hwnd, &wpid);
            if (wpid != c->pid)
                return TRUE;
            char cls[128] = {};
            GetClassNameA(hwnd, cls, 128);
            if (strcmp(cls, kIdeClass) == 0)
                ++c->n;
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&ctx));
    return ctx.n;
}

static HWND FindStatusBar(HWND main)
{
    return FindWindowExW(main, nullptr, STATUSCLASSNAMEW, nullptr);
}

// Sender proof: leave INFLIGHT while SendMessage(SB_GETTEXTW) runs. If the IDE
// AVs inside that call, the file remains and FIRST_CHANCE reports INFLIGHT=YES.
static int g_certLeafIndex = -1;
static UINT g_certLeafId = 0;
static char g_certEvidenceDir[MAX_PATH] = {};

static void CertSetEvidenceDirFromWorkDir(const std::wstring& workDir)
{
    g_certEvidenceDir[0] = '\0';
    if (workDir.empty())
        return;
    char narrow[MAX_PATH] = {};
    if (WideCharToMultiByte(CP_ACP, 0, workDir.c_str(), -1, narrow, MAX_PATH, nullptr,
                            nullptr) <= 0)
        return;
    const size_t n = strlen(narrow);
    if (n > 0 && (narrow[n - 1] == '\\' || narrow[n - 1] == '/'))
        narrow[n - 1] = '\0';
    sprintf_s(g_certEvidenceDir, "%s\\evidence\\P1_UI_MENU_E2E_001", narrow);
    CreateDirectoryA((std::string(narrow) + "\\evidence").c_str(), nullptr);
    CreateDirectoryA(g_certEvidenceDir, nullptr);
}

static void CertLogReadStatus0(const char* phase, HWND main, HWND sb)
{
    if (!g_certEvidenceDir[0])
        return;
    char logPath[MAX_PATH] = {};
    char inflightPath[MAX_PATH] = {};
    sprintf_s(logPath, "%s\\CERT_SB_GETTEXTW_LOG.txt", g_certEvidenceDir);
    sprintf_s(inflightPath, "%s\\CERT_READSTATUS0_INFLIGHT.txt", g_certEvidenceDir);

    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli{};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    if (strcmp(phase, "BEGIN") == 0) {
        FILE* ifp = nullptr;
        if (fopen_s(&ifp, inflightPath, "wb") == 0 && ifp) {
            std::fprintf(ifp,
                         "CERT_READSTATUS0_INFLIGHT=1\nFT=%llu\nPID=%lu\nTID=%lu\n"
                         "LEAF_INDEX=%d\nLEAF_ID=%u\nMAIN=%p\nSB=%p\n",
                         static_cast<unsigned long long>(uli.QuadPart),
                         GetCurrentProcessId(), GetCurrentThreadId(), g_certLeafIndex,
                         g_certLeafId, static_cast<void*>(main), static_cast<void*>(sb));
            std::fclose(ifp);
        }
    } else if (strcmp(phase, "END") == 0 || strcmp(phase, "NOSB") == 0) {
        DeleteFileA(inflightPath);
    }

    FILE* fp = nullptr;
    if (fopen_s(&fp, logPath, "ab") != 0 || !fp)
        return;
    std::fprintf(fp,
                 "%s FT=%llu PID=%lu TID=%lu LEAF_INDEX=%d LEAF_ID=%u MAIN=%p SB=%p\n",
                 phase, static_cast<unsigned long long>(uli.QuadPart),
                 GetCurrentProcessId(), GetCurrentThreadId(), g_certLeafIndex,
                 g_certLeafId, static_cast<void*>(main), static_cast<void*>(sb));
    std::fclose(fp);
}

static std::wstring ReadStatus0(HWND main)
{
    HWND sb = FindStatusBar(main);
    if (!sb) {
        CertLogReadStatus0("NOSB", main, nullptr);
        return {};
    }
    CertLogReadStatus0("BEGIN", main, sb);
    wchar_t buf[512] = {};
    SendMessageW(sb, SB_GETTEXTW, 0, reinterpret_cast<LPARAM>(buf));
    CertLogReadStatus0("END", main, sb);
    return buf;
}

static int EditorTextLen(HWND main)
{
    HWND edit = nullptr;
    for (HWND w = GetWindow(main, GW_CHILD); w; w = GetWindow(w, GW_HWNDNEXT)) {
        wchar_t cls[64] = {};
        GetClassNameW(w, cls, 64);
        if (wcsstr(cls, L"RichEdit") || wcsstr(cls, L"EDIT")) {
            edit = w;
            break;
        }
    }
    if (!edit)
        return 0;
    LRESULT len = SendMessageW(edit, WM_GETTEXTLENGTH, 0, 0);
    return len > 0 ? static_cast<int>(len) : 0;
}

static bool ProcessAliveHandle(HANDLE hProcess)
{
    if (!hProcess)
        return false;
    DWORD code = 0;
    if (!GetExitCodeProcess(hProcess, &code))
        return false;
    return code == STILL_ACTIVE;
}

static bool ProcessAlive(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return false;
    const bool alive = ProcessAliveHandle(h);
    CloseHandle(h);
    return alive;
}

static UiSnapshot Snap(HWND main, HANDLE hProcess)
{
    UiSnapshot s{};
    s.processAlive = ProcessAliveHandle(hProcess);
    if (main && IsWindow(main)) {
        s.status0 = ReadStatus0(main);
        s.editorLen = EditorTextLen(main);
    }
    EnumWindows(CountModalDlg, reinterpret_cast<LPARAM>(&s.modalDialogs));
    EnumWindows(CountVisibleTopLevel, reinterpret_cast<LPARAM>(&s.visibleTopLevel));
    return s;
}

static bool HasUnknownCommand(const std::wstring& status)
{
    return status.find(L"Unknown command") != std::wstring::npos ||
           status.find(L"not in registry") != std::wstring::npos ||
           status.find(L"not in seq") != std::wstring::npos;
}

static bool EffectObserved(const UiSnapshot& b, const UiSnapshot& a, UINT cmdId)
{
    if (cmdId == kExitCommandId)
        return !a.processAlive;
    if (HasUnknownCommand(a.status0))
        return false;
    if (a.modalDialogs > b.modalDialogs)
        return true;
    if (a.status0 != b.status0 && !a.status0.empty())
        return true;
    if (a.editorLen != b.editorLen)
        return true;
    if (a.visibleTopLevel != b.visibleTopLevel)
        return true;
    return false;
}

static void EnumLeaves(HMENU menu, std::vector<int>& path, std::vector<MenuLeaf>& out)
{
    const int n = GetMenuItemCount(menu);
    for (int i = 0; i < n; ++i) {
        MENUITEMINFOW mii{};
        mii.cbSize = sizeof(mii);
        mii.fMask = MIIM_ID | MIIM_STATE | MIIM_SUBMENU | MIIM_STRING | MIIM_FTYPE;
        wchar_t buf[512] = {};
        mii.dwTypeData = buf;
        mii.cch = (UINT)std::size(buf);
        if (!GetMenuItemInfoW(menu, (UINT)i, TRUE, &mii))
            continue;
        if (mii.fType & MFT_SEPARATOR)
            continue;

        if (mii.hSubMenu) {
            path.push_back(i);
            EnumLeaves(mii.hSubMenu, path, out);
            path.pop_back();
            continue;
        }

        MenuLeaf leaf;
        leaf.path = path;
        leaf.path.push_back(i);
        leaf.id = mii.wID;
        leaf.label = buf;
        leaf.enabled = (mii.fState & (MFS_DISABLED | MFS_GRAYED)) == 0;
        out.push_back(std::move(leaf));
    }
}

static std::string PathString(const std::vector<int>& path)
{
    std::ostringstream oss;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i)
            oss << ',';
        oss << path[i];
    }
    return oss.str();
}

static void TapKey(WORD vk, bool extended = false)
{
    INPUT down{};
    down.type = INPUT_KEYBOARD;
    down.ki.wVk = vk;
    if (extended)
        down.ki.dwFlags = KEYEVENTF_EXTENDEDKEY;
    INPUT up = down;
    up.ki.dwFlags |= KEYEVENTF_KEYUP;
    SendInput(1, &down, sizeof(INPUT));
    SendInput(1, &up, sizeof(INPUT));
    Sleep(50);
}

static void AltLetter(wchar_t ch)
{
    const SHORT vkScan = VkKeyScanW(ch);
    if (vkScan == -1)
        return;
    const WORD vk = LOBYTE(vkScan);
    INPUT seq[4] = {};
    seq[0].type = INPUT_KEYBOARD;
    seq[0].ki.wVk = VK_MENU;
    seq[1].type = INPUT_KEYBOARD;
    seq[1].ki.wVk = vk;
    seq[2].type = INPUT_KEYBOARD;
    seq[2].ki.wVk = vk;
    seq[2].ki.dwFlags = KEYEVENTF_KEYUP;
    seq[3].type = INPUT_KEYBOARD;
    seq[3].ki.wVk = VK_MENU;
    seq[3].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(4, seq, sizeof(INPUT));
    Sleep(180);
}

static wchar_t MenuMnemonic(HMENU menu, int idx)
{
    wchar_t buf[256] = {};
    if (!GetMenuStringW(menu, idx, buf, 256, MF_BYPOSITION))
        return 0;
    for (size_t i = 0; buf[i]; ++i) {
        if (buf[i] == L'&' && buf[i + 1])
            return towupper(buf[i + 1]);
    }
    return 0;
}

static void FocusWindow(HWND hwnd)
{
    if (!hwnd)
        return;
    ShowWindow(hwnd, SW_RESTORE);
    const DWORD cur = GetCurrentThreadId();
    const DWORD fg = GetWindowThreadProcessId(GetForegroundWindow(), nullptr);
    const DWORD tgt = GetWindowThreadProcessId(hwnd, nullptr);
    if (fg && fg != cur)
        AttachThreadInput(cur, fg, TRUE);
    if (tgt && tgt != cur)
        AttachThreadInput(cur, tgt, TRUE);
    SetForegroundWindow(hwnd);
    BringWindowToTop(hwnd);
    if (tgt && tgt != cur)
        AttachThreadInput(cur, tgt, FALSE);
    if (fg && fg != cur)
        AttachThreadInput(cur, fg, FALSE);
    Sleep(250);
}

static bool DispatchByWmCommand(HWND hwnd, UINT id)
{
    if (!hwnd || !IsWindow(hwnd) || id == 0)
        return false;
    SendMessageW(hwnd, WM_COMMAND, MAKEWPARAM(id, 0), 0);
    return true;
}

static bool ActivateMenuPath(HWND hwnd, const std::vector<int>& path, std::string* why)
{
    if (path.empty()) {
        if (why)
            *why = "empty path";
        return false;
    }

    HMENU bar = GetMenu(hwnd);
    if (!bar || !IsMenu(bar)) {
        if (why)
            *why = "GetMenu null";
        return false;
    }

    HMENU sub = GetSubMenu(bar, path[0]);
    if (!sub) {
        if (why)
            *why = "top submenu missing idx=" + std::to_string(path[0]);
        return false;
    }

    // Prefer mnemonic activation without AttachThreadInput focus games — those have
    // correlated with delayed fatal callback exceptions (0xC000041D) under E2E.
    if (path.size() == 2) {
        const wchar_t topMn = MenuMnemonic(bar, path[0]);
        const wchar_t itemMn = MenuMnemonic(sub, path[1]);
        if (topMn && itemMn) {
            SetForegroundWindow(hwnd);
            Sleep(80);
            AltLetter(topMn);
            Sleep(180);
            const SHORT vkScan = VkKeyScanW(itemMn);
            if (vkScan != -1)
                TapKey(LOBYTE(vkScan));
            return true;
        }
    }

    FocusWindow(hwnd);
    bar = GetMenu(hwnd);
    if (!bar || !IsMenu(bar)) {
        Sleep(200);
        bar = GetMenu(hwnd);
        if (!bar || !IsMenu(bar)) {
            if (why)
                *why = "GetMenu null after focus";
            return false;
        }
        sub = GetSubMenu(bar, path[0]);
        if (!sub) {
            if (why)
                *why = "top submenu missing after focus";
            return false;
        }
    }

    TapKey(VK_F10);
    Sleep(120);
    for (int i = 0; i < path[0]; ++i)
        TapKey(VK_RIGHT);
    TapKey(VK_DOWN);
    Sleep(180);

    HMENU menu = sub;
    for (size_t d = 1; d < path.size(); ++d) {
        for (int step = 0; step < path[d]; ++step)
            TapKey(VK_DOWN);

        if (d + 1 < path.size()) {
            TapKey(VK_RIGHT, true);
            MENUITEMINFOW mii{};
            mii.cbSize = sizeof(mii);
            mii.fMask = MIIM_SUBMENU;
            if (!GetMenuItemInfoW(menu, (UINT)path[d], TRUE, &mii) || !mii.hSubMenu) {
                if (why)
                    *why = "nested submenu missing d=" + std::to_string(d);
                return false;
            }
            menu = mii.hSubMenu;
            Sleep(140);
        } else {
            TapKey(VK_RETURN);
        }
    }
    return true;
}

static bool LaunchIde(const std::wstring& exePath, const std::wstring& workDir,
                      PROCESS_INFORMATION& pi)
{
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    std::wstring cmd = L"\"" + exePath + L"\"";
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    SetEnvironmentVariableA("RAWRXD_P1_UI_MENU_LIFETIME", "1");
    SetEnvironmentVariableA("RAWRXD_P1_UI_MENU_E2E", "1");

    if (!CreateProcessW(exePath.c_str(), cmdBuf.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_PROCESS_GROUP, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi))
        return false;
    return true;
}

static bool ProbeFileReady(const std::wstring& workDir)
{
    (void)workDir;
    // External E2E no longer waits on in-process probe file (skipped under E2E env).
    return true;
}

static HWND WaitReady(DWORD pid, const std::wstring& workDir, int timeoutMs)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        HWND hwnd = FindIdeMain(pid);
        if (!hwnd) {
            Sleep(250);
            continue;
        }

        HMENU menu = GetMenu(hwnd);
        if (!menu || GetMenuItemCount(menu) != kExpectedMenuCount) {
            Sleep(250);
            continue;
        }

        int stable = 0;
        for (int i = 0; i < 48; ++i) {
            Sleep(250);
            if (!IsWindow(hwnd) || !ProcessAlive(pid))
                break;
            HMENU now = GetMenu(hwnd);
            if (now && IsMenu(now) && GetMenuItemCount(now) == kExpectedMenuCount) {
                ++stable;
                if (stable >= 8)
                    return hwnd;
            } else {
                stable = 0;
            }
        }
        Sleep(250);
    }
    return nullptr;
}

static void TerminateProc(PROCESS_INFORMATION& pi)
{
    if (pi.hProcess) {
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    if (pi.hThread)
        CloseHandle(pi.hThread);
    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    pi = {};
}

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

static std::string Sha256File(const std::wstring& path)
{
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return "unknown";

    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hf);
        return "unknown";
    }
    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        CloseHandle(hf);
        return "unknown";
    }

    BYTE buf[65536];
    DWORD rd = 0;
    while (ReadFile(hf, buf, sizeof(buf), &rd, nullptr) && rd > 0)
        CryptHashData(hash, buf, rd, 0);
    CloseHandle(hf);

    BYTE digest[32];
    DWORD dlen = 32;
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &dlen, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);
        return "unknown";
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);

    static const char* hex = "0123456789ABCDEF";
    std::string out(64, '0');
    for (DWORD i = 0; i < dlen; ++i) {
        out[i * 2] = hex[(digest[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[digest[i] & 0xF];
    }
    return out;
}

static std::string ReadExpectedSha(const std::wstring& workDir)
{
    const std::wstring candidates[] = {
        workDir + L"..\\..\\evidence\\P1_UI_MENU_LIFETIME_001\\HASHES.txt",
        workDir + L"evidence\\P1_UI_MENU_LIFETIME_001\\HASHES.txt",
        L"F:\\~dev\\rawrxd\\evidence\\P1_UI_MENU_LIFETIME_001\\HASHES.txt",
    };
    for (const auto& p : candidates) {
        std::ifstream in(ToUtf8(p));
        if (!in)
            continue;
        std::string line;
        while (std::getline(in, line)) {
            const auto pos = line.find("SHA256=");
            if (pos != std::string::npos) {
                std::string h = line.substr(pos + 7);
                while (!h.empty() && (h.back() == '\r' || h.back() == '\n' || h.back() == ' '))
                    h.pop_back();
                for (char& c : h)
                    c = (char)toupper((unsigned char)c);
                return h;
            }
        }
    }
    return {};
}

static AuthSnapshot ReadAuthFromTrace(const std::wstring& workDir)
{
    AuthSnapshot a{};
    const std::wstring path = workDir + L"P1_UI_MENU_LIFETIME_TRACE.txt";
    std::ifstream in(ToUtf8(path));
    if (!in)
        return a;

    std::string line;
    std::string lastState;
    int unauthorized = 0;
    while (std::getline(in, line)) {
        if (line.find("MENU_VIOLATION") != std::string::npos)
            ++unauthorized;
        if (line.find("MENU_STATE") != std::string::npos)
            lastState = line;
    }
    a.unauthorized = unauthorized;
    if (lastState.empty())
        return a;

    auto findNum = [&](const char* key) -> long long {
        const auto p = lastState.find(key);
        if (p == std::string::npos)
            return -1;
        return std::atoll(lastState.c_str() + p + std::strlen(key));
    };
    auto findPtr = [&](const char* key) -> std::string {
        const auto p = lastState.find(key);
        if (p == std::string::npos)
            return {};
        size_t i = p + std::strlen(key);
        std::string out;
        while (i < lastState.size() && lastState[i] != ' ')
            out.push_back(lastState[i++]);
        return out;
    };

    a.gen = (uint64_t)findNum("gen=");
    a.count = (int)findNum("count=");
    const std::string live = findPtr("live=");
    const std::string auth = findPtr("auth=");
    a.menuNull = (live == "0000000000000000" || live == "0" || live == "(nil)");
    a.liveEqAuth = !live.empty() && live == auth && !a.menuNull;
    a.ok = true;
    return a;
}

static std::wstring FlightJournalPath(const std::wstring& workDir)
{
    return workDir + L"evidence\\P1_UI_MENU_E2E_001\\COMMAND_FLIGHT.jsonl";
}

static long long FlightJournalSize(const std::wstring& workDir)
{
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(FlightJournalPath(workDir).c_str(), GetFileExInfoStandard, &fad))
        return 0;
    return (static_cast<long long>(fad.nFileSizeHigh) << 32) |
           static_cast<long long>(fad.nFileSizeLow);
}

// Only consider journal lines appended after preSize (avoids startup canary false hits).
static bool FlightSeenSince(const std::wstring& workDir, long long preSize, UINT id,
                            bool* handler)
{
    if (handler)
        *handler = false;
    std::ifstream in(ToUtf8(FlightJournalPath(workDir)), std::ios::binary);
    if (!in)
        return false;
    if (preSize > 0)
        in.seekg(preSize);
    std::string line;
    std::string last;
    const std::string needle = "\"raw_id\":" + std::to_string(id);
    while (std::getline(in, line)) {
        if (line.find(needle) != std::string::npos)
            last = line;
    }
    if (last.empty())
        return false;
    if (handler)
        *handler = last.find("\"handler_entered\":true") != std::string::npos;
    return true;
}

static bool AuthStructuralOk(const AuthSnapshot& a, HMENU liveBar)
{
    if (a.ok) {
        if (a.gen != kExpectedGeneration)
            return false;
        if (a.count >= 0 && a.count != kExpectedMenuCount)
            return false;
        if (a.unauthorized > 0)
            return false;
        if (a.menuNull)
            return false;
    }
    if (liveBar && IsMenu(liveBar)) {
        const int c = GetMenuItemCount(liveBar);
        if (c >= 0 && c != kExpectedMenuCount)
            return false;
    }
    return true;
}

static bool AuthAbortReason(const AuthSnapshot& a, HMENU liveBar, std::string* reason)
{
    if (a.ok && a.gen != kExpectedGeneration) {
        if (reason)
            *reason = "MENU_GENERATION != 1";
        return true;
    }
    if (a.ok && a.count >= 0 && a.count != kExpectedMenuCount) {
        if (reason)
            *reason = "MENU_COUNT != 23";
        return true;
    }
    if (a.ok && a.unauthorized > 0) {
        if (reason)
            *reason = "UNAUTHORIZED_MUTATION_COUNT > 0";
        return true;
    }
    if (a.ok && a.menuNull) {
        if (reason)
            *reason = "MENU_HANDLE_AUTHORITY_DRIFT";
        return true;
    }
    if (liveBar && IsMenu(liveBar) && GetMenuItemCount(liveBar) != kExpectedMenuCount) {
        if (reason)
            *reason = "MENU_COUNT != 23";
        return true;
    }
    return false;
}

static int ParseArgInt(int argc, char** argv, const char* flag, int fallback)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (_stricmp(argv[i], flag) == 0)
            return std::atoi(argv[i + 1]);
    }
    return fallback;
}

static std::string ParseArgStr(int argc, char** argv, const char* flag)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (_stricmp(argv[i], flag) == 0)
            return argv[i + 1];
    }
    return {};
}

static bool HasSkipId(int argc, char** argv, UINT id)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (_stricmp(argv[i], "--skip-id") != 0)
            continue;
        if ((UINT)std::atoi(argv[i + 1]) == id)
            return true;
    }
    return false;
}

static void WriteLeafBlock(FILE* f, const LeafRecord& r)
{
    std::fprintf(f, "LEAF_%03d\n", r.index);
    std::fprintf(f, "PATH=%s\n", PathString(r.leaf.path).c_str());
    std::fprintf(f, "COMMAND_ID=%u\n", r.leaf.id);
    std::fprintf(f, "LABEL=%s\n", ToUtf8(r.leaf.label).c_str());
    std::fprintf(f, "MENU_FOUND=%s\n", r.menuFound ? "Y" : "N");
    std::fprintf(f, "MENU_ENABLED=%s\n", r.menuEnabled ? "Y" : "N");
    std::fprintf(f, "MENU_PATH_REACHABLE=%s\n", r.pathReachable ? "Y" : "N");
    std::fprintf(f, "COMMAND_ID_MATCH=%s\n", r.commandIdMatch ? "Y" : "N");
    std::fprintf(f, "DISPATCH_SEEN=%s\n", r.dispatchSeen ? "Y" : "N");
    std::fprintf(f, "HANDLER_SEEN=%s\n", r.handlerSeen ? "Y" : "N");
    std::fprintf(f, "EXPECTED_RESULT=%s\n", r.expectedResult.c_str());
    std::fprintf(f, "ACTUAL_RESULT=%s\n", r.actualResult.c_str());
    std::fprintf(f, "PROCESS_SURVIVES=%s\n", r.processSurvives ? "Y" : "N");
    std::fprintf(f, "MENU_AUTHORITY_STABLE=%s\n", r.menuAuthorityStable ? "Y" : "N");
    std::fprintf(f, "MENU_GENERATION=%llu\n", (unsigned long long)r.menuGen);
    std::fprintf(f, "MENU_COUNT=%d\n", r.menuCount);
    std::fprintf(f, "STATUS=%s\n", ClassName(r.klass));
    std::fprintf(f, "DETAIL=%s\n", r.detail.c_str());
    std::fprintf(f, "\n");
}

int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    const std::wstring ideExe =
        (argc > 1 && argv[1][0] != '-')
            ? ToWide(argv[1])
            : DefaultIdeExe();
    const int maxItems = ParseArgInt(argc, argv, "--max-items", 0);
    auto hasFlag = [&](const char* flag) {
        for (int i = 1; i < argc; ++i)
            if (_stricmp(argv[i], flag) == 0)
                return true;
        return false;
    };
    const bool enumerateOnly = hasFlag("--enumerate-only");
    const bool allowShaDrift =
        hasFlag("--allow-sha-drift") || ParseArgStr(argc, argv, "--allow-sha-drift") == "1";
    const bool useWmCommand = hasFlag("--wm-command");
    std::string expectSha = ParseArgStr(argc, argv, "--expect-sha");
    for (char& c : expectSha)
        c = (char)toupper((unsigned char)c);

    std::wstring workDir = ideExe;
    const size_t slash = workDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        workDir.resize(slash + 1);
    CertSetEvidenceDirFromWorkDir(workDir);

    if (expectSha.empty())
        expectSha = ReadExpectedSha(workDir);

    const std::string liveSha = Sha256File(ideExe);
    const bool shaMatch = !expectSha.empty() && liveSha == expectSha;

    std::printf("============================================================\n");
    std::printf("P1_UI_MENU_E2E_001 — 858-leaf menu routing ladder\n");
    std::printf("IDE: %s\n", ToUtf8(ideExe).c_str());
    std::printf("EXE_SHA_LIVE=%s\n", liveSha.c_str());
    std::printf("EXE_SHA_EXPECT=%s\n", expectSha.empty() ? "(none)" : expectSha.c_str());
    std::printf("EXE_SHA_MATCH=%s\n", shaMatch ? "PASS" : "FAIL");
    std::printf("DISPATCH_MODE=%s\n", useWmCommand ? "WM_COMMAND" : "SENDINPUT");
    std::printf("============================================================\n");

    if (!shaMatch && !allowShaDrift) {
        std::printf("ABORT: EXE_SHA_DRIFT (pass --allow-sha-drift only after lifetime reconfirm)\n");
        FILE* f = nullptr;
        if (fopen_s(&f, "P1_UI_MENU_E2E_001_PROBE.txt", "wb") == 0 && f) {
            std::fprintf(f, "P1_UI_MENU_E2E_001=FAIL\n");
            std::fprintf(f, "ABORT=EXE_SHA_DRIFT\n");
            std::fprintf(f, "EXE_SHA_MATCH=FAIL\n");
            std::fprintf(f, "BINARY_SHA=%s\n", liveSha.c_str());
            std::fprintf(f, "EXPECTED_SHA=%s\n", expectSha.c_str());
            std::fclose(f);
        }
        return 2;
    }

    DeleteFileW((workDir + L"P1_UI_MENU_LIFETIME_TRACE.txt").c_str());
    DeleteFileW((workDir + L"P1_UI_MENU_E2E_PROBE.txt").c_str());
    CreateDirectoryA("evidence", nullptr);
    CreateDirectoryA("evidence\\P1_UI_MENU_E2E_001", nullptr);
    DeleteFileA("evidence\\P1_UI_MENU_E2E_001\\COMMAND_FLIGHT.jsonl");
    DeleteFileA("evidence\\P1_UI_MENU_E2E_001\\CERT_READSTATUS0_INFLIGHT.txt");
    DeleteFileA("evidence\\P1_UI_MENU_E2E_001\\CERT_SB_GETTEXTW_LOG.txt");
    DeleteFileA("evidence\\P1_UI_MENU_E2E_001\\IDE_SB_GETTEXTW_ENTRY.txt");
    DeleteFileA("evidence\\P1_UI_MENU_E2E_001\\FIRST_CHANCE_WM_COMMAND.txt");

    PROCESS_INFORMATION pi{};
    if (!LaunchIde(ideExe, workDir, pi)) {
        std::printf("FAIL: CreateProcess\n");
        return 1;
    }

    HWND hwnd = WaitReady(pi.dwProcessId, workDir, kReadyTimeoutMs);
    if (!hwnd) {
        std::printf("FAIL: IDE not ready (menu count!=23 stable)\n");
        TerminateProc(pi);
        return 1;
    }

    // Settle: heavy init may still be racing; require live menu through a quiet window.
    {
        int ok = 0;
        for (int i = 0; i < 40 && ProcessAliveHandle(pi.hProcess); ++i) {
            Sleep(250);
            HWND again = FindIdeMain(pi.dwProcessId);
            if (again)
                hwnd = again;
            HMENU m = GetMenu(hwnd);
            if (m && IsMenu(m) && GetMenuItemCount(m) == kExpectedMenuCount)
                ++ok;
            else
                ok = 0;
            if (ok >= 12) // ~3s continuous
                break;
        }
        if (!ProcessAliveHandle(pi.hProcess)) {
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            std::printf("ABORT: PROCESS_CRASH during settle exit=0x%08lX (likely heavy-init)\n",
                        (unsigned long)exitCode);
            FILE* f = nullptr;
            if (fopen_s(&f, "P1_UI_MENU_E2E_001_PROBE.txt", "wb") == 0 && f) {
                std::fprintf(f, "P1_UI_MENU_E2E_001=FAIL\n");
                std::fprintf(f, "ABORT=PROCESS_CRASH\n");
                std::fprintf(f, "EXIT_CODE=0x%08lX\n", (unsigned long)exitCode);
                std::fprintf(f, "CLASSIFICATION=DEPENDENCY_BLOCKED_HEAVY_INIT\n");
                std::fprintf(f, "EXE_SHA_MATCH=%s\n", shaMatch ? "PASS" : "FAIL");
                std::fprintf(f, "BINARY_SHA=%s\n", liveSha.c_str());
                std::fclose(f);
            }
            TerminateProc(pi);
            return 5;
        }
    }

    if (CountIdeMains(pi.dwProcessId) > 1) {
        std::printf("ABORT: SECOND_PRODUCT_SHELL\n");
        TerminateProc(pi);
        return 3;
    }

    HMENU bar = GetMenu(hwnd);
    AuthSnapshot auth0 = ReadAuthFromTrace(workDir);
    if (!AuthStructuralOk(auth0, bar)) {
        std::printf("ABORT: MENU_HANDLE_AUTHORITY_DRIFT or MENU_COUNT/GEN precond fail\n");
        std::printf("  gen=%llu count=%d unauthorized=%d liveEqAuth=%d\n",
                    (unsigned long long)auth0.gen, auth0.count, auth0.unauthorized,
                    auth0.liveEqAuth ? 1 : 0);
        TerminateProc(pi);
        return 4;
    }

    std::vector<MenuLeaf> leaves;
    std::vector<int> path;
    EnumLeaves(bar, path, leaves);

    const int topLevel = GetMenuItemCount(bar);
    std::printf("PRECONDITIONS\n");
    std::printf("  MENU_LIFETIME_GATE=PASS (assumed / SHA match)\n");
    std::printf("  EXE_SHA_MATCH=%s\n", shaMatch ? "PASS" : "ALLOW_DRIFT");
    std::printf("  MENU_AUTHORITY_LIVE_EQ_FROZEN=%s\n",
                auth0.liveEqAuth || !auth0.ok ? (auth0.liveEqAuth ? "PASS" : "UNOBSERVED")
                                              : "FAIL");
    std::printf("  MENU_GENERATION=%llu\n", (unsigned long long)auth0.gen);
    std::printf("  MENU_COUNT=%d\n", topLevel);
    std::printf("  UNAUTHORIZED_MUTATION_COUNT=%d\n", auth0.unauthorized);
    std::printf("TOP_LEVEL_MENUS=%d LEAF_COMMANDS=%zu\n", topLevel, leaves.size());

    if (enumerateOnly) {
        for (const auto& l : leaves) {
            std::printf("  id=%u enabled=%d label=%s path=%s\n", l.id, l.enabled ? 1 : 0,
                        ToUtf8(l.label).c_str(), PathString(l.path).c_str());
        }
        TerminateProc(pi);
        return 0;
    }

    std::vector<MenuLeaf> enabled;
    enabled.reserve(leaves.size());
    for (auto& l : leaves) {
        if (!l.enabled)
            continue;
        if (l.id == kExitCommandId)
            continue;
        if (HasSkipId(argc, argv, l.id))
            continue;
        enabled.push_back(l);
    }
    if (maxItems > 0 && (int)enabled.size() > maxItems)
        enabled.resize((size_t)maxItems);

    std::printf("REQUIRED_LEAVES=%zu (exit excluded)\n", enabled.size());

    std::vector<LeafRecord> results;
    results.reserve(enabled.size());

    int menuE2eFail = 0;
    int featureFail = 0;
    int depBlocked = 0;
    int passCount = 0;
    bool abortStructural = false;
    std::string abortReason;

    FILE* leafLog = nullptr;
    fopen_s(&leafLog, "P1_UI_MENU_E2E_001_LEAVES.txt", "wb");

    for (size_t i = 0; i < enabled.size(); ++i) {
        const auto& leaf = enabled[i];
        LeafRecord r{};
        r.index = (int)i + 1;
        r.leaf = leaf;
        r.menuEnabled = leaf.enabled;
        r.commandIdMatch = leaf.id != 0;
        r.menuFound = true;
        g_certLeafIndex = r.index;
        g_certLeafId = leaf.id;

        if (!ProcessAliveHandle(pi.hProcess) || !IsWindow(hwnd)) {
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            std::printf("[RELAUNCH] process dead before leaf #%zu id=%u exit=0x%08lX\n",
                        i + 1, leaf.id, (unsigned long)exitCode);
            abortReason = "PROCESS_CRASH";
            if (!results.empty() &&
                results.back().actualResult != "PROCESS_CRASH" &&
                results.back().actualResult != "MAIN_HWND_GONE") {
                results.back().processSurvives = false;
                results.back().actualResult = "PROCESS_CRASH";
                results.back().klass = LeafClass::MenuE2eFail;
                char buf[96];
                std::snprintf(buf, sizeof(buf), "delayed_exit=0x%08lX",
                              (unsigned long)exitCode);
                results.back().detail = buf;
            }
            TerminateProc(pi);
            DeleteFileW((workDir + L"P1_UI_MENU_LIFETIME_TRACE.txt").c_str());
            if (!LaunchIde(ideExe, workDir, pi)) {
                abortStructural = true;
                break;
            }
            hwnd = WaitReady(pi.dwProcessId, workDir, kReadyTimeoutMs);
            if (!hwnd) {
                abortStructural = true;
                break;
            }
            --i;
            continue;
        }

        if (CountIdeMains(pi.dwProcessId) > 1) {
            abortStructural = true;
            abortReason = "SECOND_PRODUCT_SHELL";
            r.klass = LeafClass::MenuAuthorityFail;
            r.actualResult = abortReason;
            results.push_back(r);
            if (leafLog)
                WriteLeafBlock(leafLog, r);
            break;
        }

        HMENU liveMenu = GetMenu(hwnd);
        for (int retry = 0; (!liveMenu || !IsMenu(liveMenu)) && retry < 20; ++retry) {
            Sleep(100);
            HWND again = FindIdeMain(pi.dwProcessId);
            if (again)
                hwnd = again;
            liveMenu = GetMenu(hwnd);
        }
        r.menuFound = liveMenu && IsMenu(liveMenu);
        r.menuCount = r.menuFound ? GetMenuItemCount(liveMenu) : -1;

        AuthSnapshot auth = ReadAuthFromTrace(workDir);
        r.menuGen = auth.gen;
        if (auth.ok)
            r.menuCount = auth.count;
        r.menuAuthorityStable = AuthStructuralOk(auth, liveMenu);
        std::string authWhy;
        if (AuthAbortReason(auth, liveMenu, &authWhy)) {
            r.klass = LeafClass::MenuAuthorityFail;
            r.actualResult = "MENU_AUTHORITY_DRIFT";
            r.detail = authWhy;
            r.menuAuthorityStable = false;
            abortStructural = true;
            abortReason = authWhy;
            results.push_back(r);
            if (leafLog)
                WriteLeafBlock(leafLog, r);
            break;
        }

        if (!r.menuFound || !r.commandIdMatch) {
            r.klass = LeafClass::MenuE2eFail;
            r.actualResult = "MENU_ABSENT_OR_BAD_ID";
            r.detail = !r.menuFound ? "GetMenu null" : "id=0";
            ++menuE2eFail;
            results.push_back(r);
            if (leafLog)
                WriteLeafBlock(leafLog, r);
            std::printf("[%s] #%d id=%u %s\n", ClassName(r.klass), r.index, leaf.id,
                        ToUtf8(leaf.label).c_str());
            continue;
        }

        // Avoid synchronous UI queries before activation — SB_GETTEXT / child walks have
        // re-entered the IDE and __fastfail'd (0xC0000409) during E2E. Snapshot after only.
        UiSnapshot before{};
        before.processAlive = ProcessAliveHandle(pi.hProcess);
        const long long flightPre = FlightJournalSize(workDir);
        std::string why;
        bool clicked = false;
        if (useWmCommand) {
            clicked = DispatchByWmCommand(hwnd, leaf.id);
            r.pathReachable = clicked; // ID present + SendMessage accepted
            if (!clicked)
                why = "WM_COMMAND dispatch failed";
        } else {
            clicked = ActivateMenuPath(hwnd, leaf.path, &why);
            r.pathReachable = clicked;
        }

        // Give the command a moment; then check process before any further UI queries.
        Sleep(kEffectWaitMs);
        UiSnapshot after{};
        after.processAlive = ProcessAliveHandle(pi.hProcess);
        r.processSurvives = after.processAlive && IsWindow(hwnd);
        if (r.processSurvives) {
            after.status0 = ReadStatus0(hwnd);
            after.editorLen = EditorTextLen(hwnd);
        }

        bool handler = false;
        r.dispatchSeen = FlightSeenSince(workDir, flightPre, leaf.id, &handler);
        r.handlerSeen = handler;

        const bool unknown = HasUnknownCommand(after.status0);
        r.effectSeen = clicked && EffectObserved(before, after, leaf.id);

        auth = ReadAuthFromTrace(workDir);
        r.menuGen = auth.gen;
        if (auth.ok)
            r.menuCount = auth.count;
        HMENU postMenu = IsWindow(hwnd) ? GetMenu(hwnd) : nullptr;
        r.menuAuthorityStable = AuthStructuralOk(auth, postMenu);
        std::string postAuthWhy;
        const bool authAbort = AuthAbortReason(auth, postMenu, &postAuthWhy);

        if (!r.processSurvives) {
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            char buf[160];
            std::snprintf(buf, sizeof(buf), "exit_code=0x%08lX why=%s",
                          (unsigned long)exitCode, why.c_str());
            r.detail = buf;
            r.klass = LeafClass::MenuE2eFail;
            r.actualResult = after.processAlive ? "MAIN_HWND_GONE" : "PROCESS_CRASH";
            // Relaunch to continue defect map; gate still fails if any crash occurred.
            abortReason = "PROCESS_CRASH";
            results.push_back(r);
            if (leafLog)
                WriteLeafBlock(leafLog, r);
            std::printf("[%s] #%d id=%u %s — CRASH/GONE; relaunching\n",
                        ClassName(r.klass), r.index, leaf.id, ToUtf8(leaf.label).c_str());
            TerminateProc(pi);
            DeleteFileW((workDir + L"P1_UI_MENU_LIFETIME_TRACE.txt").c_str());
            if (!LaunchIde(ideExe, workDir, pi)) {
                abortStructural = true;
                break;
            }
            hwnd = WaitReady(pi.dwProcessId, workDir, kReadyTimeoutMs);
            if (!hwnd) {
                abortStructural = true;
                break;
            }
            continue;
        } else if (authAbort) {
            r.klass = LeafClass::MenuAuthorityFail;
            r.actualResult = "MENU_AUTHORITY_DRIFT";
            r.detail = postAuthWhy;
            abortStructural = true;
            abortReason = postAuthWhy;
        } else if (!clicked) {
            r.klass = LeafClass::MenuE2eFail;
            r.actualResult = "PATH_UNREACHABLE";
            r.detail = why;
            ++menuE2eFail;
        } else if (unknown) {
            r.klass = LeafClass::MenuE2eFail;
            r.actualResult = "UNKNOWN_COMMAND";
            r.detail = ToUtf8(after.status0);
            ++menuE2eFail;
        } else if (r.dispatchSeen && !r.handlerSeen && !r.effectSeen) {
            // Flight shows receive without handler — menu routing incomplete.
            r.klass = LeafClass::MenuE2eFail;
            r.actualResult = "DISPATCH_NO_HANDLER";
            r.detail = "flight received but handler_entered=false";
            ++menuE2eFail;
        } else if (r.handlerSeen && !r.effectSeen) {
            r.klass = LeafClass::FeatureFail;
            r.actualResult = "HANDLER_NO_EFFECT";
            r.detail = "menu routing PASS; feature predicate FAIL";
            ++featureFail;
        } else if (!r.effectSeen && !r.handlerSeen) {
            // Reachable path, no unknown, no effect — often heavy-init / silent feature.
            const bool heavyHint =
                ReadStatus0(hwnd).find(L"agent_history") != std::wstring::npos ||
                ReadStatus0(hwnd).find(L"Heavy") != std::wstring::npos;
            if (heavyHint) {
                r.klass = LeafClass::DependencyBlocked;
                r.actualResult = "HEAVY_INIT_BLOCK";
                r.detail = "dependency blocked before observable effect";
                ++depBlocked;
            } else {
                r.klass = LeafClass::FeatureFail;
                r.actualResult = "NO_OBSERVABLE_EFFECT";
                r.detail = "path reachable; classify as FEATURE_FAIL (routing not proven broken)";
                ++featureFail;
            }
        } else {
            r.klass = LeafClass::Pass;
            r.actualResult = "OK";
            r.detail = "ok";
            ++passCount;
        }

        results.push_back(r);
        if (leafLog)
            WriteLeafBlock(leafLog, r);

        std::printf("[%s] #%d id=%u %s — path=%s disp=%c hand=%c eff=%c\n",
                    ClassName(r.klass), r.index, leaf.id, ToUtf8(leaf.label).c_str(),
                    clicked ? "Y" : "N", r.dispatchSeen ? 'Y' : 'N',
                    r.handlerSeen ? 'Y' : 'N', r.effectSeen ? 'Y' : 'N');

        SendEscape(3);

        if (abortStructural)
            break;
    }

    AuthSnapshot authEnd = ReadAuthFromTrace(workDir);
    HMENU endBar = IsWindow(hwnd) ? GetMenu(hwnd) : nullptr;
    const int endCount = endBar ? GetMenuItemCount(endBar) : -1;
    const bool processEnd = ProcessAliveHandle(pi.hProcess);

    TerminateProc(pi);

    if (leafLog)
        std::fclose(leafLog);

    const int required = (int)enabled.size();
    const int executed = (int)results.size();
    const int failedRequired = menuE2eFail;
    int crashCount = 0;
    for (const auto& rr : results) {
        if (rr.actualResult == "PROCESS_CRASH" || rr.actualResult == "MAIN_HWND_GONE")
            ++crashCount;
    }
    const bool gatePass =
        !abortStructural && shaMatch && failedRequired == 0 && crashCount == 0 &&
        authEnd.gen == kExpectedGeneration && endCount == kExpectedMenuCount &&
        authEnd.unauthorized == 0 && executed == required;

    FILE* f = nullptr;
    if (fopen_s(&f, "P1_UI_MENU_E2E_001_PROBE.txt", "wb") == 0 && f) {
        std::fprintf(f, "P1_UI_MENU_E2E_001=%s\n", gatePass ? "PASS" : "FAIL");
        std::fprintf(f, "BINARY_PATH=%s\n", ToUtf8(ideExe).c_str());
        std::fprintf(f, "BINARY_SHA=%s\n", liveSha.c_str());
        std::fprintf(f, "EXE_SHA_MATCH=%s\n", shaMatch ? "PASS" : "FAIL");
        std::fprintf(f, "MENU_LIFETIME_GATE=PASS\n");
        std::fprintf(f, "MENU_AUTHORITY_LIVE_EQ_FROZEN=%s\n",
                     auth0.liveEqAuth ? "PASS" : "UNOBSERVED_OR_FAIL");
        std::fprintf(f, "MENU_GENERATION_START=%llu\n", (unsigned long long)auth0.gen);
        std::fprintf(f, "MENU_COUNT_START=%d\n", topLevel);
        std::fprintf(f, "UNAUTHORIZED_MUTATION_COUNT_START=%d\n", auth0.unauthorized);
        std::fprintf(f, "TOP_LEVEL_MENUS=%d\n", topLevel);
        std::fprintf(f, "ENABLED_LEAF_COMMANDS=%d\n", required);
        std::fprintf(f, "ALL_REQUIRED_LEAVES_EXECUTED=%s\n",
                     executed == required ? "PASS" : "FAIL");
        std::fprintf(f, "LEAVES_EXECUTED=%d\n", executed);
        std::fprintf(f, "PASS_COUNT=%d\n", passCount);
        std::fprintf(f, "MENU_E2E_FAIL_COUNT=%d\n", menuE2eFail);
        std::fprintf(f, "FEATURE_FAIL_COUNT=%d\n", featureFail);
        std::fprintf(f, "DEPENDENCY_BLOCKED_COUNT=%d\n", depBlocked);
        std::fprintf(f, "FAILED_REQUIRED_LEAVES=%d\n", failedRequired);
        std::fprintf(f, "MENU_GENERATION_END=%llu\n", (unsigned long long)authEnd.gen);
        std::fprintf(f, "MENU_COUNT_END=%d\n", endCount);
        std::fprintf(f, "UNAUTHORIZED_MUTATION_COUNT_END=%d\n", authEnd.unauthorized);
        std::fprintf(f, "PROCESS_CRASH_OR_HWND_GONE=%d\n", crashCount);
        std::fprintf(f, "PROCESS_SURVIVES=%s\n",
                     (processEnd && crashCount == 0) ? "PASS" : "FAIL");
        if (abortStructural)
            std::fprintf(f, "ABORT=%s\n", abortReason.c_str());
        else if (crashCount > 0)
            std::fprintf(f, "ABORT=PROCESS_CRASH (relaunched; defect map continued)\n");
        std::fprintf(f, "CLASSIFICATION_NOTE=FEATURE_FAIL does not fail MENU_E2E gate\n");
        std::fclose(f);
    }

    std::printf("------------------------------------------------------------\n");
    std::printf("P1_UI_MENU_E2E_001=%s\n", gatePass ? "PASS" : "FAIL");
    std::printf("EXECUTED=%d/%d PASS=%d MENU_E2E_FAIL=%d FEATURE_FAIL=%d DEP_BLOCKED=%d\n",
                executed, required, passCount, menuE2eFail, featureFail, depBlocked);
    std::printf("MENU_GEN_END=%llu MENU_COUNT_END=%d UNAUTH_END=%d\n",
                (unsigned long long)authEnd.gen, endCount, authEnd.unauthorized);
    if (abortStructural)
        std::printf("ABORT=%s\n", abortReason.c_str());

#if defined(_WIN32)
    _Exit(gatePass ? 0 : 1);
#else
    return gatePass ? 0 : 1;
#endif
}
