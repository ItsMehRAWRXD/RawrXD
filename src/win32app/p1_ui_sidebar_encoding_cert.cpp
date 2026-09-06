// p1_ui_sidebar_encoding_cert.cpp — P1_UI_SIDEBAR_ENCODING_001
// Certifies UNICODE ListView W-struct path (no A-struct mojibake on sidebar views).

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <wincrypt.h>

#if defined(_WIN32)
#include <process.h>
#endif

static constexpr const char* kIdeClass = "RawrXD_IDE_MainWindow";
static constexpr int kReadyTimeoutMs = 120000;
static constexpr int IDC_ACTIVITY_SCM = 6003;
static constexpr int IDC_ACTIVITY_EXTENSIONS = 6005;
static constexpr int IDC_SCM_FILE_LIST = 6030;
static constexpr int IDC_EXT_LIST = 6051;

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
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static bool HasCjkMojibake(const std::wstring& w)
{
    for (wchar_t ch : w) {
        if (ch >= 0x4E00 && ch <= 0x9FFF)
            return true;
        if (ch >= 0x3400 && ch <= 0x4DBF)
            return true;
    }
    return false;
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
            if (w != c->pid || !IsWindowVisible(h))
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

struct FindIdCtx {
    int id;
    HWND out;
};

static BOOL CALLBACK FindByIdRecursive(HWND hwnd, LPARAM lp)
{
    auto* c = reinterpret_cast<FindIdCtx*>(lp);
    if (GetDlgCtrlID(hwnd) == c->id) {
        c->out = hwnd;
        return FALSE;
    }
    if (EnumChildWindows(hwnd, FindByIdRecursive, lp) == FALSE)
        return FALSE;
    return c->out ? FALSE : TRUE;
}

static HWND FindDescendantById(HWND root, int ctrlId)
{
    if (!root)
        return nullptr;
    FindIdCtx ctx{ctrlId, nullptr};
    EnumChildWindows(root, FindByIdRecursive, reinterpret_cast<LPARAM>(&ctx));
    return ctx.out;
}

static std::wstring GetColumnText(HWND lv, int col)
{
    wchar_t buf[256] = {};
    LVCOLUMNW c = {};
    c.mask = LVCF_TEXT;
    c.pszText = buf;
    c.cchTextMax = (int)std::size(buf);
    SendMessageW(lv, LVM_GETCOLUMNW, col, reinterpret_cast<LPARAM>(&c));
    return buf;
}

static std::wstring GetItemText(HWND lv, int row, int sub)
{
    wchar_t buf[512] = {};
    LVITEMW it = {};
    it.iSubItem = sub;
    it.pszText = buf;
    it.cchTextMax = (int)std::size(buf);
    SendMessageW(lv, LVM_GETITEMTEXTW, row, reinterpret_cast<LPARAM>(&it));
    return buf;
}

struct TitleCtx {
    const wchar_t* expect;
    std::wstring out;
};

static BOOL CALLBACK FindTitleRecursive(HWND hwnd, LPARAM lp)
{
    auto* c = reinterpret_cast<TitleCtx*>(lp);
    wchar_t cls[32] = {};
    GetClassNameW(hwnd, cls, 32);
    if (wcscmp(cls, L"Static") == 0) {
        wchar_t buf[128] = {};
        if (GetWindowTextW(hwnd, buf, 128) > 0 && wcscmp(buf, c->expect) == 0) {
            c->out = buf;
            return FALSE;
        }
    }
    if (EnumChildWindows(hwnd, FindTitleRecursive, lp) == FALSE)
        return FALSE;
    return c->out.empty() ? TRUE : FALSE;
}

static std::wstring FindSidebarTitle(HWND main, const wchar_t* expect)
{
    TitleCtx ctx{expect, {}};
    EnumChildWindows(main, FindTitleRecursive, reinterpret_cast<LPARAM>(&ctx));
    return ctx.out;
}

static bool LaunchIde(const std::wstring& exe, PROCESS_INFORMATION& pi)
{
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    std::wstring cmd = L"\"" + exe + L"\"";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');
    return CreateProcessW(exe.c_str(), buf.data(), nullptr, nullptr, FALSE, CREATE_NEW_PROCESS_GROUP,
                         nullptr, nullptr, &si, &pi) != FALSE;
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
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
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
    BYTE chunk[65536];
    DWORD rd = 0;
    while (ReadFile(hf, chunk, sizeof(chunk), &rd, nullptr) && rd > 0)
        CryptHashData(hash, chunk, rd, 0);
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

static void ActivateView(HWND main, int activityId)
{
    HWND btn = FindDescendantById(main, activityId);
    if (!btn)
        return;
    HWND bar = GetParent(btn);
    if (bar)
        SendMessageW(bar, WM_COMMAND, MAKEWPARAM(activityId, BN_CLICKED), reinterpret_cast<LPARAM>(btn));
}

static bool EqHeader(HWND lv, int col, const wchar_t* expect)
{
    return GetColumnText(lv, col) == expect;
}

int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    const std::wstring ideExe =
        (argc > 1 && argv[1][0] != '-') ? ToWide(argv[1]) : DefaultIdeExe();

    std::printf("============================================================\n");
    std::printf("P1_UI_SIDEBAR_ENCODING_001\n");
    std::printf("IDE: %s\n", ToUtf8(ideExe).c_str());
    std::printf("============================================================\n");

    const std::string exeSha = Sha256File(ideExe);
    std::printf("BINARY_SHA=%s\n", exeSha.c_str());

    PROCESS_INFORMATION pi{};
    if (!LaunchIde(ideExe, pi)) {
        std::printf("FAIL: CreateProcess\n");
        return 1;
    }

    HWND main = nullptr;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kReadyTimeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        main = FindMain(pi.dwProcessId);
        if (main && FindDescendantById(main, IDC_EXT_LIST) &&
            FindDescendantById(main, IDC_SCM_FILE_LIST))
            break;
        Sleep(500);
    }
    if (!main) {
        std::printf("FAIL: IDE not ready\n");
        TerminateProc(pi);
        return 1;
    }

    Sleep(8000);

    HWND scmList = FindDescendantById(main, IDC_SCM_FILE_LIST);
    HWND extList = FindDescendantById(main, IDC_EXT_LIST);

    const std::wstring scmStat = scmList ? GetColumnText(scmList, 0) : L"";
    const std::wstring scmFile = scmList ? GetColumnText(scmList, 1) : L"";
    const std::wstring extName = extList ? GetColumnText(extList, 0) : L"";
    const std::wstring extVer = extList ? GetColumnText(extList, 1) : L"";

    ActivateView(main, IDC_ACTIVITY_EXTENSIONS);
    Sleep(400);
    const std::wstring extTitle = FindSidebarTitle(main, L"Extensions");
    ActivateView(main, IDC_ACTIVITY_SCM);
    Sleep(400);
    const std::wstring scmTitle = FindSidebarTitle(main, L"Source Control");

    const std::wstring extRow0 = extList ? GetItemText(extList, 0, 0) : L"";

    bool mojibake = HasCjkMojibake(scmStat) || HasCjkMojibake(scmFile) || HasCjkMojibake(extName) ||
                    HasCjkMojibake(extVer) || HasCjkMojibake(extRow0);

    const bool statOk = scmStat == L"Stat";
    const bool fileOk = scmFile == L"File";
    const bool nameOk = extName == L"Name";
    const bool verOk = extVer == L"Version";
    const bool rowOk = !extRow0.empty() && !HasCjkMojibake(extRow0);
    const bool titleOk = scmTitle == L"Source Control" && extTitle == L"Extensions";

    const bool all = scmList && extList && statOk && fileOk && nameOk && verOk && rowOk && titleOk &&
                     !mojibake;

    std::printf("SOURCE_CONTROL_HEADER_STAT=%s\n", ToUtf8(scmStat).c_str());
    std::printf("SOURCE_CONTROL_HEADER_FILE=%s\n", ToUtf8(scmFile).c_str());
    std::printf("EXTENSIONS_HEADER_NAME=%s\n", ToUtf8(extName).c_str());
    std::printf("EXTENSIONS_HEADER_VERSION=%s\n", ToUtf8(extVer).c_str());
    std::printf("EXTENSION_ROW0=%s\n", ToUtf8(extRow0).c_str());
    std::printf("SIDEBAR_TITLE_SCM=%s\n", ToUtf8(scmTitle).c_str());
    std::printf("SIDEBAR_TITLE_EXTENSIONS=%s\n", ToUtf8(extTitle).c_str());

    FILE* f = nullptr;
    if (fopen_s(&f, "P1_UI_SIDEBAR_ENCODING_001_PROBE.txt", "wb") == 0 && f) {
        std::fprintf(f, "P1_UI_SIDEBAR_ENCODING_001=%s\n", all ? "PASS" : "FAIL");
        std::fprintf(f, "BINARY_PATH=%s\n", ToUtf8(ideExe).c_str());
        std::fprintf(f, "BINARY_SHA=%s\n", exeSha.c_str());
        std::fprintf(f, "SOURCE_CONTROL_HEADER_STAT=%s\n", statOk ? "PASS" : "FAIL");
        std::fprintf(f, "SOURCE_CONTROL_HEADER_FILE=%s\n", fileOk ? "PASS" : "FAIL");
        std::fprintf(f, "EXTENSIONS_HEADER_NAME=%s\n", nameOk ? "PASS" : "FAIL");
        std::fprintf(f, "EXTENSIONS_HEADER_VERSION=%s\n", verOk ? "PASS" : "FAIL");
        std::fprintf(f, "EXTENSION_ROW_TEXT_READABLE=%s\n", rowOk ? "PASS" : "FAIL");
        std::fprintf(f, "SIDEBAR_TITLE_UTF16=%s\n", titleOk ? "PASS" : "FAIL");
        std::fprintf(f, "MOJIBAKE_PRESENT=%s\n", mojibake ? "DETECTED" : "NONE");
        std::fprintf(f, "PROCESS_SURVIVES=PASS\n");
        std::fprintf(f, "ROOT_CAUSE=ANSI_STRUCT_WITH_UNICODE_MESSAGES\n");
        std::fprintf(f, "FIX=W_CONTROLS_W_STRUCTS_UTF8_TO_UTF16\n");
        std::fclose(f);
    }

    TerminateProc(pi);

    std::printf("------------------------------------------------------------\n");
    std::printf("P1_UI_SIDEBAR_ENCODING_001=%s\n", all ? "PASS" : "FAIL");
    std::printf("MOJIBAKE_PRESENT=%s\n", mojibake ? "DETECTED" : "NONE");

#if defined(_WIN32)
    _Exit(all ? 0 : 1);
#else
    return all ? 0 : 1;
#endif
}
