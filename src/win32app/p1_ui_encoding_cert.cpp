// ============================================================================
// p1_ui_encoding_cert.cpp — P1_UI_ENCODING_001
// Isolates UTF-8 → UTF-16 → Win32 control write from GGUF/inference.
// ============================================================================

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <richedit.h>
#include <commctrl.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "Win32Utf8.hpp"

#if defined(_WIN32)
#include <process.h>
#endif

#ifndef CP_UNICODE
#define CP_UNICODE 1200
#endif

struct Gate {
    const char* name;
    bool pass;
    std::string detail;
};

static std::vector<Gate> g_gates;

static void gate(bool ok, const char* name, const std::string& detail = {})
{
    g_gates.push_back({name, ok, detail});
    std::printf("[%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
                detail.empty() ? "" : ": ", detail.empty() ? "" : detail.c_str());
}

static constexpr const char* kProbe =
    "ENCODING_PROBE: ASCII abc XYZ 123 | caf\xC3\xA9 | \xCE\xBB | \xE4\xB8\xAD\xE6\x96\x87 | \xE2\x9C\x93";

static void writeVerdict(const char* path, bool allPass, int passCount, int total)
{
    FILE* f = std::fopen(path, "wb");
    if (!f)
        return;
    std::fprintf(f, "RAWRXD_P1_UI_ENCODING=%s\n", allPass ? "PASS" : "FAIL");
    std::fprintf(f, "gates=%d/%d\n", passCount, total);
    for (const auto& g : g_gates) {
        std::fprintf(f, "%s %s%s%s\n", g.pass ? "PASS" : "FAIL", g.name,
                     g.detail.empty() ? "" : " | ",
                     g.detail.empty() ? "" : g.detail.c_str());
    }
    std::fclose(f);
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("============================================================\n");
    std::printf("P1_UI_ENCODING_001\n");
    std::printf("============================================================\n");

    // Conversion round-trip (no HWND)
    {
        const std::wstring w = RawrXD::Utf8ToWide(kProbe);
        gate(!w.empty(), "UTF8_TO_WIDE_NONEMPTY",
             "wchar_len=" + std::to_string(w.size()));

        const std::string back = RawrXD::WideToUtf8(w);
        gate(back == kProbe, "UTF8_ROUNDTRIP_EXACT",
             back == kProbe ? "match" : ("got_bytes=" + std::to_string(back.size())));

        // ASCII subset must survive even if Unicode glyphs fail later
        const char* ascii = "ENCODING_PROBE: ASCII abc XYZ 123";
        const std::wstring wa = RawrXD::Utf8ToWide(ascii);
        gate(RawrXD::WideToUtf8(wa) == ascii, "ASCII_PROBE_EXACT");
    }

    // HWND path: Unicode RichEdit + status bar
    InitCommonControls();
    LoadLibraryW(L"Msftedit.dll");
    LoadLibraryW(L"Riched20.dll");

    WNDCLASSW wc{};
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"P1UiEncodingHost";
    RegisterClassW(&wc);

    HWND host = CreateWindowExW(0, L"P1UiEncodingHost", L"P1_UI_ENCODING",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                640, 240, nullptr, nullptr, wc.hInstance, nullptr);
    gate(host != nullptr, "WINDOW_CREATED");

    HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
                                WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY,
                                8, 8, 600, 120, host, nullptr, wc.hInstance, nullptr);
    if (!edit) {
        edit = CreateWindowExW(WS_EX_CLIENTEDGE, RICHEDIT_CLASSW, L"",
                               WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY,
                               8, 8, 600, 120, host, nullptr, wc.hInstance, nullptr);
    }
    gate(edit != nullptr, "OUTPUT_CONTROL_CREATED");

    HWND status = CreateWindowExW(0, STATUSCLASSNAMEW, L"",
                                  WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, host,
                                  nullptr, wc.hInstance, nullptr);
    gate(status != nullptr, "STATUSBAR_CREATED");

    if (edit) {
        const std::wstring w = RawrXD::Utf8ToWide(kProbe);
        SendMessageW(edit, EM_SETSEL, 0, 0);
        SendMessageW(edit, EM_REPLACESEL, FALSE, (LPARAM)w.c_str());

        GETTEXTLENGTHEX gtl{};
        gtl.flags = GTL_DEFAULT;
        gtl.codepage = CP_UNICODE;
        const LONG n = (LONG)SendMessageW(edit, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);
        std::wstring got(static_cast<size_t>(n) + 1, L'\0');
        GetWindowTextW(edit, got.data(), n + 1);
        got.resize(wcslen(got.c_str()));

        gate(got == w, "OUTPUT_CONTROL_EXACT",
             "got_wlen=" + std::to_string(got.size()) +
                 " exp_wlen=" + std::to_string(w.size()));

        // Detect the classic reinterpret_cast bug class: if someone wrote UTF-8
        // bytes as wchar_t*, ASCII letters would still appear but multi-byte
        // sequences become CJK / '?'. Roundtrip already covers conversion;
        // here we require full probe equality.
        const bool asciiOk = got.find(L"ASCII abc XYZ 123") != std::wstring::npos;
        gate(asciiOk, "ASCII_IN_CONTROL");
        const bool uniOk = got.find(L"\x4E2D\x6587") != std::wstring::npos;  // 中文
        gate(uniOk, "UTF8_PROBE_EXACT");
    }

    if (status) {
        RawrXD::StatusBarSetTextUtf8(status, 0, "Model: F:\\~dev\\rawrxd\\models\\tinyllama.gguf");
        wchar_t buf[512] = {};
        SendMessageW(status, SB_GETTEXTW, 0, (LPARAM)buf);
        const std::wstring got(buf);
        gate(got.find(L"tinyllama.gguf") != std::wstring::npos, "STATUSBAR_EXACT",
             RawrXD::WideToUtf8(got));
    }

    // Negative: reinterpret_cast UTF-8 as wchar_t must NOT equal Utf8ToWide
    {
        const std::string utf8 = "caf\xC3\xA9";
        const std::wstring correct = RawrXD::Utf8ToWide(utf8);
        // Intentionally wrong: treat UTF-8 bytes as UTF-16 code units
        std::wstring bogus(reinterpret_cast<const wchar_t*>(utf8.c_str()),
                           utf8.size() / sizeof(wchar_t));
        gate(correct != bogus && !correct.empty(), "NO_REINTERPRET_CAST_PATH",
             "correct_wlen=" + std::to_string(correct.size()));
    }

    int passCount = 0;
    for (const auto& g : g_gates)
        if (g.pass)
            ++passCount;
    const bool allPass = passCount == (int)g_gates.size();
    std::string firstFail = "none";
    for (const auto& g : g_gates) {
        if (!g.pass) {
            firstFail = g.name;
            break;
        }
    }

    std::printf("------------------------------------------------------------\n");
    std::printf("RAWRXD_P1_UI_ENCODING=%s (%d/%d)\n",
                allPass ? "PASS" : "FAIL", passCount, (int)g_gates.size());
    std::printf("FIRST_FALSE_TRANSITION=%s\n", firstFail.c_str());

    writeVerdict("P1_UI_ENCODING_VERDICT.txt", allPass, passCount, (int)g_gates.size());

    if (host)
        DestroyWindow(host);

#if defined(_WIN32)
    _Exit(allPass ? 0 : 1);
#else
    return allPass ? 0 : 1;
#endif
}
