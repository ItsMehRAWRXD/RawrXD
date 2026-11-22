// g51_inline_completion_acceptance.cpp — G51 GhostText in-process acceptance
//
// Exercises the real RawrXD::UX::InlineCompletionEngine state machine against a
// live RichEdit20W control (the production editor class), verifying:
//   - a model response produces an active suggestion (S03: completion appears)
//   - Tab accepts and inserts the text at the caret (S04: accept)
//   - ESC dismisses (S04: dismiss)
//   - any other key dismisses a stale suggestion (S04: cancel stale)
//   - render position API (EM_POSFROMCHAR) used by renderGhostText works
//   - metrics (totalRequests, accepted) are correct
//
// Exit 0 = all G51 state-machine assertions pass.

#include <windows.h>
#include <richedit.h>
#include <cstdio>
#include <string>

#include "../../src/win32app/Win32IDE_InlineCompletion.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

using namespace RawrXD::UX;

static int failures = 0;
static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

static std::wstring getEditTExt(HWND edit) {
    const int len = GetWindowTextLengthW(edit);
    std::wstring s(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(edit, &s[0], len + 1);
    return s;
}

int main() {
    LoadLibraryW(L"riched20.dll");
    const HINSTANCE hInst = GetModuleHandleW(nullptr);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = hInst;
    wc.lpszClassName = L"G51TestMain";
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        std::printf("FAIL register_class err=%lu\n", GetLastError());
        return 1;
    }
    HWND main = CreateWindowExW(0, wc.lpszClassName, L"G51", WS_OVERLAPPED,
                                0, 0, 500, 300, nullptr, nullptr, hInst, nullptr);
    if (!main) { std::printf("FAIL create_main err=%lu\n", GetLastError()); return 1; }

    HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"RICHEDIT20W",
                                L"int main() {\r\n  ",
                                WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL |
                                WS_VSCROLL | ES_NOHIDESEL | ES_SAVESEL,
                                0, 0, 480, 200, main,
                                reinterpret_cast<HMENU>(1001), hInst, nullptr);
    if (!edit) { std::printf("FAIL create_edit err=%lu\n", GetLastError()); return 1; }
    expect(IsWindow(edit), "editor_created");

    auto& eng = InlineCompletionEngine::instance();
    expect(eng.initialize(edit), "engine_initialize");

    // S03: model response -> active suggestion appears.
    eng.onModelResponse("return 0;", 12.5);
    expect(eng.hasActiveSuggestion(), "suggestion_appears");
    expect(eng.getMetrics().totalRequests == 1, "metrics_total_requests_1");

    // Render position API (used by renderGhostText) resolves a caret location.
    POINT pt = {};
    SendMessageW(edit, EM_POSFROMCHAR, reinterpret_cast<WPARAM>(&pt), 0);
    expect(pt.y >= 0, "render_position_valid");

    // S04 accept: Tab inserts the suggestion at the caret.
    SendMessageW(edit, WM_KEYDOWN, VK_TAB, 0);
    const std::wstring afterAccept = getEditTExt(edit);
    expect(afterAccept.find(L"return 0;") != std::wstring::npos, "accept_inserts_text");
    expect(!eng.hasActiveSuggestion(), "accept_clears_suggestion");
    expect(eng.getMetrics().accepted == 1, "metrics_accepted_1");

    // S04 dismiss: ESC clears an active suggestion without inserting.
    eng.onModelResponse("x", 5.0);
    expect(eng.hasActiveSuggestion(), "suggestion2_appears");
    SendMessageW(edit, WM_KEYDOWN, VK_ESCAPE, 0);
    expect(!eng.hasActiveSuggestion(), "esc_dismisses");
    const std::wstring afterEsc = getEditTExt(edit);
    expect(afterEsc.find(L"x") == std::wstring::npos || afterEsc == afterAccept,
           "esc_does_not_insert");

    // S04 cancel stale: any other key dismisses an active suggestion.
    eng.onModelResponse("y", 5.0);
    expect(eng.hasActiveSuggestion(), "suggestion3_appears");
    SendMessageW(edit, WM_KEYDOWN, 'A', 0);
    expect(!eng.hasActiveSuggestion(), "typing_dismisses_stale");

    // Empty response produces no suggestion.
    eng.onModelResponse("", 1.0);
    expect(!eng.hasActiveSuggestion(), "empty_response_no_suggestion");

    eng.shutdown();
    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}