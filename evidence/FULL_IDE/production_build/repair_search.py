from pathlib import Path
p=Path(r'F:\rawrxd\src\win32app\Win32IDE.cpp')
s=p.read_text(encoding='utf-8')
s=s.replace('#include "Win32IDE_CommandIDs.h"','#include "Win32IDE_CommandIDs.h"\n#include <regex>',1)
pos=s.index('void Win32IDE::showFindDialog()')
s=s[:pos]+'''namespace {
HWND CreateSearchWindow(HINSTANCE instance, HWND parent, DLGPROC proc,
                        Win32IDE* ide, const char* title) {
    // A real modeless dialog installs the DLGPROC, unlike a STATIC window.
    struct EmptyDialog { DLGTEMPLATE dialog; WORD menu, windowClass, title; };
    EmptyDialog layout{};
    layout.dialog.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME;
    layout.dialog.dwExtendedStyle = WS_EX_DLGMODALFRAME;
    layout.dialog.x = 100; layout.dialog.y = 100;
    layout.dialog.cx = 270; layout.dialog.cy = 140;
    HWND window = CreateDialogIndirectParamA(instance, &layout.dialog, parent, proc,
                                             reinterpret_cast<LPARAM>(ide));
    if (window) SetWindowTextA(window, title);
    return window;
}
struct SearchMatch { size_t start, length; std::string replacement; };
std::vector<SearchMatch> SearchMatches(const std::string& text, const std::string& search,
        bool caseSensitive, bool wholeWord, bool useRegex, const std::string& replacement) {
    std::vector<SearchMatch> matches;
    if (search.empty()) return matches;
    auto word = [](unsigned char c) { return std::isalnum(c) != 0 || c == '_'; };
    auto boundary = [&](size_t start, size_t length) {
        return !wholeWord || ((start == 0 || !word(text[start - 1])) &&
            (start + length == text.size() || !word(text[start + length])));
    };
    if (useRegex) {
        auto flags = std::regex::ECMAScript;
        if (!caseSensitive) flags |= std::regex::icase;
        const std::regex expression(search, flags);
        for (std::sregex_iterator it(text.begin(), text.end(), expression), end; it != end; ++it) {
            const auto start = static_cast<size_t>(it->position());
            const auto length = static_cast<size_t>(it->length());
            if (boundary(start, length)) matches.push_back({start, length, it->format(replacement)});
        }
    } else {
        std::string haystack = text, needle = search;
        if (!caseSensitive) {
            auto lower = [](unsigned char c) { return static_cast<char>(std::tolower(c)); };
            std::transform(haystack.begin(), haystack.end(), haystack.begin(), lower);
            std::transform(needle.begin(), needle.end(), needle.begin(), lower);
        }
        for (size_t pos = 0; (pos = haystack.find(needle, pos)) != std::string::npos; pos += needle.size()) {
            if (boundary(pos, needle.size())) matches.push_back({pos, needle.size(), replacement});
        }
    }
    return matches;
}
} // namespace

'''+s[pos:]
s=s.replace('''HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Find",
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            100, 100, 400, 150, m_hwndMain, nullptr, m_hInstance, nullptr);''','''HWND hwndDlg = CreateSearchWindow(m_hInstance, m_hwndMain, FindDialogProc, this, "Find");
        if (!hwndDlg) return;
        SetWindowPos(hwndDlg, nullptr, 100, 100, 400, 150, SWP_NOZORDER | SWP_NOACTIVATE);''',1)
s=s.replace('''HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Replace",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        100, 100, 400, 200, m_hwndMain, nullptr, m_hInstance, nullptr);''','''HWND hwndDlg = CreateSearchWindow(m_hInstance, m_hwndMain, ReplaceDialogProc, this, "Replace");
    if (!hwndDlg) return;
    SetWindowPos(hwndDlg, nullptr, 100, 100, 400, 200, SWP_NOZORDER | SWP_NOACTIVATE);''',1)
# Hidden owner windows keep modeless test dialogs hidden; production owners show them.
s=s.replace('ShowWindow(m_hwndFindDialog, SW_SHOW);','ShowWindow(m_hwndFindDialog, IsWindowVisible(m_hwndMain) ? SW_SHOW : SW_HIDE);',1)
s=s.replace('ShowWindow(m_hwndReplaceDialog, SW_SHOW);','ShowWindow(m_hwndReplaceDialog, IsWindowVisible(m_hwndMain) ? SW_SHOW : SW_HIDE);',1)
a=s.index('bool Win32IDE::findText(');b=s.index('INT_PTR CALLBACK Win32IDE::FindDialogProc',a)
s=s[:a]+'''bool Win32IDE::findText(const std::string& searchText, bool forward, bool caseSensitive, bool wholeWord, bool useRegex)
{
    if (!m_hwndEditor || searchText.empty()) return false;
    const int length = GetWindowTextLengthA(m_hwndEditor);
    std::string text(length + 1, '\\0');
    GetWindowTextA(m_hwndEditor, text.data(), length + 1);
    text.resize(length);
    CHARRANGE selection{};
    SendMessageA(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&selection));
    std::vector<SearchMatch> matches;
    try { matches = SearchMatches(text, searchText, caseSensitive, wholeWord, useRegex, ""); }
    catch (const std::regex_error& e) {
        MessageBoxA(m_hwndMain, e.what(), "Invalid search expression", MB_OK | MB_ICONERROR);
        return false;
    }
    if (matches.empty()) {
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, reinterpret_cast<LPARAM>("Text not found."));
        return false;
    }
    const SearchMatch* found = forward ? &matches.front() : &matches.back();
    if (forward) {
        for (const auto& match : matches) if (match.start >= static_cast<size_t>(selection.cpMax)) {
            found = &match; break;
        }
    } else {
        for (auto it = matches.rbegin(); it != matches.rend(); ++it)
            if (it->start < static_cast<size_t>(selection.cpMin)) { found = &*it; break; }
    }
    selection.cpMin = static_cast<LONG>(found->start);
    selection.cpMax = static_cast<LONG>(found->start + found->length);
    SendMessageA(m_hwndEditor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&selection));
    SendMessageA(m_hwndEditor, EM_SCROLLCARET, 0, 0);
    m_lastFoundPos = selection.cpMin;
    return true;
}

int Win32IDE::replaceText(const std::string& searchText, const std::string& replacement, bool all,
                         bool caseSensitive, bool wholeWord, bool useRegex)
{
    if (!m_hwndEditor || searchText.empty()) return 0;
    const int length = GetWindowTextLengthA(m_hwndEditor);
    std::string text(length + 1, '\\0');
    GetWindowTextA(m_hwndEditor, text.data(), length + 1);
    text.resize(length);
    std::vector<SearchMatch> matches;
    try { matches = SearchMatches(text, searchText, caseSensitive, wholeWord, useRegex, replacement); }
    catch (const std::regex_error& e) {
        MessageBoxA(m_hwndMain, e.what(), "Invalid search expression", MB_OK | MB_ICONERROR);
        return 0;
    }
    if (matches.empty()) return 0;
    if (all) {
        std::string result;
        size_t cursor = 0;
        for (const auto& match : matches) {
            result.append(text, cursor, match.start - cursor);
            result.append(match.replacement);
            cursor = match.start + match.length;
        }
        result.append(text, cursor, std::string::npos);
        SendMessageA(m_hwndEditor, EM_SETSEL, 0, -1);
        SendMessageA(m_hwndEditor, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(result.c_str()));
        m_fileModified = true;
        return static_cast<int>(matches.size());
    }
    CHARRANGE selection{};
    SendMessageA(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&selection));
    for (const auto& match : matches) {
        if (match.start == static_cast<size_t>(selection.cpMin) &&
            match.start + match.length == static_cast<size_t>(selection.cpMax)) {
            SendMessageA(m_hwndEditor, EM_REPLACESEL, TRUE,
                         reinterpret_cast<LPARAM>(match.replacement.c_str()));
            m_fileModified = true;
            findText(searchText, true, caseSensitive, wholeWord, useRegex);
            return 1;
        }
    }
    return 0;
}

'''+s[b:]
p.write_text(s,encoding='utf-8')
