// ============================================================================
// Win32Utf8.hpp — single UTF-8 ↔ UTF-16 boundary for Unicode Win32 IDE controls
//
// STATUS BAR LAW (P1_UI_ENCODING_002):
//   CREATE  = STATUSCLASSNAMEW only (ANSI create = FORBIDDEN)
//   WRITE   = SB_SETTEXTW only via StatusBarSetTextUtf8 / StatusBarSetTextWide
//   SB_SETTEXTA / SendMessageA(status, …) = FORBIDDEN (UTF-8→ANSI mojibake)
//   LENIENT MultiByteToWideChar fallback = FORBIDDEN
// ============================================================================
#pragma once

#include <string>
#include <windows.h>
#include <commctrl.h>

namespace RawrXD {

inline std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty())
        return {};

    const int count = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        s.data(),
        static_cast<int>(s.size()),
        nullptr,
        0);

    if (count <= 0)
        return {};

    std::wstring out(static_cast<size_t>(count), L'\0');

    const int written = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        s.data(),
        static_cast<int>(s.size()),
        out.data(),
        count);

    if (written != count)
        return {};

    return out;
}

inline std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty())
        return {};

    const int count = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        w.data(),
        static_cast<int>(w.size()),
        nullptr,
        0,
        nullptr,
        nullptr);

    if (count <= 0)
        return {};

    std::string out(static_cast<size_t>(count), '\0');

    const int written = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        w.data(),
        static_cast<int>(w.size()),
        out.data(),
        count,
        nullptr,
        nullptr);

    if (written != count)
        return {};

    return out;
}

// Wide path — preferred when caller already has UTF-16.
inline bool StatusBarSetTextWide(HWND statusBar, int part, const wchar_t* text)
{
    if (!statusBar || !IsWindow(statusBar))
        return false;
    if (!IsWindowUnicode(statusBar))
        return false; // fail closed — never ACP / SB_SETTEXTA
    return SendMessageW(
               statusBar,
               SB_SETTEXTW,
               static_cast<WPARAM>(part),
               reinterpret_cast<LPARAM>(text ? text : L"")) != FALSE;
}

inline bool StatusBarSetTextWide(HWND statusBar, int part, const std::wstring& text)
{
    return StatusBarSetTextWide(statusBar, part, text.c_str());
}

// UTF-8 → UTF-16 → SB_SETTEXTW. ACP dual-write removed permanently.
inline bool StatusBarSetTextUtf8(HWND statusBar, int part, const std::string& utf8)
{
    if (!statusBar || !IsWindow(statusBar))
        return false;
    if (!IsWindowUnicode(statusBar))
        return false;

    if (utf8.empty())
        return StatusBarSetTextWide(statusBar, part, L"");

    const std::wstring w = Utf8ToWide(utf8);
    if (w.empty())
        return false;

    return StatusBarSetTextWide(statusBar, part, w);
}

}  // namespace RawrXD
