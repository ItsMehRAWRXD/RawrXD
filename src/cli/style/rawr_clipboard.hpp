// rawr_clipboard.hpp — Win32 clipboard helper (optional UX)
#pragma once
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::style {

inline bool ClipboardSetText(const std::string& text) {
#ifdef _WIN32
    if (!OpenClipboard(nullptr)) return false;
    EmptyClipboard();
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!h) { CloseClipboard(); return false; }
    char* p = (char*)GlobalLock(h);
    if (!p) { GlobalFree(h); CloseClipboard(); return false; }
    memcpy(p, text.c_str(), text.size() + 1);
    GlobalUnlock(h);
    SetClipboardData(CF_TEXT, h);
    CloseClipboard();
    return true;
#else
    (void)text;
    return false;
#endif
}

inline bool ClipboardGetText(std::string& out) {
#ifdef _WIN32
    out.clear();
    if (!OpenClipboard(nullptr)) return false;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (!h) { CloseClipboard(); return false; }
    const char* p = (const char*)GlobalLock(h);
    if (p) out = p;
    GlobalUnlock(h);
    CloseClipboard();
    return !out.empty();
#else
    (void)out;
    return false;
#endif
}

} // namespace rawr::style
