#pragma once
#include "document.hpp"
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::product {

struct EditorHwnd {
#ifdef _WIN32
    HWND hwnd = nullptr;
    HWND edit = nullptr;
#endif
    int created = 0;

    bool create(const char* title) {
#ifdef _WIN32
        hwnd = CreateWindowExA(0, "STATIC", title, 0, 0, 0, 0, 0,
                               HWND_MESSAGE, nullptr, GetModuleHandleA(nullptr),
                               nullptr);
        if (!hwnd) return false;
        edit = CreateWindowExA(0, "EDIT", "",
                               WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL, 0, 0,
                               400, 200, hwnd, nullptr,
                               GetModuleHandleA(nullptr), nullptr);
        created = (edit != nullptr) ? 1 : 0;
        return created != 0;
#else
        (void)title;
        return false;
#endif
    }

    void setText(const std::string& t) {
#ifdef _WIN32
        if (edit) SetWindowTextA(edit, t.c_str());
#else
        (void)t;
#endif
    }

    std::string getText() const {
#ifdef _WIN32
        if (!edit) return {};
        int n = GetWindowTextLengthA(edit);
        if (n <= 0) return {};
        std::string s((size_t)n + 1, '\0');
        GetWindowTextA(edit, s.data(), n + 1);
        s.resize((size_t)n);
        return s;
#else
        return {};
#endif
    }

    void destroy() {
#ifdef _WIN32
        if (hwnd) DestroyWindow(hwnd);
        hwnd = nullptr;
        edit = nullptr;
#endif
        created = 0;
    }

    ~EditorHwnd() { destroy(); }
};

inline bool SyncDocToHwnd(const Document& d, EditorHwnd& w) {
    w.setText(d.text);
    return w.getText() == d.text;
}

} // namespace rawr::product
