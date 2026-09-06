// Win32IDE_MainMenuAuthority.hpp — MAIN_MENU_AUTHORITY (P1_UI_MENU_LIFETIME_001)
#pragma once

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdarg>

namespace RawrXD::MainMenuAuthority {

struct MainMenuAuthorityState {
    HWND     hwnd = nullptr;
    HMENU    authoritativeMenu = nullptr;
    uint64_t generation = 0;
    bool     intentionallyDetached = false;
    bool     windowDestroying = false;
    uint32_t unauthorizedMutationCount = 0;
    uint32_t unauthorizedDestroyCount = 0;
};

inline MainMenuAuthorityState& State()
{
    static MainMenuAuthorityState s;
    return s;
}

inline bool TraceEnabled()
{
    const char* v = std::getenv("RAWRXD_P1_UI_MENU_LIFETIME");
    return v && v[0] && v[0] != '0';
}

inline void TraceLine(const char* fmt, ...)
{
    if (!TraceEnabled())
        return;
    static CRITICAL_SECTION s_cs;
    static bool s_csInit = false;
    if (!s_csInit) {
        InitializeCriticalSection(&s_cs);
        s_csInit = true;
    }
    EnterCriticalSection(&s_cs);
    FILE* f = nullptr;
    if (fopen_s(&f, "P1_UI_MENU_LIFETIME_TRACE.txt", "ab") == 0 && f) {
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(f, fmt, ap);
        va_end(ap);
        std::fputc('\n', f);
        std::fflush(f);
        std::fclose(f);
    }
    LeaveCriticalSection(&s_cs);
}

inline void TraceMenuState(HWND hwnd, const char* phase)
{
    if (!TraceEnabled())
        return;

    auto& st = State();
    if (hwnd)
        st.hwnd = hwnd;

    HMENU live = hwnd ? GetMenu(hwnd) : nullptr;
    const int count = live ? GetMenuItemCount(live) : -1;
    const BOOL valid = live ? IsMenu(live) : FALSE;

    TraceLine(
        "MENU_STATE phase=%s hwnd=%p live=%p auth=%p gen=%llu valid=%d count=%d "
        "detached=%d destroying=%d",
        phase ? phase : "?",
        static_cast<void*>(hwnd),
        static_cast<void*>(live),
        static_cast<void*>(st.authoritativeMenu),
        static_cast<unsigned long long>(st.generation),
        valid ? 1 : 0,
        count,
        st.intentionallyDetached ? 1 : 0,
        st.windowDestroying ? 1 : 0);
}

inline void TraceMenuViolation(const char* kind, HMENU live, HMENU auth, uint64_t gen)
{
    auto& st = State();
    ++st.unauthorizedMutationCount;
    TraceLine(
        "MENU_VIOLATION kind=%s live=%p auth=%p gen=%llu mutations=%u",
        kind ? kind : "UNKNOWN",
        static_cast<void*>(live),
        static_cast<void*>(auth),
        static_cast<unsigned long long>(gen),
        st.unauthorizedMutationCount);
}

inline void TracePromote(HMENU oldMenu, HMENU newMenu, uint64_t oldGen, uint64_t newGen,
                         const char* reason)
{
    TraceLine("MENU_PROMOTE OLD=%p NEW=%p GEN=%llu->%llu REASON=%s",
              static_cast<void*>(oldMenu),
              static_cast<void*>(newMenu),
              static_cast<unsigned long long>(oldGen),
              static_cast<unsigned long long>(newGen),
              reason ? reason : "?");
}

inline void TraceDetach(uint64_t gen, const char* reason, bool authorized)
{
    TraceLine("MENU_DETACH GEN=%llu REASON=%s AUTHORIZED=%s",
              static_cast<unsigned long long>(gen),
              reason ? reason : "?",
              authorized ? "TRUE" : "FALSE");
}

inline bool ReplaceMainMenu(HWND hwnd, HMENU candidate, const char* reason = "ReplaceMainMenu",
                            HMENU* retiredOut = nullptr)
{
    auto& st = State();
    if (retiredOut)
        *retiredOut = nullptr;
    if (!hwnd || !candidate || !IsMenu(candidate))
        return false;
    if (GetMenuItemCount(candidate) <= 0)
        return false;

    st.hwnd = hwnd;
    HMENU previousLive = GetMenu(hwnd);
    HMENU previousAuth = st.authoritativeMenu;
    const uint64_t oldGen = st.generation;

    if (!SetMenu(hwnd, candidate)) {
        if (previousLive && previousLive != candidate)
            SetMenu(hwnd, previousLive);
        DrawMenuBar(hwnd);
        TraceMenuState(hwnd, "REPLACE_SETMENU_FAILED");
        return false;
    }
    DrawMenuBar(hwnd);

    if (GetMenu(hwnd) != candidate) {
        SetMenu(hwnd, previousLive);
        DrawMenuBar(hwnd);
        TraceMenuState(hwnd, "REPLACE_VERIFY_FAILED");
        return false;
    }

    if (retiredOut)
        *retiredOut = previousLive;
    else if (previousLive && previousLive != candidate && previousLive != previousAuth &&
             IsMenu(previousLive)) {
        if (DestroyMenu(previousLive))
            TraceLine("MENU_DESTROY live=%p gen=%llu REASON=replace_retire_live",
                      static_cast<void*>(previousLive),
                      static_cast<unsigned long long>(st.generation));
    }

    st.authoritativeMenu = candidate;
    st.generation++;
    st.intentionallyDetached = false;

    TracePromote(previousAuth, candidate, oldGen, st.generation, reason);
    TraceMenuState(hwnd, "AFTER_REPLACE_MAIN_MENU");
    return true;
}

inline bool EnsureAttached(HWND hwnd, HMENU authorityHint = nullptr)
{
    auto& st = State();
    if (hwnd)
        st.hwnd = hwnd;

    HMENU auth = st.authoritativeMenu ? st.authoritativeMenu : authorityHint;
    if (!hwnd || !auth || !IsMenu(auth))
        return false;

    if (!st.authoritativeMenu)
        st.authoritativeMenu = auth;

    HMENU live = GetMenu(hwnd);

    if (st.windowDestroying)
        return true;

    if (st.intentionallyDetached) {
        if (live != nullptr) {
            TraceMenuViolation("DETACH_ACTIVE_BUT_LIVE_NONNULL", live, auth, st.generation);
            SetMenu(hwnd, nullptr);
            DrawMenuBar(hwnd);
        }
        return live == nullptr;
    }

    if (live != auth) {
        TraceMenuViolation("OUT_OF_AUTHORITY_MENU_MUTATION", live, auth, st.generation);
        if (SetMenu(hwnd, auth)) {
            DrawMenuBar(hwnd);
            live = GetMenu(hwnd);
            TraceMenuState(hwnd, "ENSURE_REPAIR_APPLIED");
        }
    }

    if (live == auth) {
        DrawMenuBar(hwnd);
        if (IsMenu(auth) && GetMenuItemCount(auth) > 0) {
            SetPropW(hwnd, L"RawrXD.MainMenuReady",
                     reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1)));
        }
        return true;
    }

    TraceMenuState(hwnd, "ENSURE_ATTACH_FAILED");
    return false;
}

inline bool IsStable(HWND hwnd, int samples = 3)
{
    if (!hwnd || !IsWindow(hwnd))
        return false;
    HMENU first = GetMenu(hwnd);
    if (!first || !IsMenu(first))
        return false;
    const int count = GetMenuItemCount(first);
    if (count <= 0)
        return false;
    for (int i = 1; i < samples; ++i) {
        HMENU now = GetMenu(hwnd);
        if (now != first || !IsMenu(now) || GetMenuItemCount(now) != count)
            return false;
    }
    return GetPropW(hwnd, L"RawrXD.MainMenuReady") != nullptr;
}

inline void DetachAuthorized(HWND hwnd, const char* reason)
{
    auto& st = State();
    if (hwnd)
        st.hwnd = hwnd;
    st.intentionallyDetached = true;
    RemovePropW(hwnd, L"RawrXD.MainMenuReady");
    SetMenu(hwnd, nullptr);
    DrawMenuBar(hwnd);
    TraceDetach(st.generation, reason, true);
    TraceMenuState(hwnd, "DETACH_AUTHORIZED");
}

inline void Reattach(HWND hwnd, HMENU authorityHint = nullptr)
{
    auto& st = State();
    st.intentionallyDetached = false;
    if (authorityHint && !st.authoritativeMenu)
        st.authoritativeMenu = authorityHint;
    EnsureAttached(hwnd, authorityHint);
    TraceMenuState(hwnd, "REATTACH");
}

inline void MarkWindowDestroying(HWND hwnd)
{
    auto& st = State();
    st.windowDestroying = true;
    TraceMenuState(hwnd, "WINDOW_DESTROYING");
}

}  // namespace RawrXD::MainMenuAuthority
