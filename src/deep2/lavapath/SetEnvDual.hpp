#pragma once
/* Dual env arm: Win32 process block + CRT _environ (getenv-visible). */
#include <cstdlib>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace Deep2 {

inline bool SetEnv(const char* k, const char* v) {
    if (!k || !v) return false;
#ifdef _WIN32
    const bool os = SetEnvironmentVariableA(k, v) != FALSE;
    const bool crt = (_putenv_s(k, v) == 0);
    return os && crt;
#else
    return setenv(k, v, 1) == 0;
#endif
}

inline bool SetEnvIfUnset(const char* k, const char* v) {
    const char* cur = std::getenv(k);
    if (cur && *cur) return true;
    return SetEnv(k, v);
}

} // namespace Deep2
