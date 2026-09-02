// Durable checkpoints for P1 CPUInferenceEngine::LoadModel localization.
// 0xC0000409 / __fastfail cannot be caught — last flushed stage is the signal.
#pragma once

#include <cstdio>
#include <cstring>
#include <windows.h>

namespace RawrXD::P1LoadCkpt {

inline const char* defaultPath()
{
    char buf[MAX_PATH] = {};
    if (GetEnvironmentVariableA("RAWRXD_EVIDENCE_ROOT", buf, (DWORD)sizeof(buf)) > 0)
    {
        static char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\P1_PRODUCT_RUNTIME_AUTHORITY_002\\p1_cpu_load_ckpt.txt", buf);
        return path;
    }
    return "F:\\~dev\\rawrxd\\build_p1pra_win32ide\\bin\\logs\\p1_cpu_load_ckpt.txt";
}

inline void ensureParentDir(const char* path)
{
    char dir[MAX_PATH];
    strncpy_s(dir, path, _TRUNCATE);
    char* slash = strrchr(dir, '\\');
    if (!slash)
        return;
    *slash = '\0';
    CreateDirectoryA(dir, nullptr);
}

inline void reset(const char* path = nullptr)
{
    const char* p = path ? path : defaultPath();
    ensureParentDir(p);
    HANDLE h = CreateFileA(p, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return;
    const char* hdr = "P1_CPU_LOAD_CKPT begin\n";
    DWORD w = 0;
    WriteFile(h, hdr, (DWORD)strlen(hdr), &w, nullptr);
    FlushFileBuffers(h);
    CloseHandle(h);
}

inline void emit(const char* stage, const char* detail = nullptr, const char* path = nullptr)
{
    if (!stage || !stage[0])
        return;
    const char* p = path ? path : defaultPath();
    ensureParentDir(p);

    char line[1024];
    SYSTEMTIME st{};
    GetLocalTime(&st);
    if (detail && detail[0])
        snprintf(line, sizeof(line), "%02u:%02u:%02u.%03u %s %s\n", st.wHour, st.wMinute, st.wSecond,
                 st.wMilliseconds, stage, detail);
    else
        snprintf(line, sizeof(line), "%02u:%02u:%02u.%03u %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 stage);

    HANDLE h = CreateFileA(p, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD w = 0;
        WriteFile(h, line, (DWORD)strlen(line), &w, nullptr);
        FlushFileBuffers(h);
        CloseHandle(h);
    }

    fputs(line, stdout);
    fflush(stdout);
    OutputDebugStringA(line);
}

}  // namespace RawrXD::P1LoadCkpt
