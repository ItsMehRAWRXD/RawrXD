// P1 Scenario 2 — Win32IDE product-path GGUF load cert sink.
// Writes exe-local logs/p1_gguf_load_cert.txt (key=PASS|FAIL|INFO detail).
// Not a loader harness: only records outcomes of the real IDE load path.
#pragma once

#include <cstdio>
#include <cstring>
#include <windows.h>

namespace RawrXD::P1GgufCert {

inline bool certFilePath(char* out, DWORD outChars)
{
    if (!out || outChars < 32)
        return false;
    DWORD n = GetModuleFileNameA(nullptr, out, outChars);
    if (n == 0 || n >= outChars)
        return false;
    char* slash = strrchr(out, '\\');
    if (!slash)
        return false;
    slash[1] = '\0';
    if (strlen(out) + 32 >= outChars)
        return false;
    strcat_s(out, outChars, "logs\\p1_gguf_load_cert.txt");
    return true;
}

inline void ensureLogsDir()
{
    char dir[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(nullptr, dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return;
    char* slash = strrchr(dir, '\\');
    if (!slash)
        return;
    slash[1] = '\0';
    strcat_s(dir, "logs");
    CreateDirectoryA(dir, nullptr);
}

inline void reset()
{
    ensureLogsDir();
    char path[MAX_PATH] = {};
    if (!certFilePath(path, MAX_PATH))
        return;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "w") == 0 && f)
    {
        fprintf(f, "P1_GGUF_LOAD_CERT begin\n");
        fclose(f);
    }
}

inline void emit(const char* key, const char* status, const char* detail = nullptr)
{
    if (!key || !status)
        return;
    ensureLogsDir();
    char path[MAX_PATH] = {};
    if (!certFilePath(path, MAX_PATH))
        return;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") != 0 || !f)
        return;
    fprintf(f, "%s=%s", key, status);
    if (detail && detail[0])
        fprintf(f, " %s", detail);
    fprintf(f, "\n");
    fflush(f);
    fclose(f);

    char dbg[512];
    if (detail && detail[0])
        snprintf(dbg, sizeof(dbg), "[P1_GGUF] %s=%s %s\n", key, status, detail);
    else
        snprintf(dbg, sizeof(dbg), "[P1_GGUF] %s=%s\n", key, status);
    OutputDebugStringA(dbg);
}

}  // namespace RawrXD::P1GgufCert
