// runtime_gguf_roots.cpp — product model root collection (no Ollama client)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "runtime_gguf_roots.h"

static void push_root(char roots[][MAX_PATH], int* n, int cap, const char* r) {
    if (!r || !*r || !n || *n >= cap) return;
    DWORD a = GetFileAttributesA(r);
    if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY))
        return;
    for (int i = 0; i < *n; ++i)
        if (_stricmp(roots[i], r) == 0) return;
    strncpy_s(roots[*n], MAX_PATH, r, _TRUNCATE);
    ++(*n);
}

void RawrNative_CollectGgufRoots(char roots[][MAX_PATH], int* n, int cap) {
    if (!roots || !n || cap <= 0) return;
    *n = 0;
    char envbuf[2048]{};
    const char* keys[] = {"RAWRXD_MODELS", "OLLAMA_MODELS", nullptr};
    for (int k = 0; keys[k]; ++k) {
        DWORD m = GetEnvironmentVariableA(keys[k], envbuf, sizeof(envbuf));
        if (!m || m >= sizeof(envbuf)) continue;
        char* ctx = nullptr;
        for (char* tok = strtok_s(envbuf, ";", &ctx); tok;
             tok = strtok_s(nullptr, ";", &ctx))
            push_root(roots, n, cap, tok);
    }
    push_root(roots, n, cap, "F:\\OllamaModels");
    push_root(roots, n, cap, "G:\\OllamaModels");
    push_root(roots, n, cap, "D:\\OllamaModels");
    push_root(roots, n, cap, "C:\\OllamaModels");
    push_root(roots, n, cap, "D:\\models");
    push_root(roots, n, cap, "F:\\models");
    char exe[MAX_PATH]{};
    DWORD el = GetModuleFileNameA(nullptr, exe, MAX_PATH);
    if (el && el < MAX_PATH) {
        char* slash = strrchr(exe, '\\');
        if (slash) {
            *slash = 0;
            char mdir[MAX_PATH]{};
            _snprintf_s(mdir, sizeof(mdir), _TRUNCATE, "%s\\models", exe);
            push_root(roots, n, cap, mdir);
        }
    }
}
