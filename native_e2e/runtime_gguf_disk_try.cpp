// runtime_gguf_disk_try.cpp — resolve requested model name to on-disk GGUF
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "runtime_gguf_disk_resolve.h"
#include "runtime_gguf_roots.h"

static int path_is_file(const char* p) {
    if (!p || !*p) return 0;
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES &&
           !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void stem_copy(const char* in, char* out, size_t cap) {
    if (!out || cap < 2) return;
    out[0] = 0;
    if (!in || !*in) return;
    const char* base = in;
    for (const char* q = in; *q; ++q)
        if (*q == '\\' || *q == '/') base = q + 1;
    strncpy_s(out, cap, base, _TRUNCATE);
    size_t n = strlen(out);
    if (n >= 5) {
        char* e = out + (n - 5);
        if (_stricmp(e, ".gguf") == 0) *e = 0;
    }
}

extern "C" uint32_t RawrNative_TryRegisterRuntimeGgufFromDisk(
    const char* model_name, RawrNativeProfileInfo* out_info)
{
    if (!model_name || !*model_name) return 1;
    if (path_is_file(model_name)) {
        return RawrNative_RegisterRuntimeGgufPathEx(
            model_name, model_name, out_info);
    }
    char stem[256]{};
    stem_copy(model_name, stem, sizeof(stem));
    char roots[16][MAX_PATH]{};
    int nroots = 0;
    RawrNative_CollectGgufRoots(roots, &nroots, 16);
    for (int i = 0; i < nroots; ++i) {
        char cand[MAX_PATH]{};
        _snprintf_s(cand, sizeof(cand), _TRUNCATE, "%s\\%s",
                    roots[i], model_name);
        if (RawrNative_RegisterRuntimeGgufPathEx(
                model_name, cand, out_info) == 0)
            return 0;
        if (!stem[0]) continue;
        _snprintf_s(cand, sizeof(cand), _TRUNCATE, "%s\\%s.gguf",
                    roots[i], stem);
        if (RawrNative_RegisterRuntimeGgufPathEx(
                model_name, cand, out_info) == 0)
            return 0;
        _snprintf_s(cand, sizeof(cand), _TRUNCATE, "%s\\%s",
                    roots[i], stem);
        if (RawrNative_RegisterRuntimeGgufPathEx(
                model_name, cand, out_info) == 0)
            return 0;
    }
    return 1;
}
