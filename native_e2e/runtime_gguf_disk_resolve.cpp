// runtime_gguf_disk_resolve.cpp — lazy GGUF runtime profile registration
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "runtime_gguf_disk_resolve.h"

extern "C" uint32_t RawrNative_RegisterRuntimeModel(
    const char* model_name, const RawrNativeProfileInfo* info);

static int path_is_file(const char* p) {
    if (!p || !*p) return 0;
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES &&
           !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static uint32_t path_size_mb(const char* p) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(p, GetFileExInfoStandard, &fad))
        return 0;
    ULARGE_INTEGER u;
    u.HighPart = fad.nFileSizeHigh;
    u.LowPart = fad.nFileSizeLow;
    return (uint32_t)(u.QuadPart / (1024ull * 1024ull));
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

static uint32_t stable_id(const char* name) {
    uint32_t h = 2166136261u;
    for (const char* p = name; p && *p; ++p) {
        h ^= (uint8_t)*p;
        h *= 16777619u;
    }
    return 9100u + (h % 800u);
}

static void fill_profile_from_path(
    const char* path, const char* key, RawrNativeProfileInfo* p)
{
    memset(p, 0, sizeof(*p));
    uint32_t mb = path_size_mb(path);
    p->profile_id = stable_id(key);
    p->engine_mode =
        RN_ENGINE_MODE_SAFEDECODE | RN_ENGINE_MODE_TENSORHOP;
    p->num_layers = 80;
    p->context_default = 8192;
    p->context_max = 32768;
    p->max_tokens = 512;
    p->tier = (mb >= 16000) ? 2u : 1u;
    p->quant_type = 1;
    p->ram_mb = mb ? mb : 4096;
    p->vram_mb = (mb > 8192) ? 8192u : (mb ? mb : 4096u);
}

static void register_aliases(
    const char* requested, const char* path, RawrNativeProfileInfo* p)
{
    char stem[256]{};
    char with_ext[280]{};
    stem_copy(requested, stem, sizeof(stem));
    if (!stem[0]) stem_copy(path, stem, sizeof(stem));
    fill_profile_from_path(path, stem[0] ? stem : requested, p);
    (void)RawrNative_RegisterRuntimeModel(requested, p);
    if (stem[0] && _stricmp(stem, requested) != 0)
        (void)RawrNative_RegisterRuntimeModel(stem, p);
    if (stem[0]) {
        _snprintf_s(with_ext, sizeof(with_ext), _TRUNCATE,
                    "%s.gguf", stem);
        if (_stricmp(with_ext, requested) != 0)
            (void)RawrNative_RegisterRuntimeModel(with_ext, p);
    }
}

extern "C" uint32_t RawrNative_RegisterRuntimeGgufPathEx(
    const char* model_name, const char* gguf_path,
    RawrNativeProfileInfo* out_info)
{
    if (!model_name || !*model_name || !gguf_path || !*gguf_path)
        return 1;
    if (!path_is_file(gguf_path)) return 1;
    RawrNativeProfileInfo p{};
    register_aliases(model_name, gguf_path, &p);
    if (out_info) *out_info = p;
    return 0;
}

extern "C" uint32_t RawrNative_RegisterRuntimeGgufPath(
    const char* model_name, const char* gguf_path)
{
    return RawrNative_RegisterRuntimeGgufPathEx(
        model_name, gguf_path, nullptr);
}
