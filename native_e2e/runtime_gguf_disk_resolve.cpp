// runtime_gguf_disk_resolve.cpp — GGUF metadata admission (no size invent)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "runtime_gguf_disk_resolve.h"
#include "runtime_gguf_meta.h"

extern "C" uint32_t RawrNative_RegisterRuntimeModelSrc(
    const char* model_name, const RawrNativeProfileInfo* info,
    const char* source);

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

/* 0=ok 3=malformed/unsupported KV (arch+ctx+layers absent). */
static uint32_t fill_from_meta(
    const char* path, const char* key, RawrNativeProfileInfo* p)
{
    memset(p, 0, sizeof(*p));
    RawrNativeGgufMeta meta{};
    if (RawrNative_ReadGgufMeta(path, &meta) != 0 || !meta.ok)
        return 3;
    if (!meta.architecture[0] && !meta.block_count &&
        !meta.context_length)
        return 3;
    uint32_t mb = path_size_mb(path);
    p->profile_id = stable_id(key);
    p->engine_mode =
        RN_ENGINE_MODE_SAFEDECODE | RN_ENGINE_MODE_TENSORHOP;
    p->num_layers = meta.block_count ? meta.block_count : 1u;
    p->context_default =
        meta.context_length ? meta.context_length : 2048u;
    p->context_max =
        meta.context_length ? meta.context_length : 8192u;
    p->max_tokens = 512;
    p->tier = (mb >= 16000) ? 2u : 1u;
    p->quant_type = meta.file_type ? meta.file_type : 1u;
    p->ram_mb = mb ? mb : 4096;
    p->vram_mb = (mb > 8192) ? 8192u : (mb ? mb : 4096u);
    return 0;
}

static uint32_t register_aliases(
    const char* requested, const char* path, RawrNativeProfileInfo* p)
{
    char stem[256]{};
    char with_ext[280]{};
    stem_copy(requested, stem, sizeof(stem));
    if (!stem[0]) stem_copy(path, stem, sizeof(stem));
    uint32_t rc = fill_from_meta(
        path, stem[0] ? stem : requested, p);
    if (rc != 0) return rc;
    (void)RawrNative_RegisterRuntimeModelSrc(
        requested, p, "model_metadata");
    if (stem[0] && _stricmp(stem, requested) != 0)
        (void)RawrNative_RegisterRuntimeModelSrc(
            stem, p, "model_metadata");
    if (stem[0]) {
        _snprintf_s(with_ext, sizeof(with_ext), _TRUNCATE,
                    "%s.gguf", stem);
        if (_stricmp(with_ext, requested) != 0)
            (void)RawrNative_RegisterRuntimeModelSrc(
                with_ext, p, "model_metadata");
    }
    return 0;
}

extern "C" uint32_t RawrNative_RegisterRuntimeGgufPathEx(
    const char* model_name, const char* gguf_path,
    RawrNativeProfileInfo* out_info)
{
    if (!model_name || !*model_name || !gguf_path || !*gguf_path)
        return 1;
    if (!path_is_file(gguf_path)) return 1;
    RawrNativeProfileInfo p{};
    uint32_t rc = register_aliases(model_name, gguf_path, &p);
    if (rc != 0) return rc;
    if (out_info) *out_info = p;
    return 0;
}

extern "C" uint32_t RawrNative_RegisterRuntimeGgufPath(
    const char* model_name, const char* gguf_path)
{
    return RawrNative_RegisterRuntimeGgufPathEx(
        model_name, gguf_path, nullptr);
}
