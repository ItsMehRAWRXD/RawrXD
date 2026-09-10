// runtime_gguf_meta.cpp — lightweight GGUF header KV probe
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "runtime_gguf_meta.h"

enum { GGUF_MAGIC = 0x46554747u };

static int rd(HANDLE h, void* b, DWORD n) {
    DWORD g = 0;
    return ReadFile(h, b, n, &g, nullptr) && g == n;
}

static int rd_str(HANDLE h, char* out, size_t cap) {
    uint64_t n = 0;
    if (!rd(h, &n, 8) || n > 4096) return 0;
    if (out && cap) {
        size_t keep = (size_t)n < cap - 1 ? (size_t)n : cap - 1;
        if (keep && !rd(h, out, (DWORD)keep)) return 0;
        out[keep] = 0;
        if (n > keep) SetFilePointer(h, (LONG)(n - keep), nullptr, FILE_CURRENT);
    } else if (n) {
        SetFilePointer(h, (LONG)n, nullptr, FILE_CURRENT);
    }
    return 1;
}

static int ends_with(const char* s, const char* suf) {
    size_t n = strlen(s), m = strlen(suf);
    return n >= m && _stricmp(s + (n - m), suf) == 0;
}

static int skip_val(HANDLE h, uint32_t typ) {
    uint8_t tmp[8];
    if (typ <= 1 || typ == 7) return rd(h, tmp, 1);
    if (typ <= 3) return rd(h, tmp, 2);
    if (typ <= 6) return rd(h, tmp, 4);
    if (typ == 8) return rd_str(h, nullptr, 0);
    if (typ == 10 || typ == 11 || typ == 12) return rd(h, tmp, 8);
    if (typ == 9) {
        uint32_t at = 0; uint64_t an = 0;
        if (!rd(h, &at, 4) || !rd(h, &an, 8) || an > 1000000) return 0;
        for (uint64_t i = 0; i < an; ++i) {
            if (at == 8) { if (!rd_str(h, nullptr, 0)) return 0; }
            else if (!skip_val(h, at)) return 0;
        }
        return 1;
    }
    return 0;
}

extern "C" uint32_t RawrNative_ReadGgufMeta(
    const char* path, RawrNativeGgufMeta* out)
{
    if (!path || !*path || !out) return 1;
    memset(out, 0, sizeof(*out));
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 1;
    uint32_t magic = 0, ver = 0;
    uint64_t tc = 0, kc = 0;
    int ok = rd(h, &magic, 4) && magic == GGUF_MAGIC &&
             rd(h, &ver, 4) && rd(h, &tc, 8) && rd(h, &kc, 8) && kc <= 4096;
    for (uint64_t i = 0; ok && i < kc; ++i) {
        char key[128]{};
        uint32_t typ = 0;
        if (!rd_str(h, key, sizeof(key)) || !rd(h, &typ, 4)) { ok = 0; break; }
        if (typ == 8 && strcmp(key, "general.architecture") == 0) {
            if (!rd_str(h, out->architecture, sizeof(out->architecture)))
                ok = 0;
        } else if (typ == 4 || typ == 5 || typ == 10 || typ == 11) {
            uint64_t v = 0;
            if (typ == 4 || typ == 5) {
                uint32_t u = 0;
                if (!rd(h, &u, 4)) ok = 0; else v = u;
            } else {
                if (!rd(h, &v, 8)) ok = 0;
            }
            if (!ok) break;
            if (ends_with(key, "block_count") || ends_with(key, ".n_layer"))
                out->block_count = (uint32_t)v;
            else if (ends_with(key, "context_length") ||
                     ends_with(key, "max_position_embeddings"))
                out->context_length = (uint32_t)v;
            else if (strcmp(key, "general.file_type") == 0)
                out->file_type = (uint32_t)v;
        } else if (!skip_val(h, typ)) {
            ok = 0;
        }
    }
    CloseHandle(h);
    if (!ok) return 1;
    out->ok = (out->block_count || out->context_length || out->architecture[0])
                  ? 1u : 0u;
    return out->ok ? 0u : 1u;
}
