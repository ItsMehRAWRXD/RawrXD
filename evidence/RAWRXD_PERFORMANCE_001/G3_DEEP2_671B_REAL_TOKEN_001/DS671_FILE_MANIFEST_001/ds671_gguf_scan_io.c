/* ds671_gguf_scan_io.c */
#include "ds671_gguf_scan_priv.h"

int gr_open(GgufR *r, const char *path) {
    LARGE_INTEGER li;
    r->h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (r->h == INVALID_HANDLE_VALUE) return GGUF_E_IO;
    if (!GetFileSizeEx(r->h, &li)) { CloseHandle(r->h); return GGUF_E_IO; }
    r->size = (uint64_t)li.QuadPart; r->pos = 0; return GGUF_OK;
}
void gr_close(GgufR *r) {
    if (r->h && r->h != INVALID_HANDLE_VALUE) CloseHandle(r->h);
}
int gr_read(GgufR *r, void *dst, uint64_t n) {
    uint8_t *p = (uint8_t *)dst;
    while (n) {
        DWORD chunk = (n > 0x40000000ull) ? 0x40000000u : (DWORD)n, got = 0;
        if (!ReadFile(r->h, p, chunk, &got, 0) || got != chunk) return GGUF_E_IO;
        p += got; n -= got; r->pos += got;
    }
    return GGUF_OK;
}
int gr_skip(GgufR *r, uint64_t n) {
    LARGE_INTEGER off, neu;
    if (r->pos + n > r->size) return GGUF_E_BOUND;
    off.QuadPart = (LONGLONG)n;
    if (!SetFilePointerEx(r->h, off, &neu, FILE_CURRENT)) return GGUF_E_IO;
    r->pos += n; return GGUF_OK;
}
int gr_u32(GgufR *r, uint32_t *v) { return gr_read(r, v, 4); }
int gr_u64(GgufR *r, uint64_t *v) { return gr_read(r, v, 8); }
int gr_str(GgufR *r, char *buf, size_t cap) {
    uint64_t len = 0;
    if (gr_u64(r, &len)) return GGUF_E_IO;
    if (len > 0x100000ull) return GGUF_E_FMT;
    if (buf && cap) {
        size_t keep = (len + 1 < cap) ? (size_t)len : cap - 1;
        if (keep && gr_read(r, buf, keep)) return GGUF_E_IO;
        buf[keep] = 0;
        if (len > keep && gr_skip(r, len - keep)) return GGUF_E_IO;
    } else if (gr_skip(r, len)) return GGUF_E_IO;
    return GGUF_OK;
}
