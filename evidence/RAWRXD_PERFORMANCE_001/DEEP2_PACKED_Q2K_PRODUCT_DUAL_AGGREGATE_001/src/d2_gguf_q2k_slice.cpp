/* d2_gguf_q2k_slice.cpp — map first Q2_K matrix (GGUF v3 aligned data base) */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

struct D2Q2kSlice {
    const uint8_t* data; uint64_t bytes; uint32_t rows, cols; HANDLE map; void* view;
};

static uint64_t rd64(const uint8_t* p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint32_t rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }

static int skip_val(const uint8_t** pp, const uint8_t* end, uint32_t t, uint32_t* align) {
    const uint8_t* p = *pp;
    if (t <= 1 || t == 7) { if (p + 1 > end) return 0; p += 1; }
    else if (t <= 3) { if (p + 2 > end) return 0; p += 2; }
    else if (t <= 6) {
        if (p + 4 > end) return 0;
        if (t == 4 && align) *align = rd32(p);
        p += 4;
    } else if (t == 8) {
        if (p + 8 > end) return 0; uint64_t n = rd64(p); p += 8;
        if (p + n > end) return 0; p += n;
    } else if (t == 9) {
        if (p + 12 > end) return 0;
        uint32_t at = rd32(p); p += 4; uint64_t n = rd64(p); p += 8;
        if (at == 8) {
            for (uint64_t i = 0; i < n; ++i) {
                if (p + 8 > end) return 0; uint64_t sn = rd64(p); p += 8;
                if (p + sn > end) return 0; p += sn;
            }
        } else {
            uint64_t es = (at <= 1 || at == 7) ? 1 : (at <= 3 ? 2 : (at <= 6 ? 4 : 8));
            if (p + n * es > end) return 0; p += n * es;
        }
    } else if (t <= 12) { if (p + 8 > end) return 0; p += 8; }
    else return 0;
    *pp = p; return 1;
}

extern "C" int d2_gguf_load_q2k_matrix(const char* path, D2Q2kSlice* out) {
    if (!path || !out) return 0; memset(out, 0, sizeof *out);
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) { printf("GGUF_OPEN=FAIL\n"); return 0; }
    LARGE_INTEGER sz; GetFileSizeEx(f, &sz);
    HANDLE m = CreateFileMappingA(f, 0, PAGE_READONLY, 0, 0, 0); CloseHandle(f);
    if (!m) return 0;
    const uint8_t* base = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(m); return 0; }
    if (sz.QuadPart < 24 || memcmp(base, "GGUF", 4)) goto fail;
    const uint8_t* p = base + 8;
    const uint8_t* end = base + (size_t)sz.QuadPart;
    uint64_t n_tensors = rd64(p); p += 8; uint64_t n_kv = rd64(p); p += 8;
    uint32_t align = 32;
    for (uint64_t i = 0; i < n_kv; ++i) {
        if (p + 8 > end) goto fail;
        uint64_t nl = rd64(p); p += 8; if (p + nl + 4 > end) goto fail;
        int is_align = (nl == 17 && memcmp(p, "general.alignment", 17) == 0);
        p += nl; uint32_t t = rd32(p); p += 4;
        if (!skip_val(&p, end, t, is_align ? &align : 0)) goto fail;
    }
    int hit = -1; uint64_t hit_off = 0, hit_d0 = 0, hit_d1 = 0, hit_bytes_est = 0;
    uint64_t* rel = (uint64_t*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n_tensors * 8);
    uint32_t* r0a = (uint32_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)n_tensors * 4);
    uint32_t* r1a = (uint32_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)n_tensors * 4);
    uint32_t* tya = (uint32_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)n_tensors * 4);
    if (!rel || !r0a || !r1a || !tya) {
        if (rel) HeapFree(GetProcessHeap(), 0, rel);
        if (r0a) HeapFree(GetProcessHeap(), 0, r0a);
        if (r1a) HeapFree(GetProcessHeap(), 0, r1a);
        if (tya) HeapFree(GetProcessHeap(), 0, tya);
        goto fail;
    }
    for (uint64_t ti = 0; ti < n_tensors; ++ti) {
        if (p + 8 > end) { HeapFree(GetProcessHeap(),0,rel); HeapFree(GetProcessHeap(),0,r0a); HeapFree(GetProcessHeap(),0,r1a); HeapFree(GetProcessHeap(),0,tya); goto fail; }
        uint64_t nl = rd64(p); p += 8; if (p + nl > end) { HeapFree(GetProcessHeap(),0,rel); HeapFree(GetProcessHeap(),0,r0a); HeapFree(GetProcessHeap(),0,r1a); HeapFree(GetProcessHeap(),0,tya); goto fail; }
        p += nl;
        if (p + 4 > end) { HeapFree(GetProcessHeap(),0,rel); HeapFree(GetProcessHeap(),0,r0a); HeapFree(GetProcessHeap(),0,r1a); HeapFree(GetProcessHeap(),0,tya); goto fail; }
        uint32_t nd = rd32(p); p += 4;
        if (nd < 1 || nd > 4 || p + 8ull * nd + 12 > end) { HeapFree(GetProcessHeap(),0,rel); HeapFree(GetProcessHeap(),0,r0a); HeapFree(GetProcessHeap(),0,r1a); HeapFree(GetProcessHeap(),0,tya); goto fail; }
        uint64_t dims[4] = {1,1,1,1};
        for (uint32_t d = 0; d < nd; ++d) dims[d] = rd64(p + 8ull * d);
        p += 8ull * nd;
        uint32_t typ = rd32(p); p += 4; uint64_t off = rd64(p); p += 8;
        rel[ti] = off; tya[ti] = typ; r0a[ti] = (uint32_t)dims[0]; r1a[ti] = nd > 1 ? (uint32_t)dims[1] : 1;
    }
    for (uint64_t ti = 0; ti < n_tensors; ++ti) {
        if (tya[ti] != 10 || r1a[ti] < 2) continue;
        uint64_t nblk = ((uint64_t)r0a[ti] + 255) / 256;
        uint64_t est = (uint64_t)r1a[ti] * nblk * 84ull;
        if (est > hit_bytes_est) {
            hit = (int)ti; hit_off = rel[ti]; hit_d0 = r0a[ti]; hit_d1 = r1a[ti]; hit_bytes_est = est;
        }
    }
    HeapFree(GetProcessHeap(), 0, r0a); HeapFree(GetProcessHeap(), 0, r1a); HeapFree(GetProcessHeap(), 0, tya);
    if (hit < 0) { HeapFree(GetProcessHeap(), 0, rel); printf("GGUF_NO_Q2K\n"); goto fail; }
    uint64_t data_base = (uint64_t)(p - base);
    data_base = (data_base + align - 1) & ~((uint64_t)align - 1);
    uint64_t best = ~(uint64_t)0;
    for (uint64_t k = 0; k < n_tensors; ++k)
        if (rel[k] > hit_off && rel[k] < best) best = rel[k];
    HeapFree(GetProcessHeap(), 0, rel);
    uint32_t cols = (uint32_t)hit_d0, rows = (uint32_t)hit_d1;
    uint64_t nblk = ((uint64_t)cols + 255) / 256;
    uint64_t bytes = (best != ~(uint64_t)0) ? (best - hit_off) : ((uint64_t)rows * nblk * 84ull);
    if (data_base + hit_off + bytes > (uint64_t)sz.QuadPart) goto fail;
    out->rows = rows; out->cols = cols; out->bytes = bytes;
    out->data = base + data_base + hit_off;
    out->map = m; out->view = (void*)base;
    printf("GGUF_Q2K_LOAD=PASS align=%u rows=%u cols=%u bytes=%llu\n",
           align, rows, cols, (unsigned long long)bytes);
    return 1;
fail:
    UnmapViewOfFile(base); CloseHandle(m); memset(out, 0, sizeof *out); return 0;
}

extern "C" void d2_gguf_unload_q2k(D2Q2kSlice* s) {
    if (!s) return;
    if (s->view) UnmapViewOfFile(s->view);
    if (s->map) CloseHandle(s->map);
    memset(s, 0, sizeof *s);
}
