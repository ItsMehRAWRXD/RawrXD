/* ss_gguf_find.c — GGUF v3 named tensor absolute range (aligned data base) */
#include "ss_gguf_find.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef struct { char name[128]; uint64_t rel, d0, d1, elems; uint32_t ty, nd; } Ent;
static int rd(FILE *f, void *p, size_t n) { return fread(p, 1, n, f) == n ? 0 : 1; }
static int sk(FILE *f, int64_t n) { return _fseeki64(f, n, SEEK_CUR) ? 1 : 0; }
static int skip_str(FILE *f)
{
    uint64_t n; if (rd(f, &n, 8)) return 1; return sk(f, (int64_t)n);
}
static int rstr(FILE *f, char *buf, size_t cap)
{
    uint64_t n; if (rd(f, &n, 8) || n >= cap) return 1;
    if (n && rd(f, buf, (size_t)n)) return 1; buf[n] = 0; return 0;
}
static int skip_val(FILE *f, uint32_t *align_out)
{
    uint32_t t, at; uint64_t n, i;
    if (rd(f, &t, 4)) return 1;
    if (t <= 1) return sk(f, 1);
    if (t <= 3) return sk(f, 2);
    if (t <= 6) {
        if (t == 4 && align_out) {
            uint32_t v; if (rd(f, &v, 4)) return 1; *align_out = v; return 0;
        }
        return sk(f, 4);
    }
    if (t == 7) return sk(f, 1);
    if (t == 8) return skip_str(f);
    if (t == 10 || t == 11 || t == 12) return sk(f, 8);
    if (t != 9) return 1;
    if (rd(f, &at, 4) || rd(f, &n, 8)) return 1;
    if (at == 8) { for (i = 0; i < n; ++i) if (skip_str(f)) return 1; return 0; }
    {
        uint64_t sz = (at <= 1 || at == 7) ? 1 : (at <= 3 ? 2 : (at <= 6 ? 4 : 8));
        return sk(f, (int64_t)(n * sz));
    }
}
int ss_gguf_find(const char *path, const char *name, SsGgufTensor *out)
{
    FILE *f; uint32_t ver, i, nd, ty, align = 32; uint64_t nt, nk, off, dims[4], base, j;
    char key[256]; Ent *e = 0; int hit = -1;
    if (!path || !name || !out) return 1;
    memset(out, 0, sizeof *out);
    f = fopen(path, "rb"); if (!f) return 1;
    if (rd(f, key, 4) || memcmp(key, "GGUF", 4) || rd(f, &ver, 4)) goto bad;
    if (rd(f, &nt, 8) || rd(f, &nk, 8) || nt > 100000ull) goto bad;
    for (i = 0; i < (uint32_t)nk; ++i) {
        uint32_t *ap = 0;
        if (rstr(f, key, sizeof key)) goto bad;
        if (!strcmp(key, "general.alignment")) ap = &align;
        if (skip_val(f, ap)) goto bad;
    }
    e = (Ent *)calloc((size_t)nt, sizeof(Ent));
    if (!e) goto bad;
    for (i = 0; i < (uint32_t)nt; ++i) {
        uint64_t elems = 1;
        if (rstr(f, e[i].name, sizeof e[i].name) || rd(f, &nd, 4) || nd > 4) goto bad;
        for (j = 0; j < nd; ++j) { if (rd(f, &dims[j], 8)) goto bad; elems *= dims[j]; }
        if (rd(f, &ty, 4) || rd(f, &off, 8)) goto bad;
        e[i].nd = nd; e[i].ty = ty; e[i].rel = off; e[i].elems = elems;
        e[i].d0 = nd ? dims[0] : 0; e[i].d1 = nd > 1 ? dims[1] : 1;
        if (!strcmp(e[i].name, name)) hit = (int)i;
    }
    base = (uint64_t)_ftelli64(f);
    base = (base + (uint64_t)align - 1ull) & ~((uint64_t)align - 1ull);
    if (hit < 0) goto bad;
    out->found = 1; out->type = e[hit].ty; out->n_dims = e[hit].nd;
    out->dim0 = e[hit].d0; out->dim1 = e[hit].d1; out->elems = e[hit].elems;
    out->abs_off = base + e[hit].rel;
    {
        uint64_t best = ~(uint64_t)0; uint32_t k;
        for (k = 0; k < (uint32_t)nt; ++k)
            if (e[k].rel > e[hit].rel && e[k].rel < best) best = e[k].rel;
        out->bytes = (best != ~(uint64_t)0) ? (best - e[hit].rel) : 0;
    }
    free(e); fclose(f);
    return out->bytes ? 0 : 1;
bad:
    free(e); if (f) fclose(f); return 1;
}
