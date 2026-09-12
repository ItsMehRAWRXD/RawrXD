/* ss_gguf_find.c — locate one named GGUF tensor's exact file range */
#include "ss_gguf_find.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int rd(FILE *f, void *p, size_t n)
{ return fread(p, 1, n, f) == n ? 0 : -1; }
static int sk(FILE *f, uint64_t n)
{ return _fseeki64(f, (__int64)n, SEEK_CUR) == 0 ? 0 : -1; }
static int skip_val(FILE *f, uint32_t t);
static int skip_arr(FILE *f)
{
    uint32_t et = 0; uint64_t n = 0, i;
    if (rd(f, &et, 4) || rd(f, &n, 8)) return -1;
    for (i = 0; i < n; i++) if (skip_val(f, et)) return -1;
    return 0;
}
static int skip_val(FILE *f, uint32_t t)
{
    static const uint8_t sz[13] = {1,1,2,2,4,4,4,1,0,0,8,8,8};
    uint64_t n;
    if (t > 12) return -1;
    if (t == 8) { if (rd(f, &n, 8)) return -1; return sk(f, n); }
    if (t == 9) return skip_arr(f);
    return sk(f, sz[t]);
}
static int kv_one(FILE *f, uint32_t *align, char *arch, size_t acap)
{
    uint64_t ln = 0, n = 0; uint32_t ty = 0; char kn[40];
    if (rd(f, &ln, 8)) return -1;
    if (ln >= sizeof kn) return sk(f, ln) || rd(f, &ty, 4) || skip_val(f, ty);
    memset(kn, 0, sizeof kn);
    if (rd(f, kn, (size_t)ln) || rd(f, &ty, 4)) return -1;
    if (!strcmp(kn, "general.alignment") && ty == 4) return rd(f, align, 4);
    if (!strcmp(kn, "general.architecture") && ty == 8) {
        if (rd(f, &n, 8)) return -1;
        if (n >= acap) {
            if (rd(f, arch, acap - 1)) return -1;
            return sk(f, n - (acap - 1));
        }
        return rd(f, arch, (size_t)n);
    }
    return skip_val(f, ty);
}

int ss_gguf_find(const char *path, const char *name, SsTensorHit *out)
{
    FILE *f; char mag[4]; uint32_t ver = 0, align = 32; uint64_t nt = 0, nk = 0, i;
    uint64_t hit_rel = 0, hit_ne = 1; uint32_t hit_ty = 0, hit_nd = 0, found = 0;
    uint64_t hit_dims[4] = {0,0,0,0};
    if (!path || !name || !out) return -1;
    memset(out, 0, sizeof *out);
    f = fopen(path, "rb"); if (!f) return -1;
    if (rd(f, mag, 4) || memcmp(mag, "GGUF", 4) || rd(f, &ver, 4)) { fclose(f); return -1; }
    if (rd(f, &nt, 8) || rd(f, &nk, 8)) { fclose(f); return -1; }
    for (i = 0; i < nk; i++)
        if (kv_one(f, &align, out->arch, sizeof out->arch)) { fclose(f); return -1; }
    if (!align) align = 32;
    for (i = 0; i < nt; i++) {
        uint64_t ln = 0, off = 0, ne = 1, dims[4] = {0}; uint32_t nd = 0, ty = 0, d;
        char nm[192];
        if (rd(f, &ln, 8) || ln >= sizeof nm) { fclose(f); return -1; }
        memset(nm, 0, sizeof nm);
        if (rd(f, nm, (size_t)ln) || rd(f, &nd, 4) || nd > 4) { fclose(f); return -1; }
        for (d = 0; d < nd; d++) {
            if (rd(f, &dims[d], 8)) { fclose(f); return -1; }
            if (dims[d] && ne < (UINT64_MAX / dims[d])) ne *= dims[d];
        }
        if (rd(f, &ty, 4) || rd(f, &off, 8)) { fclose(f); return -1; }
        if (!found && strcmp(nm, name) == 0) {
            found = 1; hit_rel = off; hit_ty = ty; hit_nd = nd; hit_ne = ne;
            memcpy(hit_dims, dims, sizeof dims);
        }
    }
    {
        long long pos = _ftelli64(f); uint64_t pad, data, al = align;
        if (pos < 0) { fclose(f); return -1; }
        pad = (al - ((uint64_t)pos % al)) % al;
        data = (uint64_t)pos + pad;
        fclose(f);
        if (!found) return -2;
        out->file_off = data + hit_rel;
        out->type = hit_ty; out->n_dims = hit_nd; out->found = 1;
        out->align = align;
        memcpy(out->dims, hit_dims, sizeof hit_dims);
        if (hit_ty == 12) out->nbytes = (hit_ne / 256ull) * 144ull;
        else if (hit_ty == 0) out->nbytes = hit_ne * 4ull;
        else if (hit_ty == 1) out->nbytes = hit_ne * 2ull;
        else out->nbytes = hit_ne;
        return 0;
    }
}
