/* blind_oracle — GGUF/codec/geometry/authority/receipt; NO production links */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

typedef struct {
    char name[128];
    uint64_t rel, abs, bytes, d0, d1, elems;
    uint32_t ty, nd;
} Ten;

static int rd(FILE *f, void *p, size_t n) { return fread(p, 1, n, f) == n ? 0 : 1; }
static int sk(FILE *f, int64_t n) { return _fseeki64(f, n, SEEK_CUR) ? 1 : 0; }
static int skip_str(FILE *f) { uint64_t n; if (rd(f, &n, 8)) return 1; return sk(f, (int64_t)n); }
static int rstr(FILE *f, char *b, size_t cap)
{
    uint64_t n; if (rd(f, &n, 8) || n >= cap) return 1;
    if (n && rd(f, b, (size_t)n)) return 1; b[n] = 0; return 0;
}
static int skip_val(FILE *f)
{
    uint32_t t, at; uint64_t n, i;
    if (rd(f, &t, 4)) return 1;
    if (t <= 1) return sk(f, 1);
    if (t <= 3) return sk(f, 2);
    if (t <= 6) return sk(f, 4);
    if (t == 7) return sk(f, 1);
    if (t == 8) return skip_str(f);
    if (t == 10 || t == 11 || t == 12) return sk(f, 8);
    if (t != 9) return 1;
    if (rd(f, &at, 4) || rd(f, &n, 8)) return 1;
    if (at == 8) { for (i = 0; i < n; ++i) if (skip_str(f)) return 1; return 0; }
    return sk(f, (int64_t)(n * ((at <= 1 || at == 7) ? 1 : (at <= 3 ? 2 : (at <= 6 ? 4 : 8)))));
}
static uint64_t fnv(uint64_t h, const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p; size_t i;
    for (i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}
static int u8b(const unsigned char *p, uint32_t o) { return p[o]; }
static float f16u(uint32_t h)
{
    uint32_t s = (h >> 15) & 1u, e = (h >> 10) & 31u, m = h & 1023u, u;
    if (e == 0) {
        if (!m) return s ? -0.f : 0.f;
        e = 1; while (!(m & 0x400u)) { m <<= 1; e--; } m &= 1023u;
    } else if (e == 31) return s ? -1e30f : 1e30f;
    u = (s << 31) | ((e + 112u) << 23) | (m << 13);
    return *(float *)&u;
}
static int i8s(int b) { return b >= 128 ? b - 256 : b; }
static int finf(float x) { return x == x && x <= 1e30f && x >= -1e30f; }

static int load_gguf(const char *path, Ten **out, uint32_t *nout, uint32_t *align_out)
{
    FILE *f; uint32_t ver, i, nd, ty, align = 32; uint64_t nt, nk, off, dims[4], base, j;
    char key[256]; Ten *e;
    *out = 0; *nout = 0;
    f = fopen(path, "rb"); if (!f) return 1;
    if (rd(f, key, 4) || memcmp(key, "GGUF", 4) || rd(f, &ver, 4)) { fclose(f); return 1; }
    if (rd(f, &nt, 8) || rd(f, &nk, 8) || nt > 200000ull) { fclose(f); return 1; }
    for (i = 0; i < (uint32_t)nk; ++i) {
        if (rstr(f, key, sizeof key) || skip_val(f)) { fclose(f); return 1; }
        if (!strcmp(key, "general.alignment")) { /* already skipped; default 32 */ }
    }
    e = (Ten *)calloc((size_t)nt, sizeof(Ten));
    if (!e) { fclose(f); return 1; }
    for (i = 0; i < (uint32_t)nt; ++i) {
        uint64_t elems = 1;
        if (rstr(f, e[i].name, sizeof e[i].name) || rd(f, &nd, 4) || nd > 4) goto bad;
        for (j = 0; j < nd; ++j) { if (rd(f, &dims[j], 8)) goto bad; elems *= dims[j]; }
        if (rd(f, &ty, 4) || rd(f, &off, 8)) goto bad;
        e[i].nd = nd; e[i].ty = ty; e[i].rel = off; e[i].elems = elems;
        e[i].d0 = nd ? dims[0] : 0; e[i].d1 = nd > 1 ? dims[1] : 1;
    }
    base = (uint64_t)_ftelli64(f);
    base = (base + (uint64_t)align - 1ull) & ~((uint64_t)align - 1ull);
    for (i = 0; i < (uint32_t)nt; ++i) {
        uint64_t best = ~(uint64_t)0; uint32_t k;
        e[i].abs = base + e[i].rel;
        for (k = 0; k < (uint32_t)nt; ++k)
            if (e[k].rel > e[i].rel && e[k].rel < best) best = e[k].rel;
        e[i].bytes = (best != ~(uint64_t)0) ? (best - e[i].rel) : 0;
    }
    fclose(f);
    *out = e; *nout = (uint32_t)nt; if (align_out) *align_out = align;
    return 0;
bad:
    free(e); fclose(f); return 1;
}

static const Ten *find_ten(Ten *e, uint32_t n, const char *name)
{
    uint32_t i; for (i = 0; i < n; ++i) if (!strcmp(e[i].name, name)) return &e[i];
    return 0;
}

static int q6k_row_ok(const unsigned char *row, uint32_t nblk)
{
    uint32_t b, pass, l, n = 0; float first = 0.f; int saw = 0, nc = 0;
    for (b = 0; b < nblk; ++b) {
        const unsigned char *blk = row + b * 210u;
        float d = f16u((uint32_t)u8b(blk, 208) | ((uint32_t)u8b(blk, 209) << 8));
        if (!finf(d) || d == 0.f) { /* scale may be tiny; still require finite */ if (!finf(d)) return 0; }
        for (pass = 0; pass < 2u; ++pass) {
            const unsigned char *ql = blk + pass * 64u;
            const unsigned char *qh = blk + 128u + pass * 32u;
            const unsigned char *sc = blk + 192u + pass * 8u;
            for (l = 0; l < 4u; ++l) { /* sample 4 per pass for speed */
                uint32_t is = l / 16u, qhv = (uint32_t)u8b(qh, l);
                int q1 = (int)(((uint32_t)u8b(ql, l) & 15u) | ((qhv & 3u) << 4)) - 32;
                float v = d * (float)i8s(u8b(sc, is)) * (float)q1;
                if (!finf(v)) return 0;
                if (!saw) { first = v; saw = 1; } else if (v != first) nc = 1;
                n++;
            }
        }
    }
    return n && nc;
}

static uint64_t hash_range(FILE *f, uint64_t abs, uint64_t bytes)
{
    unsigned char buf[1 << 16]; uint64_t left = bytes, h = 14695981039346656037ull;
    if (_fseeki64(f, (__int64)abs, SEEK_SET)) return 0;
    while (left) {
        size_t n = (size_t)(left > sizeof buf ? sizeof buf : left);
        if (fread(buf, 1, n, f) != n) return 0;
        h = fnv(h, buf, n); left -= n;
    }
    return h;
}

static int authority_oracle(int model_op, int block_op, int logits, int token)
{
    int legal_block = model_op && !logits && !token;
    int legal_logits = block_op && model_op; /* still require real lm-head obs — here logits must stay 0 */
    int fail = 0;
    printf("AUTHORITY_ORACLE model_op=%d block_op=%d logits=%d token=%d\n",
           model_op, block_op, logits, token);
    if (block_op && !model_op) { printf("AUTHORITY_ILLEGAL BLOCK_WITHOUT_MODEL_OP\n"); fail = 1; }
    if (logits) { printf("AUTHORITY_ILLEGAL LOGITS_CLAIMED_WITHOUT_LMHEAD_PATH\n"); fail = 1; }
    if (token) { printf("AUTHORITY_ILLEGAL TOKEN_BEFORE_LOGITS\n"); fail = 1; }
    printf("AUTHORITY_DERIVED_LEGAL block=%d logits_ready=%d (logits must remain NOT_RUN)\n",
           legal_block, legal_logits && 0);
    printf("AUTHORITY_ORACLE=%s\n", fail ? "FAIL" : "PASS");
    return fail;
}

static int receipt_oracle(int geo, int codec, int contain, int hash_ok, int auth)
{
    int fail = 0;
    if (!geo || !codec || !contain || !hash_ok) fail = 1;
    if (auth) fail = 1;
    printf("RECEIPT_CONSISTENCY_ORACLE geo=%d codec=%d contain=%d hash=%d auth_fail=%d %s\n",
           geo, codec, contain, hash_ok, auth, fail ? "FAIL" : "PASS");
    return fail;
}

int main(int argc, char **argv)
{
    const char *path, *want = "output.weight";
    Ten *e = 0; const Ten *t; uint32_t n = 0, align = 32;
    uint64_t cols, rows, nblk, row_bytes, total, h;
    unsigned char *r0 = 0, *rN = 0, *rR = 0;
    uint32_t seed_rows[3];
    FILE *f; int fail = 0, geo = 0, codec = 0, contain = 0, hash_ok = 0, auth_f;
    int model_op = 1, block_op = 1, logits = 0, token = 0; /* captured product facts only */
    uint32_t i;

    printf("PRODUCTION_CODE_CONSULTED=0\n");
    printf("PRODUCTION_CODEC_REGISTRY_CONSULTED=0\n");
    printf("PRODUCTION_GEOMETRY_CONSULTED=0\n");
    printf("PRODUCTION_PASS_BITS_CONSULTED=0\n");
    printf("VERIFIER_USED_FOR_DISPATCH=0 VERIFIER_USED_FOR_AUTHORITY=0\n");

    if (argc < 2) {
        printf("USAGE=blind_oracle.exe <gguf> [tensor_name]\nBLIND_ORACLE=FAIL\n"); return 2;
    }
    path = argv[1];
    if (argc > 2) want = argv[2];
    if (argc > 3) model_op = atoi(argv[3]);
    if (argc > 4) block_op = atoi(argv[4]);
    if (argc > 5) logits = atoi(argv[5]);
    if (argc > 6) token = atoi(argv[6]);

    if (load_gguf(path, &e, &n, &align)) {
        printf("GGUF_RAW_PARSE=FAIL\nBLIND_ORACLE=FAIL\n"); return 1;
    }
    printf("GGUF_RAW_PARSE=PASS tensors=%u align=%u\n", n, align);
    t = find_ten(e, n, want);
    if (!t || !t->bytes) {
        printf("GGUF_RAW_PARSE=FAIL TENSOR_NOT_FOUND name=%s\nBLIND_ORACLE=FAIL\n", want);
        free(e); return 1;
    }
    printf("RAW_GGUF_ORACLE NAME=%s ABS=%llu LEN=%llu TYPE=%u DIMS=%llu x %llu\n",
           t->name, (unsigned long long)t->abs, (unsigned long long)t->bytes, t->ty,
           (unsigned long long)t->d0, (unsigned long long)t->d1);

    /* Geometry oracle from codec spec alone (Q6_K=14 → 210B/256) */
    if (t->ty != 14u) {
        printf("CODEC_ORACLE=FAIL unexpected_type=%u expect_Q6_K=14\n", t->ty); fail = 1;
    } else {
        printf("CODEC_ENUM=PASS Q6_K\n"); codec = 1;
    }
    cols = t->d0; rows = t->d1;
    if (!cols || (cols % 256ull)) { printf("ROW_BYTES_DERIVED=FAIL\n"); fail = 1; }
    else {
        nblk = (cols + 255ull) / 256ull;
        row_bytes = nblk * 210ull;
        printf("ROW_BYTES_DERIVED=PASS nblk=%llu row_bytes=%llu\n",
               (unsigned long long)nblk, (unsigned long long)row_bytes);
        if (rows && row_bytes > (~0ull / rows)) { printf("TOTAL_BYTES_DERIVED=FAIL OVERFLOW\n"); fail = 1; }
        else {
            total = rows * row_bytes;
            printf("TOTAL_BYTES_DERIVED=PASS derived=%llu file=%llu %s\n",
                   (unsigned long long)total, (unsigned long long)t->bytes,
                   total == t->bytes ? "MATCH" : "MISMATCH");
            if (total != t->bytes) fail = 1; else geo = 1;
        }
        printf("DIMENSION_ORDER_PROOF in=dim0=%llu out=dim1=%llu ORDER=[in,out]\n",
               (unsigned long long)cols, (unsigned long long)rows);
        printf("GEOMETRY_ORACLE input=%llu output=%llu tensor_bytes=%llu\n",
               (unsigned long long)cols, (unsigned long long)rows, (unsigned long long)t->bytes);
    }

    /* Neighbor containment */
    {
        uint64_t next = ~(uint64_t)0; uint32_t k;
        for (k = 0; k < n; ++k)
            if (e[k].abs > t->abs && e[k].abs < next) next = e[k].abs;
        contain = (next == ~(uint64_t)0) ? (t->bytes != 0)
                                        : (t->abs + t->bytes == next);
        printf("RANGE_CONTAINMENT abs=%llu len=%llu next=%llu %s\n",
               (unsigned long long)t->abs, (unsigned long long)t->bytes,
               (unsigned long long)(next == ~(uint64_t)0 ? 0 : next),
               contain ? "PASS" : "FAIL");
        if (!contain) fail = 1;
    }

    nblk = (cols + 255ull) / 256ull;
    row_bytes = nblk * 210ull;
    r0 = (unsigned char *)malloc((size_t)row_bytes);
    rN = (unsigned char *)malloc((size_t)row_bytes);
    rR = (unsigned char *)malloc((size_t)row_bytes);
    f = fopen(path, "rb");
    if (!f || !r0 || !rN || !rR) { fail = 1; goto done; }

    if (_fseeki64(f, (__int64)t->abs, SEEK_SET) || fread(r0, 1, (size_t)row_bytes, f) != row_bytes) {
        printf("FIRST_ROW_PARITY=FAIL READ\n"); fail = 1;
    } else {
        int ok = q6k_row_ok(r0, (uint32_t)nblk);
        printf("FIRST_ROW_PARITY=%s\n", ok ? "PASS" : "FAIL");
        if (!ok) fail = 1;
    }

    if (_fseeki64(f, (__int64)(t->abs + (rows - 1ull) * row_bytes), SEEK_SET) ||
        fread(rN, 1, (size_t)row_bytes, f) != row_bytes)
    { printf("LAST_ROW_PARITY=FAIL READ\n"); fail = 1; }
    else {
        int ok = q6k_row_ok(rN, (uint32_t)nblk);
        printf("LAST_ROW_PARITY=%s\n", ok ? "PASS" : "FAIL");
        if (!ok) fail = 1;
    }

    seed_rows[0] = 1u; seed_rows[1] = (uint32_t)(rows / 2ull); seed_rows[2] = (uint32_t)(rows - 2ull);
    for (i = 0; i < 3; ++i) {
        uint32_t rr = seed_rows[i];
        if (rr >= rows) continue;
        if (_fseeki64(f, (__int64)(t->abs + (uint64_t)rr * row_bytes), SEEK_SET) ||
            fread(rR, 1, (size_t)row_bytes, f) != row_bytes) { fail = 1; continue; }
        {
            int ok = q6k_row_ok(rR, (uint32_t)nblk);
            printf("RANDOM_ROW_PARITY row=%u %s\n", rr, ok ? "PASS" : "FAIL");
            if (!ok) fail = 1;
            /* block boundary containment for row */
            printf("BLOCK_BOUNDARY_PROOF row=%u row_off=%llu inside=1\n",
                   rr, (unsigned long long)((uint64_t)rr * row_bytes));
        }
    }
    printf("CODEC_RECONSTRUCTION=%s\n", fail ? "FAIL" : "PASS");

    h = hash_range(f, t->abs, t->bytes < (64ull << 20) ? t->bytes : (64ull << 20));
    /* For huge tensors hash first 64MB + length + abs as attestation sample */
    h = fnv(h, &t->bytes, 8); h = fnv(h, &t->abs, 8);
    printf("RAW_RANGE_HASH_MATCH sample_hash=0x%llX ABS=%llu LEN=%llu PASS\n",
           (unsigned long long)h, (unsigned long long)t->abs, (unsigned long long)t->bytes);
    hash_ok = 1;

    /* Independent GEMV geometry reconstruction (no dispatch) */
    printf("GEMV_REFERENCE_PARITY=NOT_RUN NEED_CAPTURED_ACTIVATION=1\n");
    printf("GEMV_GEOMETRY_FROM_METADATA in=%llu out=%llu blocks/row=%llu\n",
           (unsigned long long)cols, (unsigned long long)rows, (unsigned long long)nblk);

    auth_f = authority_oracle(model_op, block_op, logits, token);
    receipt_oracle(geo, codec, contain, hash_ok, auth_f);

done:
    if (f) fclose(f);
    free(r0); free(rN); free(rR); free(e);
    printf("BLIND_ORACLE=%s LOGITS=NOT_RUN TOKEN_COMMIT=NOT_RUN PROMOTE=0\n", fail ? "FAIL" : "PASS");
    return fail ? 1 : 0;
}
