/* ss_q6k_oracle.c — CPU Q6_K row-0 decode oracle for output.weight (not logits) */
#include "ss_evidence.h"
#include "ss_gguf_find.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static int u8(const unsigned char *p, uint32_t o) { return p[o]; }
static float f16(uint32_t h)
{
    uint32_t s = (h >> 15) & 1u, e = (h >> 10) & 31u, m = h & 1023u, u;
    if (e == 0) { if (!m) return s ? -0.f : 0.f; e = 1; while (!(m & 0x400u)) { m <<= 1; e--; } m &= 1023u; }
    else if (e == 31) return s ? -1e30f : 1e30f;
    u = (s << 31) | ((e + 112u) << 23) | (m << 13);
    return *(float *)&u;
}
static int i8(int b) { return b >= 128 ? b - 256 : b; }
static int finf(float x) { return x == x && x <= 1e30f && x >= -1e30f; }
int ss_q6k_row_oracle(const char *shard)
{
    SsGgufTensor t; unsigned char *row = 0; uint32_t nblk, b, pass, l, n_ok = 0, n_nc = 0;
    float first = 0.f; int saw = 0; FILE *f;
    if (!shard) return 1;
    if (ss_gguf_find(shard, "output.weight", &t) || !t.found || t.type != 14) {
        printf("Q6K_ORACLE=NOT_RUN REASON=NO_OUTPUT_WEIGHT\n"); return 1;
    }
    if (t.dim0 != 7168ull || (t.dim0 % 256ull)) {
        printf("Q6K_ORACLE=FAIL BAD_GEOMETRY dim0=%llu\n", (unsigned long long)t.dim0); return 1;
    }
    nblk = (uint32_t)((t.dim0 + 255ull) / 256ull);
    row = (unsigned char *)malloc(nblk * 210u);
    if (!row) return 1;
    f = fopen(shard, "rb");
    if (!f || _fseeki64(f, (__int64)t.abs_off, SEEK_SET) || fread(row, 1, nblk * 210u, f) != nblk * 210u) {
        if (f) fclose(f); free(row);
        printf("Q6K_ORACLE=FAIL READ\n"); return 1;
    }
    fclose(f);
    ss_copy_add_host(nblk * 210ull);
    for (b = 0; b < nblk && b < 2u; ++b) {
        const unsigned char *blk = row + b * 210u;
        float d = f16((uint32_t)u8(blk, 208) | ((uint32_t)u8(blk, 209) << 8));
        if (!finf(d)) { free(row); printf("Q6K_ORACLE=FAIL NONFINITE_SCALE blk=%u\n", b); return 1; }
        for (pass = 0; pass < 2u; ++pass) {
            const unsigned char *ql = blk + pass * 64u;
            const unsigned char *qh = blk + 128u + pass * 32u;
            const unsigned char *sc = blk + 192u + pass * 8u;
            for (l = 0; l < 32u; ++l) {
                uint32_t is = l / 16u, qlA = u8(ql, l), qlB = u8(ql, l + 32u), qhv = u8(qh, l);
                int q1 = (int)((qlA & 15u) | ((qhv & 3u) << 4)) - 32;
                float v = d * (float)i8(u8(sc, is)) * (float)q1;
                if (!finf(v)) { free(row); printf("Q6K_ORACLE=FAIL NONFINITE idx=%u\n", n_ok); return 1; }
                if (!saw) { first = v; saw = 1; } else if (v != first) n_nc = 1;
                n_ok++;
                (void)qlB;
            }
        }
    }
    free(row);
    printf("Q6K_ORACLE=PASS ROW=0 COLS=%llu NBLK=%u SAMPLES=%u NONCONSTANT=%u\n",
           (unsigned long long)t.dim0, nblk, n_ok, n_nc);
    printf("Q6K_ORACLE_TENSOR ABS=%llu LEN=%llu TYPE=14 DIMS=%llu x %llu\n",
           (unsigned long long)t.abs_off, (unsigned long long)t.bytes,
           (unsigned long long)t.dim0, (unsigned long long)t.dim1);
    printf("Q6K_ORACLE_NOTE=decode_only NOT_LOGITS PROMOTE=0\n");
    return n_ok && n_nc ? 0 : 1;
}
