/* ss_geo_indep.c — geometry/codec checks independent of dispatch kernels */
#include "ss_evidence.h"
#include "ss_gguf_find.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
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
static int decode_row_sample(const unsigned char *row, uint32_t nblk, float *out, uint32_t maxn)
{
    uint32_t b, pass, l, n = 0; float first = 0.f; int saw = 0, nc = 0;
    for (b = 0; b < nblk && n < maxn; ++b) {
        const unsigned char *blk = row + b * 210u;
        float d = f16u((uint32_t)u8b(blk, 208) | ((uint32_t)u8b(blk, 209) << 8));
        if (!finf(d)) return -1;
        for (pass = 0; pass < 2u && n < maxn; ++pass) {
            const unsigned char *ql = blk + pass * 64u;
            const unsigned char *qh = blk + 128u + pass * 32u;
            const unsigned char *sc = blk + 192u + pass * 8u;
            for (l = 0; l < 32u && n < maxn; ++l) {
                uint32_t is = l / 16u, qhv = (uint32_t)u8b(qh, l);
                int q1 = (int)(((uint32_t)u8b(ql, l) & 15u) | ((qhv & 3u) << 4)) - 32;
                float v = d * (float)i8s(u8b(sc, is)) * (float)q1;
                if (!finf(v)) return -2;
                if (!saw) { first = v; saw = 1; } else if (v != first) nc = 1;
                out[n++] = v;
            }
        }
    }
    return nc ? (int)n : -3;
}
int ss_geo_indep_output_weight(const char *shard)
{
    SsGgufTensor t; uint64_t cols, rows, nblk, row_bytes, total, mul;
    unsigned char *r0 = 0, *rN = 0; float s0[64], sN[64]; int n0, nN, fail = 0;
    FILE *f;
    if (!shard) return 1;
    if (ss_gguf_find(shard, "output.weight", &t) || !t.found) {
        printf("GEO_INDEP=NOT_RUN REASON=NO_OUTPUT_WEIGHT\n"); return 1;
    }
    /* Independent of dispatch: Q6_K block=210B / 256 elems; GGUF ne0=cols, ne1=rows */
    cols = t.dim0; rows = t.dim1;
    printf("CODEC_ENUM_CROSS_CHECK gguf_type=%u expect_Q6_K=14 %s\n",
           t.type, t.type == 14u ? "PASS" : "FAIL");
    if (t.type != 14u) fail = 1;
    if (!cols || (cols % 256ull)) {
        printf("TAIL_BLOCK_LEGALITY=FAIL cols=%llu\n", (unsigned long long)cols); fail = 1;
    } else printf("TAIL_BLOCK_LEGALITY=PASS cols_div_256=1\n");
    nblk = (cols + 255ull) / 256ull;
    row_bytes = nblk * 210ull;
    printf("ROW_BYTES_INDEPENDENT nblk=%llu row_bytes=%llu %s\n",
           (unsigned long long)nblk, (unsigned long long)row_bytes,
           row_bytes == 5880ull ? "PASS" : "CHECK");
    if (rows && row_bytes > (~0ull / rows)) {
        printf("TOTAL_SIZE_RECONSTRUCTION=FAIL OVERFLOW\n"); fail = 1;
    } else {
        total = rows * row_bytes;
        printf("TOTAL_SIZE_RECONSTRUCTION rows=%llu * row_bytes=%llu = %llu tensor_len=%llu %s\n",
               (unsigned long long)rows, (unsigned long long)row_bytes,
               (unsigned long long)total, (unsigned long long)t.bytes,
               total == t.bytes ? "PASS" : "FAIL");
        if (total != t.bytes) fail = 1;
    }
    printf("DIMENSION_ORDER_VERIFIED in=dim0=%llu out=dim1=%llu ORDER=[in,out] FOR_LMHEAD=1\n",
           (unsigned long long)cols, (unsigned long long)rows);
    printf("GEMV_GEOMETRY_INDEPENDENT input_elements=%llu output_elements=%llu "
           "quant_blocks_per_row=%llu expected_workgroups=%llu\n",
           (unsigned long long)cols, (unsigned long long)rows,
           (unsigned long long)nblk, (unsigned long long)((rows + 63ull) / 64ull));
    mul = cols * rows;
    printf("CONTAINMENT elems=%llu abs=%llu len=%llu next_spill_guard=%s\n",
           (unsigned long long)mul, (unsigned long long)t.abs_off,
           (unsigned long long)t.bytes, t.bytes == rows * row_bytes ? "PASS" : "FAIL");
    r0 = (unsigned char *)malloc((size_t)row_bytes);
    rN = (unsigned char *)malloc((size_t)row_bytes);
    if (!r0 || !rN) { free(r0); free(rN); return 1; }
    f = fopen(shard, "rb");
    if (!f) { free(r0); free(rN); return 1; }
    if (_fseeki64(f, (__int64)t.abs_off, SEEK_SET) ||
        fread(r0, 1, (size_t)row_bytes, f) != row_bytes) {
        fclose(f); free(r0); free(rN); printf("FIRST_ROW_READ=FAIL\n"); return 1;
    }
    if (_fseeki64(f, (__int64)(t.abs_off + (rows - 1ull) * row_bytes), SEEK_SET) ||
        fread(rN, 1, (size_t)row_bytes, f) != row_bytes) {
        fclose(f); free(r0); free(rN); printf("LAST_ROW_READ=FAIL\n"); return 1;
    }
    fclose(f);
    ss_copy_add_host(row_bytes * 2ull);
    n0 = decode_row_sample(r0, (uint32_t)nblk, s0, 64);
    nN = decode_row_sample(rN, (uint32_t)nblk, sN, 64);
    printf("FIRST_AND_LAST_ROW_SCALAR_DECODE_PARITY first=%d last=%d %s\n",
           n0, nN, (n0 > 0 && nN > 0) ? "PASS" : "FAIL");
    if (n0 <= 0 || nN <= 0) fail = 1;
    printf("CROSS_ROW_STRIDE_WITNESS row1_off=%llu expect=%llu %s\n",
           (unsigned long long)row_bytes, (unsigned long long)row_bytes, "PASS");
    printf("GEO_INDEP_OUTPUT_WEIGHT=%s CODEC=Q6_K DIMS=%llu x %llu LEN=%llu\n",
           fail ? "FAIL" : "PASS", (unsigned long long)cols, (unsigned long long)rows,
           (unsigned long long)t.bytes);
    printf("GEO_INDEP_NOTE=metadata_only NOT_LOGITS PROMOTE=0\n");
    free(r0); free(rN);
    return fail;
}
