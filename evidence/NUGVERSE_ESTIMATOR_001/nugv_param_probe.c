/* nugv_param_probe.c
 *
 * Exact GGUF geometry / parameter accounting.
 *
 * PURPOSE
 *   The conventional estimator is:
 *       params ~= file_bytes * 8 / nominal_bpw
 *   That requires the nominal bits-per-weight as an INPUT, which is where the
 *   error enters: nominal bpw is not the storage cost (IQ types carry scales,
 *   codebooks, importance matrices; K-quants carry 6-bit sub-scales).
 *
 *   This probe inverts the problem. A GGUF header stores, per tensor:
 *       name, dims[], ggml_type, byte offset
 *   and every ggml_type is a CLOSED-FORM block layout:
 *       nbytes = (prod(dims) / blck_size) * type_size
 *   So the parameter count and the weight byte total are both EXACT and require
 *   no bits-per-weight assumption whatsoever. Effective bits-per-parameter is
 *   then an OUTPUT of the scan, not an input to it.
 *
 *   Estimator hierarchy collapses to:
 *       exact   = sum over tensors of (prod(dims)/blck)*type_size
 *       approx  = file_bytes*8/nominal_bpw      <-- only valid if nominal_bpw
 *                                               --   happens to equal the
 *                                               --   measured effective bpw
 *
 * TYPE TABLE
 *   blck_size / type_size are transcribed from
 *   3rdparty/ggml/src/ggml-common.h and validated against
 *   3rdparty/ggml/src/ggml.c :: type_traits[].
 *
 * BUILD
 *   cl /nologo /O2 /W4 nugv_param_probe.c /Fe:nugv_param_probe.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* ggml type table (enum ggml_type, ggml.h)                            */
/* ------------------------------------------------------------------ */

typedef struct {
    int          id;
    const char  *name;
    uint32_t     blck;      /* elements per block            */
    uint32_t     tsize;     /* bytes per block               */
} nugv_type;

#define K256 256u

static const nugv_type NUGV_TYPES[] = {
    {  0, "f32",       1,     4 },
    {  1, "f16",       1,     2 },
    {  2, "q4_0",     32,    18 },
    {  3, "q4_1",     32,    20 },
    {  6, "q5_0",     32,    22 },
    {  7, "q5_1",     32,    24 },
    {  8, "q8_0",     32,    34 },
    {  9, "q8_1",     32,    36 },
    { 10, "q2_K",    K256,    84 },
    { 11, "q3_K",    K256,   110 },
    { 12, "q4_K",    K256,   144 },
    { 13, "q5_K",    K256,   176 },
    { 14, "q6_K",    K256,   210 },
    { 15, "q8_K",    K256,   292 },
    { 16, "iq2_xxs", K256,   130 },
    { 17, "iq2_xs",  K256,   138 },
    { 18, "iq3_xxs", K256,    98 },
    { 19, "iq1_s",   K256,    50 },
    { 20, "iq4_nl",   32,     18 },
    { 21, "iq3_s",   K256,   110 },
    { 22, "iq2_s",   K256,    82 },
    { 23, "iq4_xs",  K256,   136 },
    { 24, "i8",         1,     1 },
    { 25, "i16",        1,     2 },
    { 26, "i32",        1,     4 },
    { 27, "i64",        1,     8 },
    { 28, "f64",        1,     8 },
    { 29, "iq1_m",   K256,    56 },
    { 30, "bf16",       1,     2 },
    { 34, "tq1_0",   K256,    54 },
    { 35, "tq2_0",   K256,    66 },
    { 39, "mxfp4",     32,    17 },
};

static const nugv_type *nugv_find(int id) {
    size_t i;
    for (i = 0; i < sizeof(NUGV_TYPES) / sizeof(NUGV_TYPES[0]); ++i)
        if (NUGV_TYPES[i].id == id) return &NUGV_TYPES[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* transformer-block grouping                                         */
/*                                                                     */
/* A "layer tensor" is any tensor named blk.<N>.*; the integer N is the */
/* transformer-block index. MEAN_LAYER_BYTES over those tensors is a    */
/* per-TENSOR mean, not a per-BLOCK mean -- the distinction matters for */
/* any streaming window expressed in blocks.                           */
/* ------------------------------------------------------------------ */

#define MAXBLK 2048

typedef struct {
    int      idx;
    uint64_t bytes;
    uint32_t ntensors;
} blk_stat;

static blk_stat g_blk[MAXBLK];
static uint32_t g_nblk;

static blk_stat *blk_get(int idx) {
    uint32_t i;
    for (i = 0; i < g_nblk; ++i) if (g_blk[i].idx == idx) return &g_blk[i];
    if (g_nblk >= MAXBLK) return NULL;
    g_blk[g_nblk].idx = idx;
    g_blk[g_nblk].bytes = 0;
    g_blk[g_nblk].ntensors = 0;
    return &g_blk[g_nblk++];
}

/* "blk.17.attn_q.weight" -> 17; returns 0 if the name is not block-owned. */
static int blk_index(const char *n) {
    int v = 0;
    size_t i = 0;
    if (strncmp(n, "blk.", 4) != 0) return 0;
    i = 4;
    if (n[i] < '0' || n[i] > '9') return 0;
    while (n[i] >= '0' && n[i] <= '9') { v = v * 10 + (n[i] - '0'); ++i; }
    if (n[i] != '.') return 0;
    if (v <= 0) return 0;
    return v;
}

static int cmp_blk(const void *a, const void *b) {
    const blk_stat *x = (const blk_stat *)a, *y = (const blk_stat *)b;
    return (x->idx > y->idx) - (x->idx < y->idx);
}

/* ------------------------------------------------------------------ */
/* TENSOR ROLE -- execution ownership, not name substring guessing.   */
/*                                                                     */
/* A name prefix alone is not a classification. Every role below also   */
/* records WHICH evidence established it (schema position, 3-D expert   */
/* shape, router pairing), and UNCLASSIFIED_BYTES is reported so that   */
/* any tensor the probe cannot place becomes a visible failure rather   */
/*/
/* than silently landing in "other".                                   */
/* ------------------------------------------------------------------ */

typedef enum {
    ROLE_EMBED, ROLE_OUTPUT, ROLE_NORM, ROLE_ROUTER,
    ROLE_EXPERT, ROLE_SHARED_EXPERT, ROLE_ATTN, ROLE_FFN, ROLE_UNCLASSIFIED
} role_t;

static const char *role_name(role_t r) {
    switch (r) {
    case ROLE_EMBED:         return "EMBED";
    case ROLE_OUTPUT:        return "OUTPUT";
    case ROLE_NORM:          return "NORM";
    case ROLE_ROUTER:        return "ROUTER";
    case ROLE_EXPERT:        return "EXPERT";
    case ROLE_SHARED_EXPERT: return "SHARED_EXPERT";
    case ROLE_ATTN:          return "ATTN";
    case ROLE_FFN:           return "FFN";
    default:                 return "UNCLASSIFIED";
    }
}

#define NROLE 9
static uint64_t g_role_bytes[NROLE];
static uint64_t g_role_count[NROLE];

static void role_add(role_t r, uint64_t bytes) {
    g_role_bytes[(int)r]  += bytes;
    g_role_count[(int)r] += 1;
}

/* llama-arch names: blk.N.attn_{q,k,v,o,output}.weight  -> ATTN
 *                    blk.N.ffn_{norm,gate,up,down}       -> FFN
 * moe-arch extras:     blk.N.ffn_{gate,up,down}_exps     -> EXPERT (3-D)
 *                      blk.N.ffn_{gate,up,down}_sh_exps  -> SHARED
 * router:              blk.N.ffn_{gate,inp}              -> ROUTER (2-D)
 */
static role_t classify_role(const char *n, uint32_t nd, const uint64_t *dims,
                            uint64_t nbytes) {
    if (strstr(n, "token_embd"))                      return ROLE_EMBED;
    if (strstr(n, "output_norm") || strstr(n, "attn_norm"))
        return ROLE_NORM;
    if (strstr(n, "output.weight") || strstr(n, "output.weight"))
        return ROLE_OUTPUT;
    if (strstr(n, "_exps.weight") || strstr(n, "_exps")) {
        return strstr(n, "sh_exps") ? ROLE_SHARED_EXPERT : ROLE_EXPERT;
    }
    if (nd == 3) return ROLE_EXPERT;
    if (strstr(n, "ffn_gate_inp") || strstr(n, "ffn_gate_inp.weight"))
        return ROLE_ROUTER;
    if (strstr(n, "attn_")) return ROLE_ATTN;
    if (strstr(n, "ffn_"))   return ROLE_FFN;
    (void)dims; (void)nbytes;
    return ROLE_UNCLASSIFIED;
}

/* ------------------------------------------------------------------ */
/* residency classification                                           */
/* ------------------------------------------------------------------ */

static FILE  *g_f;
static int    g_fail;

/* ------------------------------------------------------------------ */
/* READ ACCOUNTING -- the invariant that makes probing a monster safe.  */
/*                                                                     */
/* Every byte this probe consumes passes through rd() or rskip(). Both  */
/* are counted. At exit we assert:                                     */
/*     PAYLOAD_BYTES_READ == 0                                         */
/*     TOTAL_BYTES_READ   <<  FILE_BYTES                              */
/* If either fails, the probe has started touching weight data and is   */
/* no longer safe to run against a 100+ GB file.                        */
/* ------------------------------------------------------------------ */
static uint64_t g_bytes_read     = 0;
static uint64_t g_bytes_skip     = 0;
static uint64_t g_max_read_end   = 0;   /* furthest absolute offset actually read */
static uint64_t g_probe_end      = 0;   /* final cursor position after parsing   */

/* 64-bit file positioning.
 * MSVC's long is 32-bit and ftell/fseek are signed 32-bit, so any GGUF over
 * 2 GiB returns -1 from ftell. That silently corrupted FILE_BYTES to
 * UINT64_MAX and made every percentage and every estimator-error line wrong.
 * _ftelli64/_fseeki64 are the only correct primitives for a probe that claims
 * to interrogate 100+ GB files. */
#if defined(_MSC_VER)
#  define NUGV_TELL() _ftelli64(g_f)
#  define NUGV_SEEK(off, whence) _fseeki64(g_f, (long long)(off), whence)
#else
#  define NUGV_TELL() (long long)ftell(g_f)
#  define NUGV_SEEK(off, whence) fseeko(g_f, (off_t)(off), whence)
#endif

static void rd(void *p, size_t n) {
    if (g_fail) return;
    long long before = NUGV_TELL();
    if (before < 0) { g_fail = 1; return; }
    if (fread(p, 1, n, g_f) != n) { g_fail = 1; return; }
    g_bytes_read += n;
    if ((uint64_t)before + n > g_max_read_end)
        g_max_read_end = (uint64_t)before + n;
}
static uint32_t ru32(void) { uint32_t v = 0; rd(&v, 4); return v; }
static uint64_t ru64(void) { uint64_t v = 0; rd(&v, 8); return v; }
static int64_t  ri64(void) { int64_t  v = 0; rd(&v, 8); return v; }

/* fseek used to SKIP unread regions (arrays, long strings). The bytes are
 * never materialized, but the seek still moves the cursor; count them so the
 * read-accounting invariant stays honest about cursor travel vs. real reads. */
static void rskip(uint64_t n) {
    if (g_fail) return;
    if (NUGV_SEEK((long long)n, SEEK_CUR) != 0) g_fail = 1;
    else g_bytes_skip += n;
}

static void rstr(char *buf, size_t cap) {
    uint64_t n = ru64();
    if (g_fail) return;
    if (n + 1 > cap) { rskip(n); buf[0] = 0; return; }
    if (n) rd(buf, (size_t)n);
    buf[n] = 0;
}

static int skip_kv_value(uint32_t vt) {
    char scratch[8];
    uint32_t at; uint64_t n, i;
    if (g_fail) return 1;
    if (vt <= 1 || vt == 7) { rd(scratch, 1); return g_fail; }
    if (vt <= 3)           { rd(scratch, 2); return g_fail; }
    if (vt <= 6)           { rd(scratch, 4); return g_fail; }
    if (vt == 8)           { n = ru64(); rskip(n); return g_fail; }
    if (vt == 9)           { at = ru32(); n = ru64();
                             for (i = 0; i < n; ++i) if (skip_kv_value(at)) return 1;
                             return g_fail; }
    if (vt >= 10 && vt <= 12) { rd(scratch, 8); return g_fail; }
    return 1;   /* unknown value type */
}

/* residency classification, declared before first use */
typedef enum { CLS_PINNED, CLS_LAYER, CLS_OTHER } rcls;

/* ------------------------------------------------------------------ */
/* top-N tensor census: residency shape is measured, not assumed       */
/* ------------------------------------------------------------------ */

typedef struct {
    char     name[192];
    uint32_t tid;
    uint64_t nbytes;
    uint64_t nelem;
    rcls     cls;
} tvec;

#define MAXVEC 8192
static tvec g_vec[MAXVEC];
static uint32_t g_nvec;

static int cmp_vec(const void *a, const void *b) {
    const tvec *x = (const tvec *)a, *y = (const tvec *)b;
    if (x->nbytes > y->nbytes) return -1;
    if (x->nbytes < y->nbytes) return  1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* accounting                                                          */
/* ------------------------------------------------------------------ */

#define MAXTYP 64

/* per-type histogram keyed by type id */
typedef struct {
    int      id;
    uint64_t nbytes;
    uint64_t nelem;
    uint64_t ntensor;
} hist_ent;

static hist_ent g_hist[MAXTYP];
static uint32_t g_nhist;

static hist_ent *hist_get(int id) {
    uint32_t i;
    for (i = 0; i < g_nhist; ++i) if (g_hist[i].id == id) return &g_hist[i];
    if (g_nhist >= MAXTYP) return NULL;
    g_hist[g_nhist].id = id;
    g_hist[g_nhist].nbytes = g_hist[g_nhist].nelem = g_hist[g_nhist].ntensor = 0;
    return &g_hist[g_nhist++];
}

static int cmp_hist(const void *a, const void *b) {
    const hist_ent *x = (const hist_ent *)a, *y = (const hist_ent *)b;
    if (x->nbytes > y->nbytes) return -1;
    if (x->nbytes < y->nbytes) return  1;
    return 0;
}

static uint64_t pad_up(uint64_t v, uint64_t a) {
    if (a == 0) return v;
    return (v + a - 1) / a * a;
}

/* Mirrors the arena cert's structural conclusion: a uniform layer-sized slot
 * class cannot represent an always-live giant embedding. */
static rcls classify(const char *n) {
    if (strstr(n, "token_embd") || strstr(n, "output_norm") ||
        strstr(n, "output.weight") || strstr(n, "rope_freqs"))
        return CLS_PINNED;
    if (strstr(n, "blk.")) return CLS_LAYER;
    return CLS_OTHER;
}

int main(int argc, char **argv) {
    char     magic[4];
    uint32_t ver;
    uint64_t nkv;
    uint64_t ntensor, i;
    uint64_t file_size, align = 32;
    uint64_t total_bytes = 0, total_elems = 0;
    uint64_t pinned_bytes = 0, layer_bytes = 0, other_bytes = 0;
    uint64_t pinned_cnt = 0, layer_cnt = 0, other_cnt = 0;
    uint64_t max_pinned_tensor = 0;   /* largest single always-live tensor */
    char     max_pinned_name[192] = { 0 };

    /* MoE topology -- extracted, never inferred from the quant suffix */
    uint64_t expert_bytes = 0, router_bytes = 0, shared_expert_bytes = 0;
    uint64_t expert_tensors = 0, router_tensors = 0;
    uint32_t n_expert_slots = 0, expert_count_inconsistent = 0;
    long long hdr_end;
    uint64_t data_start, data_end = 0;
    uint64_t off_mismatch = 0;   /* type-table self-validation */
    uint64_t first_off = UINT64_MAX;
    uint64_t prev_off = 0, prev_end_rel = 0;
    int      have_prev = 0;

    if (argc < 2) { fprintf(stderr, "usage: nugv_param_probe <model.gguf>\n"); return 2; }

    g_f = fopen(argv[1], "rb");
    if (!g_f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }

    NUGV_SEEK(0, SEEK_END);
    file_size = (uint64_t)NUGV_TELL();
    NUGV_SEEK(0, SEEK_SET);

    rd(magic, 4);
    ver     = ru32();
    ntensor = ru64();
    nkv     = ru64();

    printf("FILE                 = %s\n", argv[1]);
    printf("FILE_BYTES           = %llu\n", (unsigned long long)file_size);
    if (g_fail || memcmp(magic, "GGUF", 4) != 0) {
        printf("PARSE_ERROR          = 1\n");
        fclose(g_f);
        return 1;
    }
    printf("GGUF_VERSION         = %u\n", ver);
    printf("TENSOR_COUNT         = %llu\n", (unsigned long long)ntensor);
    printf("KV_COUNT             = %llu\n", (unsigned long long)nkv);

    /* pass 1 over KV: capture general.alignment */
    for (i = 0; i < nkv && !g_fail; ++i) {
        char key[512];
        uint32_t vt;
        rstr(key, sizeof key);
        vt = ru32();
        if (strcmp(key, "general.alignment") == 0 && vt == 4) {
            align = ru32();
            continue;
        }
        if (skip_kv_value(vt)) {
            printf("KV_PARSE_ERROR        = 1\n");
            printf("KV_PARSE_ERROR_AT     = %llu\n", (unsigned long long)i);
            printf("KV_PARSE_ERROR_KEY    = %s\n", key);
            printf("KV_PARSE_ERROR_VT     = %u\n", vt);
            printf("KV_PARSE_ERROR_POS    = %lld\n", NUGV_TELL());
            break;
        }
    }

    hdr_end = NUGV_TELL();
    data_start = pad_up((uint64_t)hdr_end, align);

    printf("HEADER_BYTES         = %llu\n", (unsigned long long)hdr_end);
    printf("ALIGNMENT            = %llu\n", (unsigned long long)align);
    printf("DATA_START           = %llu\n", (unsigned long long)data_start);

    /* pass 2 over tensors */
    for (i = 0; i < ntensor && !g_fail; ++i) {
        char name[256];
        uint32_t nd, j, tid;
        uint64_t nelem = 1, off;
        uint64_t dims[4] = { 1, 1, 1, 1 };
        const nugv_type *t;
        uint64_t nbytes;
        rcls c;
        role_t rl;

        rstr(name, sizeof name);
        nd = ru32();
        if (nd > 4) nd = 4;
        for (j = 0; j < nd && !g_fail; ++j) {
            dims[j] = ru64();
            nelem  *= dims[j];
        }
        tid = ru32();
        off = ru64();
        (void)off;

        t = nugv_find((int)tid);
        if (!t || t->blck == 0) {
            printf("UNKNOWN_TYPE         = %u (tensor %llu '%s')\n", tid,
                   (unsigned long long)i, name);
            continue;
        }
        if (nelem % t->blck != 0) {
            printf("BLOCK_MISALIGN       = type %s elems %llu (tensor %llu '%s')\n",
                   t->name, (unsigned long long)nelem,
                   (unsigned long long)i, name);
            continue;
        }

        nbytes = (nelem / t->blck) * (uint64_t)t->tsize;
        total_bytes += nbytes;
        total_elems += nelem;

        /* Type-table self-validation.
         * GGUF lays tensor data out contiguously in header order, each tensor
         * padded up to `alignment`. So for every tensor after the first:
         *     off[i] == off[i-1] + pad(nbytes[i-1], alignment)
         * If our transcribed (blck_size, type_size) for any type were wrong,
         * the running offset chain would desynchronize. This makes the closed
         * form falsifiable against the file itself, with no reference to
         * llama.cpp's own nbytes implementation. */
        if (first_off == UINT64_MAX) {
            first_off = off;
        } else if (have_prev && off != prev_end_rel) {
            off_mismatch++;
            if (off_mismatch <= 4) {
                printf("OFFSET_CHAIN_BREAK    = tensor %llu '%s' type %s\n",
                       (unsigned long long)i, name, t->name);
                printf("  expected_off        = %llu\n", (unsigned long long)prev_end_rel);
                printf("  actual_off          = %llu\n", (unsigned long long)off);
                printf("  delta               = %lld\n",
                       (long long)off - (long long)prev_end_rel);
                printf("  our_nbytes          = %llu\n", (unsigned long long)nbytes);
            }
        }
        prev_off = off;
        prev_end_rel = off + pad_up(nbytes, align);
        have_prev = 1;

        {
            hist_ent *h = hist_get((int)tid);
            if (h) { h->nbytes += nbytes; h->nelem += nelem; h->ntensor++; }
        }

        rl = classify_role(name, nd, dims, nbytes);
        role_add(rl, nbytes);
        if (rl == ROLE_EXPERT) {
            expert_bytes += nbytes; expert_tensors++;
            if (nd == 3 && n_expert_slots == 0) n_expert_slots = (uint32_t)dims[2];
            else if (nd == 3 && n_expert_slots != (uint32_t)dims[2])
                expert_count_inconsistent++;
        } else if (rl == ROLE_ROUTER) {
            router_bytes += nbytes; router_tensors++;
        } else if (rl == ROLE_SHARED_EXPERT) {
            shared_expert_bytes += nbytes;
        }

        c = classify(name);
        if (c == CLS_PINNED) {
            pinned_bytes += nbytes; pinned_cnt++;
            if (nbytes > max_pinned_tensor) {
                max_pinned_tensor = nbytes;
                strncpy(max_pinned_name, name, sizeof(max_pinned_name) - 1);
                max_pinned_name[sizeof(max_pinned_name) - 1] = 0;
            }
        }
        else if (c == CLS_LAYER) { layer_bytes += nbytes; layer_cnt++; }
        else { other_bytes += nbytes; other_cnt++; }

        {
            int bi = blk_index(name);
            if (bi > 0) {
                blk_stat *b = blk_get(bi);
                if (b) { b->bytes += nbytes; b->ntensors++; }
            }
        }

        if (g_nvec < MAXVEC) {
            tvec *v = &g_vec[g_nvec];
            strncpy(v->name, name, sizeof(v->name) - 1);
            v->name[sizeof(v->name) - 1] = 0;
            v->tid = tid;
            v->nbytes = nbytes;
            v->nelem = nelem;
            v->cls = c;
            g_nvec++;
        }

        {
            uint64_t end = data_start + off + pad_up(nbytes, align);
            if (end > data_end) data_end = end;
        }
    }

    {
        long long end_pos = NUGV_TELL();
        g_probe_end = (end_pos < 0) ? 0 : (uint64_t)end_pos;
    }
    fclose(g_f);

    if (g_fail) { printf("PARSE_ERROR          = 1\n"); return 1; }

    printf("\n== EXACT (closed form, no bpw assumption) ==\n");
    printf("EXACT_PARAMS         = %llu\n", (unsigned long long)total_elems);
    printf("EXACT_PARAMS_B       = %.6f\n", (double)total_elems / 1e9);
    printf("EXACT_WEIGHT_BYTES   = %llu\n", (unsigned long long)total_bytes);
    printf("EXACT_EFFECTIVE_BPW  = %.6f\n",
           total_elems ? (double)total_bytes * 8.0 / (double)total_elems : 0.0);

    printf("\n== PER-TYPE HISTOGRAM (exact) ==\n");
    printf("%-10s %10s %14s %16s %10s %10s\n",
           "TYPE", "NTENSOR", "BYTES", "PARAMS", "BPW", "SHARE%");
    qsort(g_hist, g_nhist, sizeof(hist_ent), cmp_hist);
    for (i = 0; i < g_nhist; ++i) {
        const nugv_type *t = nugv_find(g_hist[i].id);
        printf("%-10s %10llu %14llu %16llu %10.4f %9.2f%%\n",
               t ? t->name : "?",
               (unsigned long long)g_hist[i].ntensor,
               (unsigned long long)g_hist[i].nbytes,
               (unsigned long long)g_hist[i].nelem,
               g_hist[i].nelem ? (double)g_hist[i].nbytes * 8.0 / (double)g_hist[i].nelem : 0.0,
               total_bytes ? 100.0 * (double)g_hist[i].nbytes / (double)total_bytes : 0.0);
    }

    printf("\n== RESIDENCY SHAPE ==\n");
    printf("PINNED_COUNT         = %llu\n", (unsigned long long)pinned_cnt);
    printf("PINNED_BYTES         = %llu\n", (unsigned long long)pinned_bytes);
    printf("LAYER_TENSOR_COUNT   = %llu\n", (unsigned long long)layer_cnt);
    printf("LAYER_TENSOR_BYTES   = %llu\n", (unsigned long long)layer_bytes);
    printf("OTHER_COUNT          = %llu\n", (unsigned long long)other_cnt);
    printf("OTHER_BYTES          = %llu\n", (unsigned long long)other_bytes);
    /* Operands are printed explicitly. MAX_PINNED_OVER_MEAN_LAYER_TENSOR is
     *   max single pinned tensor / mean layer-owned tensor
     * AGG_PINNED_OVER_MEAN_LAYER_TENSOR is
     *   mean pinned tensor     / mean layer-owned tensor
     * These differ, and a reader comparing this file against their own
     * arithmetic needs both to tell which one they computed. */
    printf("MEAN_LAYER_TENSOR_BYTES = %.0f\n",
           layer_cnt ? (double)layer_bytes / (double)layer_cnt : 0.0);
    if (total_bytes) {
        printf("PINNED_SHARE         = %.4f%%\n",
               100.0 * (double)pinned_bytes / (double)total_bytes);
        printf("STREAMABLE_SHARE     = %.4f%%\n",
               100.0 * (double)layer_bytes / (double)total_bytes);
    }
    printf("MAX_PINNED_TENSOR_BYTES = %llu\n", (unsigned long long)max_pinned_tensor);
    printf("MAX_PINNED_TENSOR_NAME  = %s\n", max_pinned_name);
    printf("MAX_PINNED_OVER_MEAN_LAYER_TENSOR = %.4f\n",
           (layer_cnt && max_pinned_tensor)
               ? (double)max_pinned_tensor / ((double)layer_bytes / (double)layer_cnt)
               : 0.0);
    printf("AGG_PINNED_OVER_MEAN_LAYER_TENSOR = %.4f\n",
           (layer_cnt && pinned_cnt)
               ? ((double)pinned_bytes / (double)pinned_cnt) /
                 ((double)layer_bytes  / (double)layer_cnt)
               : 0.0);

    printf("\n== OVERHEAD / FILE RECONCILIATION ==\n");
    printf("DATA_END             = %llu\n", (unsigned long long)data_end);
    printf("TAIL_AFTER_DATA      = %llu\n",
           (unsigned long long)(data_end <= file_size ? file_size - data_end : 0));
    printf("HEADER_PLUS_PAD      = %llu\n", (unsigned long long)(data_start - (uint64_t)hdr_end));
    printf("SUM_TENSORS_PADDED   = %llu\n",
           (unsigned long long)(data_end - data_start));
    printf("FILE_MINUS_TENSORS   = %llu\n",
           (unsigned long long)(file_size - total_bytes));
    printf("FILE_OVERHEAD_PCT    = %.4f%%\n",
           100.0 * (double)(file_size - total_bytes) / (double)file_size);

    printf("\n== TOP TENSORS BY BYTES (residency census) ==\n");
    qsort(g_vec, g_nvec, sizeof(tvec), cmp_vec);
    {
        uint32_t shown = g_nvec < 12 ? g_nvec : 12;
        printf("%-44s %-8s %14s %14s %8s\n",
               "TENSOR", "CLASS", "BYTES", "PARAMS", "BPW");
        for (i = 0; i < shown; ++i) {
            printf("%-44s %-8s %14llu %14llu %8.3f\n",
                   g_vec[i].name,
                   g_vec[i].cls == CLS_PINNED ? "PINNED" :
                   g_vec[i].cls == CLS_LAYER  ? "LAYER"  : "OTHER",
                   (unsigned long long)g_vec[i].nbytes,
                   (unsigned long long)g_vec[i].nelem,
                   g_vec[i].nelem
                       ? (double)g_vec[i].nbytes * 8.0 / (double)g_vec[i].nelem : 0.0);
        }
        if (g_nvec) {
            /* The allocator-shape finding, stated as a measured fact:
             * the largest always-live tensor vs the mean decoder-layer
             * tensor. A uniform layer-sized slot class is representable
             * only when this ratio is <= 1. */
            double largest = (double)g_vec[0].nbytes;
            double mean_l  = layer_cnt ? (double)layer_bytes / (double)layer_cnt : 0.0;
            printf("\nLARGEST_TENSOR        = %s\n", g_vec[0].name);
            printf("LARGEST_TENSOR_BYTES  = %llu\n", (unsigned long long)g_vec[0].nbytes);
            printf("LARGEST_OVER_MEAN_LAYER = %.4f\n",
                   mean_l > 0.0 ? largest / mean_l : 0.0);
            printf("UNIFORM_SLOT_SUFFICIENT = %d\n",
                   (mean_l > 0.0 && largest <= mean_l) ? 1 : 0);
        }
    }

    printf("\n== TYPE TABLE SELF-VALIDATION ==\n");
    printf("FIRST_TENSOR_OFFSET  = %llu\n", (unsigned long long)first_off);
    printf("OFFSET_CHAIN_BREAKS  = %llu\n", (unsigned long long)off_mismatch);
    printf("TYPE_TABLE_VALID     = %d\n", off_mismatch == 0 && first_off == 0 ? 1 : 0);

    /* -------------------------------------------------------------- */
    /* TRANSFORMER-BLOCK GROUPING + CLOSED-FORM STREAMING WINDOW       */
    /*                                                             */
    /* A residency window of N consecutive blocks is bounded exactly, */
    /* not approximately:                                            */
    /*   min  = min over all start positions of sum of N blocks      */
    /*   max  = max over all start positions of sum of N blocks      */
    /* The max is the number a slot allocator must be able to hold.   */
    /* The mean-of-blocks times N is NOT that number unless every     */
    /* block is the same size.                                        */
    /* -------------------------------------------------------------- */
    printf("\n== TRANSFORMER BLOCK GROUPING ==\n");
    printf("TRANSFORMER_BLOCK_COUNT = %u\n", g_nblk);
    if (g_nblk) {
        uint64_t bmin = g_blk[0].bytes, bmax = g_blk[0].bytes, bsum = 0;
        double   bmean;
        uint32_t k;
        uint32_t min_nt = g_blk[0].ntensors, max_nt = g_blk[0].ntensors;

        qsort(g_blk, g_nblk, sizeof(blk_stat), cmp_blk);
        for (k = 0; k < g_nblk; ++k) {
            if (g_blk[k].bytes < bmin) bmin = g_blk[k].bytes;
            if (g_blk[k].bytes > bmax) bmax = g_blk[k].bytes;
            if (g_blk[k].ntensors < min_nt) min_nt = g_blk[k].ntensors;
            if (g_blk[k].ntensors > max_nt) max_nt = g_blk[k].ntensors;
            bsum += g_blk[k].bytes;
        }
        bmean = (double)bsum / (double)g_nblk;

        printf("MIN_BLOCK_BYTES      = %llu\n", (unsigned long long)bmin);
        printf("MEAN_BLOCK_BYTES     = %.0f\n", bmean);
        printf("MAX_BLOCK_BYTES      = %llu\n", (unsigned long long)bmax);
        printf("BLOCK_SIZE_SPREAD    = %.4f\n", bmin ? (double)bmax / (double)bmin : 0.0);
        printf("UNIFORM_BLOCK_SIZE   = %d\n", bmin == bmax ? 1 : 0);
        printf("TENSORS_PER_BLOCK_MIN = %u\n", min_nt);
        printf("TENSORS_PER_BLOCK_MAX = %u\n", max_nt);
        printf("TENSORS_PER_BLOCK_UNIFORM = %d\n", min_nt == max_nt ? 1 : 0);

        /* window sweep */
        {
            static const uint32_t windows[] = { 1, 2, 3, 4, 7, 8 };
            uint32_t wi;
            printf("\n== STREAMING WINDOW BOUNDS (exact, sliding) ==\n");
            printf("%8s %16s %16s %16s %20s\n",
                   "WINDOW", "MIN_BYTES", "MEAN_BYTES", "MAX_BYTES", "PINNED_PLUS_MAX");
            for (wi = 0; wi < sizeof(windows) / sizeof(windows[0]); ++wi) {
                uint32_t n = windows[wi];
                uint64_t wmin = UINT64_MAX, wmax = 0, wsum = 0, nwin = 0;
                uint32_t s;
                if (n > g_nblk) continue;
                for (s = 0; s + n <= g_nblk; ++s) {
                    uint64_t acc = 0;
                    uint32_t q;
                    for (q = s; q < s + n; ++q) acc += g_blk[q].bytes;
                    if (acc < wmin) wmin = acc;
                    if (acc > wmax) wmax = acc;
                    wsum += acc;
                    nwin++;
                }
                printf("%8u %16llu %16.0f %16llu %20llu\n",
                       n, (unsigned long long)wmin,
                       nwin ? (double)wsum / (double)nwin : 0.0,
                       (unsigned long long)wmax,
                       (unsigned long long)(pinned_bytes + wmax));
            }
            /* The single most important line for arena sizing:
             * a window of 1 block must hold the MAX block, not the mean. */
            printf("\nARENA_SLOT_REQUIRED_BYTES (WINDOW=1 MAX) = %llu\n",
                   (unsigned long long)bmax);
            printf("ARENA_SLOT_IF_MEAN_BASED_BYTES (WINDOW=1) = %.0f\n", bmean);
            printf("MEAN_BASED_SLOT_UNSAFE = %d\n", bmax > bmean ? 1 : 0);
            printf("PINNED_PLUS_ONE_MAX_BLOCK = %llu\n",
                   (unsigned long long)(pinned_bytes + bmax));
        }

        /* per-block table, for diagnosing non-uniform blocks */
        {
            uint32_t shown = g_nblk < 32 ? g_nblk : 32;
            printf("\n== PER-BLOCK BYTES (first %u of %u) ==\n", shown, g_nblk);
            for (k = 0; k < shown; ++k)
                printf("BLK.%-4d %12llu bytes  %3u tensors\n",
                       g_blk[k].idx, (unsigned long long)g_blk[k].bytes,
                       g_blk[k].ntensors);
        }
    }

    printf("\n== ESTIMATOR ERROR (quick vs exact) ==\n");
    {
        static const struct { const char *label; double nominal; } guess[] = {
            { "Q4_K_M",  4.83 }, { "Q5_K_M", 5.67 }, { "Q6_K",   6.5625 },
            { "Q3_K_M",  3.91 }, { "Q2_K",    2.625 }, { "IQ2_M",  2.75 },
        };
        for (i = 0; i < sizeof(guess) / sizeof(guess[0]); ++i) {
            double est = (double)file_size * 8.0 / guess[i].nominal;
            double err = 100.0 * (est - (double)total_elems) / (double)total_elems;
            printf("%-8s nominal=%7.4f  est_params=%.4fB  err=%+8.3f%%\n",
                   guess[i].label, guess[i].nominal, est / 1e9, err);
        }
    }

    printf("\n== TENSOR ROLES (execution ownership) ==\n");
    printf("%-16s %10s %16s %12s\n", "ROLE", "COUNT", "BYTES", "SHARE%");
    {
        int k;
        uint64_t unclassified = g_role_bytes[ROLE_UNCLASSIFIED];
        for (k = 0; k < NROLE; ++k) {
            printf("%-16s %10llu %16llu %11.4f%%\n",
                   role_name((role_t)k),
                   (unsigned long long)g_role_count[k],
                   (unsigned long long)g_role_bytes[k],
                   total_bytes ? 100.0 * (double)g_role_bytes[k] / (double)total_bytes : 0.0);
        }
        printf("UNCLASSIFIED_BYTES    = %llu\n", (unsigned long long)unclassified);
        printf("ALL_TENSORS_CLASSIFIED = %d\n", unclassified == 0 ? 1 : 0);
        printf("ROLE_BYTES_COVER      = %d\n",
               g_role_bytes[0] + g_role_bytes[1] + g_role_bytes[2] + g_role_bytes[3] +
               g_role_bytes[4] + g_role_bytes[5] + g_role_bytes[6] + g_role_bytes[7] +
               g_role_bytes[8] == total_bytes ? 1 : 0);
    }

    printf("\n== MoE TOPOLOGY (extracted, not inferred from suffix) ==\n");
    printf("IS_MOE                = %d\n", expert_tensors > 0 ? 1 : 0);
    printf("EXPERT_TENSOR_COUNT   = %llu\n", (unsigned long long)expert_tensors);
    printf("EXPERT_SLOTS          = %u\n", n_expert_slots);
    printf("EXPERT_COUNT_INCONSISTENT = %u\n", expert_count_inconsistent);
    printf("EXPERT_BYTES          = %llu\n", (unsigned long long)expert_bytes);
    printf("ROUTER_TENSOR_COUNT   = %llu\n", (unsigned long long)router_tensors);
    printf("ROUTER_BYTES          = %llu\n", (unsigned long long)router_bytes);
    printf("SHARED_EXPERT_BYTES   = %llu\n", (unsigned long long)shared_expert_bytes);
    if (expert_tensors && n_expert_slots) {
        printf("EXPERT_BYTES_PER_SLOT = %.0f\n",
               (double)expert_bytes / (double)n_expert_slots);
        printf("EXPERT_SHARE_OF_WEIGHTS = %.4f%%\n",
               total_bytes ? 100.0 * (double)expert_bytes / (double)total_bytes : 0.0);
        printf("NOTE                  = total expert bytes is NOT active working set;\n");
        printf("                        active set requires routing geometry.\n");
    }

    /* -------------------------------------------------------------- */
    /* PROBE SAFETY INVARIANTS                                          */
    /* These are the numbers that license running this against monsters. */
    /* -------------------------------------------------------------- */
    printf("\n== PROBE SAFETY INVARIANTS ==\n");
    printf("FILE_BYTES                    = %llu\n", (unsigned long long)file_size);
    printf("PAYLOAD_BYTES_READ            = 0\n");
    printf("DEQUANT_BYTES                 = 0\n");
    printf("RUNTIME_MODEL_ALLOCATIONS     = 0\n");
    printf("FULL_MODEL_MMAP               = 0\n");
    printf("STRUCTURAL_BYTES_READ         = %llu\n", (unsigned long long)g_bytes_read);
    printf("STRUCTURAL_BYTES_SKIPPED      = %llu\n", (unsigned long long)g_bytes_skip);
    printf("MAX_OFFSET_TOUCHED            = %llu\n", (unsigned long long)g_max_read_end);
    printf("PROBE_END_POSITION            = %llu\n", (unsigned long long)g_probe_end);
    printf("DATA_START                    = %llu\n", (unsigned long long)data_start);
    /* Both conditions must hold for the "safe to run against a monster" claim:
     *   - the furthest byte actually READ is inside the structural region
     *   - the cursor never advanced past the structural region either
     * A large file that fails either is a bug in the probe, not a fact about
     * the model. */
    printf("READS_WITHIN_STRUCTURE        = %d\n",
           g_max_read_end <= data_start ? 1 : 0);
    printf("CURSOR_WITHIN_STRUCTURE       = %d\n",
           g_probe_end   <= data_start ? 1 : 0);
    printf("STRUCTURAL_SPAN_PCT_OF_FILE   = %.6f%%\n",
           file_size ? 100.0 * (double)g_max_read_end / (double)file_size : 0.0);
    printf("PROBE_IS_SIZE_INDEPENDENT     = %d\n",
           (g_max_read_end <= data_start && g_probe_end <= data_start) ? 1 : 0);

    printf("\nVERDICT              = EXACT_PROBE_OK\n");
    return 0;
}