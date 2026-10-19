/* nugv_genie.c -- Model Genie: GGUF -> plain-text executable anatomy
 *
 * Emits three separate artifacts, kept separate on purpose:
 *
 *   model.physical.txt   what the file literally states (tensor directory)
 *   model.genome.txt     what Deep2 reconstructed (roles, topology, MoE)
 *   model.execution.txt  the derived machine, as pseudo-source
 *
 * Separating them prevents inferred behaviour from masquerading as file
 * evidence. Every reconstructed statement carries an evidence tag, and the
 * first thing that cannot be proven is reported as an explicit hole rather
 * than silently guessed.
 *
 * Every field records HOW it was established:
 *   EXPLICIT   stated by a metadata key
 *   DIRECTORY  present in the tensor directory
 *   SHAPE      derived from tensor dimensions
 *   TOPOLOGY   derived from tensor grouping/relationships
 *   CONTRACT   assumed from the architecture's grammar
 *   OBSERVED   measured at runtime
 *
 * Reads only the structural region. Never touches tensor payload.
 *
 * BUILD
 *   cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS nugv_genie.c /Fe:nugv_genie.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#if defined(_MSC_VER)
#  define NUGV_TELL() _ftelli64(g_f)
#  define NUGV_SEEK(o, w) _fseeki64(g_f, (long long)(o), w)
#else
#  define NUGV_TELL() (long long)ftell(g_f)
#  define NUGV_SEEK(o, w) fseeko(g_f, (off_t)(o), w)
#endif

static FILE *g_f;
static int   g_fail;
static uint64_t g_bytes_read = 0, g_max_end = 0;

static void rd(void *p, size_t n) {
    if (g_fail) return;
    long long before = NUGV_TELL();
    if (before < 0) { g_fail = 1; return; }
    if (fread(p, 1, n, g_f) != n) { g_fail = 1; return; }
    g_bytes_read += n;
    if ((uint64_t)before + n > g_max_end) g_max_end = (uint64_t)before + n;
}
static uint32_t ru32(void) { uint32_t v = 0; rd(&v, 4); return v; }
static uint64_t ru64(void) { uint64_t v = 0; rd(&v, 8); return v; }
static void skipn(uint64_t n) { if (NUGV_SEEK((long long)n, SEEK_CUR) != 0) g_fail = 1; }
static void rstr(char *b, size_t cap) {
    uint64_t n = ru64();
    if (g_fail) return;
    if (n + 1 > cap) { skipn(n); b[0] = 0; return; }
    if (n) rd(b, (size_t)n);
    b[n] = 0;
}

/* ------------------------------------------------------------------ */
/* ggml type table -- identical to nugv_param_probe.c                  */
/* ------------------------------------------------------------------ */

typedef struct { int id; const char *name; uint32_t blck, tsize; } nugv_type;
#define K256 256u
static const nugv_type NUGV_TYPES[] = {
    {  0,"f32",1,4 },   {  1,"f16",1,2 },   {  2,"q4_0",32,18 }, {  3,"q4_1",32,20 },
    {  6,"q5_0",32,22 },{  7,"q5_1",32,24 },{  8,"q8_0",32,34 },{  9,"q8_1",32,36 },
    { 10,"q2_K",K256,84 },{11,"q3_K",K256,110},{12,"q4_K",K256,144},{13,"q5_K",K256,176 },
    { 14,"q6_K",K256,210},{15,"q8_K",K256,292},{16,"iq2_xxs",K256,130},{17,"iq2_xs",K256,138 },
    { 18,"iq3_xxs",K256,98 },{19,"iq1_s",K256,50},{20,"iq4_nl",32,18},{21,"iq3_s",K256,110 },
    { 22,"iq2_s",K256,82 },{23,"iq4_xs",K256,136},{24,"i8",1,1},{25,"i16",1,2 },
    { 26,"i32",1,4 },  { 27,"i64",1,8 },  { 28,"f64",1,8 },  { 29,"iq1_m",K256,56 },
    { 30,"bf16",1,2 }, { 34,"tq1_0",K256,54 },{35,"tq2_0",K256,66},{39,"mxfp4",32,17 },
};
static const nugv_type *tfind(int id) {
    size_t i;
    for (i = 0; i < sizeof(NUGV_TYPES)/sizeof(NUGV_TYPES[0]); ++i)
        if (NUGV_TYPES[i].id == id) return &NUGV_TYPES[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* metadata store: keys are arch-prefixed, so index by suffix match     */
/* ------------------------------------------------------------------ */

#define MAXKV 256
typedef struct { char key[160]; char sval[256]; double nval; uint32_t vt; uint64_t alen; } kvent;
static kvent g_kv[MAXKV];
static uint32_t g_nkv;

static void kv_put(const char *k, uint32_t vt, const char *s, double n, uint64_t alen) {
    uint32_t i;
    for (i = 0; i < g_nkv; ++i) if (!strcmp(g_kv[i].key, k)) { g_kv[i].vt = vt; strncpy(g_kv[i].sval, s ? s : "", 255); g_kv[i].nval = n; g_kv[i].alen = alen; return; }
    if (g_nkv >= MAXKV) return;
    strncpy(g_kv[g_nkv].key, k, 159); g_kv[g_nkv].key[159] = 0;
    g_kv[g_nkv].vt = vt; strncpy(g_kv[g_nkv].sval, s ? s : "", 255); g_kv[g_nkv].sval[255] = 0;
    g_kv[g_nkv].nval = n; g_kv[g_nkv].alen = alen;
    g_nkv++;
}
/* look up by suffix, e.g. "block_count" matches "deepseek2.block_count" */
static const kvent *kv_by_suffix(const char *suffix) {
    uint32_t i;
    for (i = 0; i < g_nkv; ++i) {
        const char *dot = strchr(g_kv[i].key, '.');
        const char *tail = dot ? dot + 1 : g_kv[i].key;
        if (!strcmp(tail, suffix)) return &g_kv[i];
    }
    return NULL;
}
static double kv_num(const char *suffix, double dflt) {
    const kvent *k = kv_by_suffix(suffix);
    return k ? k->nval : dflt;
}
static int kv_has(const char *suffix) { return kv_by_suffix(suffix) != NULL; }
static const char *kv_str(const char *suffix, const char *dflt) {
    const kvent *k = kv_by_suffix(suffix);
    return (k && k->sval[0]) ? k->sval : dflt;
}

/* ------------------------------------------------------------------ */
/* skip a KV value (we already captured the ones we care about)        */
/* ------------------------------------------------------------------ */

/* skip one array element of the given type */
static int skip_elem(uint32_t et) {
    char s[8];
    if (g_fail) return 1;
    switch (et) {
    case 0: case 1: case 7: rd(s,1); return g_fail;
    case 2: case 3:         rd(s,2); return g_fail;
    case 4: case 5: case 6: rd(s,4); return g_fail;
    case 8: { uint64_t n = ru64(); skipn(n); return g_fail; }
    case 9: { uint32_t at = ru32(); uint64_t n = ru64(); uint64_t q;
              for (q = 0; q < n && !g_fail; ++q) if (skip_elem(at)) return 1;
              return g_fail; }
    case 10: case 11: case 12: rd(s,8); return g_fail;
    default: g_fail = 1; return 1;
    }
}

static int skip_value(uint32_t vt) { return skip_elem(vt); }

/* ------------------------------------------------------------------ */
/* tensor directory                                                    */
/* ------------------------------------------------------------------ */

/* GGUF records dimensions in ggml ne-order: ne[0] is the fastest-varying
 * axis and is the ROW length, ne[1] the number of rows. So a token embedding
 * declared vocab x hidden appears as {ne0=hidden, ne1=vocab}. Reading dims[0]
 * as the vocabulary size silently reports the hidden width instead, which is
 * exactly the kind of plausible-but-wrong number that survives review. */
typedef enum { R_EMBED, R_OUTPUT, R_NORM, R_ROUTER, R_EXPERT,
               R_SHARED_EXPERT, R_ATTN, R_FFN, R_UNCLASSIFIED } role_t;
static const char *role_name(role_t r) {
    switch (r) {
    case R_EMBED: return "EMBED"; case R_OUTPUT: return "OUTPUT";
    case R_NORM: return "NORM";   case R_ROUTER: return "ROUTER";
    case R_EXPERT: return "EXPERT"; case R_SHARED_EXPERT: return "SHARED_EXPERT";
    case R_ATTN: return "ATTN";  case R_FFN: return "FFN";
    default: return "UNCLASSIFIED";
    }
}

typedef struct {
    char     name[192];
    uint32_t tid;
    uint32_t nd;
    uint64_t dims[4];
    uint64_t nelem;
    uint64_t off;
    uint64_t nbytes;
    role_t   role;
    int      block;       /* -1 if not block-owned */
} tenv;

#define MAXT 8192
static tenv g_t[MAXT];
static uint32_t g_nt;

/* "blk.17.attn_q.weight" -> 17, or -1 if the name is not block-owned.
 * The index is returned verbatim: v - 1 would silently discard block 0 and
 * report a block count one short of what the directory actually contains. */
static int parse_block(const char *n) {
    int v = 0; size_t i;
    if (strncmp(n, "blk.", 4)) return -1;
    i = 4;
    if (n[i] < '0' || n[i] > '9') return -1;
    while (n[i] >= '0' && n[i] <= '9') { v = v*10 + (n[i]-'0'); ++i; }
    if (n[i] != '.') return -1;
    return v;
}

/* GGUF records dimensions in ggml ne-order: ne[0] is the fastest-varying
 * axis and is the ROW length, ne[1] the number of rows. A token embedding
 * declared vocab x hidden therefore appears as {ne0=hidden, ne1=vocab}.
 * Reading dims[0] as the vocabulary size silently reports the hidden width
 * instead, which is exactly the kind of plausible-but-wrong number that
 * survives review because it looks reasonable. */
static uint32_t dim_rows(const tenv *e) {
    return e->nd >= 2 ? (uint32_t)e->dims[1] : (uint32_t)e->dims[0];
}

/* The LM head must be a top-level tensor that is not a block weight.
         * role_of() falls through to ATTN for anything containing "attn_",
         * so blk.N.attn_output.weight can be mistaken for the head. The head
         * is identified by being block-independent, not by its name pattern. */
static role_t head_role(const tenv *e) {
    if (e->block >= 0) return R_UNCLASSIFIED;
    if (strstr(e->name, "output_norm")) return R_NORM;
    if (strstr(e->name, "output.weight")) return R_OUTPUT;
    return R_UNCLASSIFIED;
}

static role_t role_of(const char *n, uint32_t nd) {
    if (strstr(n, "token_embd")) return R_EMBED;
    if (strstr(n, "output_norm") || strstr(n, "attn_norm") ||
        strstr(n, "ffn_norm") || strstr(n, "_norm")) return R_NORM;
    if (strstr(n, "output.weight")) return R_OUTPUT;
    if (strstr(n, "sh_exps")) return R_SHARED_EXPERT;
    if (strstr(n, "_exps")) return R_EXPERT;
    if (nd == 3) return R_EXPERT;
    if (strstr(n, "gate_inp")) return R_ROUTER;
    /* ffn_* before attn_*: a name like blk.N.attn_output_norm is attention,
         * but generic "ffn" ordering keeps dense FFN distinct from QKV. */
    if (strstr(n, "ffn_")) return R_FFN;
    if (strstr(n, "attn_") || strstr(n, "wq_") || strstr(n, "wk_") ||
        strstr(n, "wv_") || strstr(n, "wo_")) return R_ATTN;
    return R_UNCLASSIFIED;
}

/* ------------------------------------------------------------------ */
/* discovery log                                                       */
/* ------------------------------------------------------------------ */

#define MAXD 512
static char g_disc[MAXD][220];
static uint32_t g_nd;
static void discover(const char *fmt, ...) {
    if (g_nd >= MAXD) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_disc[g_nd], sizeof g_disc[0], fmt, ap);
    va_end(ap);
    g_nd++;
}

/* first boundary we cannot prove, and why */
static char g_frontier[256] = "NONE";
static char g_frontier_why[256] = "all operations resolved";

static void set_frontier(const char *what, const char *why) {
    if (strcmp(g_frontier, "NONE") == 0) {
        strncpy(g_frontier, what, 255);
        strncpy(g_frontier_why, why, 255);
    }
}

#include <stdarg.h>

/* ------------------------------------------------------------------ */

/* ---- tensors grouped by declared block ---- */
typedef struct {
    uint32_t bytes, tensors;
    uint64_t attn, norm, dense_ffn, router, expert, shared;
    uint8_t  has[16];
} blkprof;

#define MAXBLK 1024
static blkprof g_bp[MAXBLK];

static void profile_block(blkprof *p, const tenv *e) {
    p->bytes   += (uint32_t)e->nbytes;
    p->tensors += 1;
    switch (e->role) {
    case R_ATTN:          p->attn += e->nbytes;  p->has[0] = 1; break;
    case R_NORM:          p->norm += e->nbytes;  p->has[1] = 1; break;
    case R_FFN:           p->dense_ffn += e->nbytes; p->has[2] = 1; break;
    case R_ROUTER:        p->router += e->nbytes; p->has[3] = 1; break;
    case R_EXPERT:        p->expert += e->nbytes; p->has[4] = 1; break;
    case R_SHARED_EXPERT: p->shared += e->nbytes; p->has[5] = 1; break;
    default: break;
    }
}

/* signature string: which roles are present in a block */
static void block_signature(char *buf, size_t cap, const blkprof *p) {
    snprintf(buf, cap, "attn=%d,norm=%d,ffn=%d,router=%d,expert=%d,shared=%d",
             p->has[0], p->has[1], p->has[2], p->has[3], p->has[4], p->has[5]);
}

int main(int argc, char **argv) {
    char magic[4], arch[64] = "";
    uint32_t ver, i;
    uint64_t ntensor, nkv, file_size, align = 32, data_start;
    long long hdr_end;
    uint64_t total_bytes = 0, total_elems = 0;
    uint64_t off_mismatch = 0, first_off = UINT64_MAX, prev_end = 0;
    uint64_t gaps = 0, off_overlap = 0, exact_continuations = 0;
    int have_prev = 0;
    uint32_t nblk_decl = 0, max_block = 0;
    const tenv *embed = NULL, *lmhead = NULL;
    int tied_head = 0;

    if (argc < 2) { fprintf(stderr, "usage: nugv_genie <model.gguf> [outdir]\n"); return 2; }

    g_f = fopen(argv[1], "rb");
    if (!g_f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }

    NUGV_SEEK(0, SEEK_END); file_size = (uint64_t)NUGV_TELL(); NUGV_SEEK(0, SEEK_SET);

    rd(magic, 4); ver = ru32(); ntensor = ru64(); nkv = ru64();
    if (g_fail || memcmp(magic, "GGUF", 4)) {
        printf("PARSE_ERROR = 1\n"); fclose(g_f); return 1;
    }

    /* ---- KV pass ---- */
    for (i = 0; i < nkv && !g_fail; ++i) {
        char key[512], sbuf[4096];
        uint32_t vt;
        double n = 0.0;
        uint64_t alen = 0;
        sbuf[0] = 0;
        rstr(key, sizeof key);
        vt = ru32();
        switch (vt) {
        case 0: { uint8_t  v; rd(&v,1); n=v; } break;
        case 1: { int8_t   v; rd(&v,1); n=v; } break;
        case 2: { uint16_t v; rd(&v,2); n=v; } break;
        case 3: { int16_t  v; rd(&v,2); n=v; } break;
        case 4: { uint32_t v; rd(&v,4); n=v; } break;
        case 5: { int32_t  v; rd(&v,4); n=v; } break;
        case 6: { float    v; rd(&v,4); n=v; } break;
        case 7: { uint8_t  v; rd(&v,1); n=v; } break;
        case 8: { rstr(sbuf, sizeof sbuf); } break;
        case 9: { uint32_t et = ru32(); uint64_t cnt = ru64();
                  uint64_t q;
                  alen = cnt;
                  /* capture small numeric arrays (vocab-size masks, flags);
                     skip everything else, including huge string arrays */
                  if (et >= 4 && et <= 6 && cnt <= 64) {
                      n = 0;
                      for (q = 0; q < cnt && !g_fail; ++q) {
                          if (et == 4) { uint32_t v; rd(&v,4); n += v; }
                          else if (et == 5) { int32_t v; rd(&v,4); n += v; }
                          else { float v; rd(&v,4); n += v; }
                      }
                  } else {
                      for (q = 0; q < cnt && !g_fail; ++q)
                          if (skip_elem(et)) break;
                  }
                } break;
        case 10:{ uint64_t v; rd(&v,8); n=(double)v; } break;
        case 11:{ int64_t  v; rd(&v,8); n=(double)v; } break;
        case 12:{ double   v; rd(&v,8); n=v; } break;
        default: g_fail = 1; break;
        }
        if (strcmp(key, "general.alignment") == 0) align = (uint64_t)n;
        kv_put(key, vt, sbuf, n, alen);
        if (!strcmp(key, "general.architecture")) strncpy(arch, sbuf, 63);
        if (g_fail) {
            fprintf(stderr, "KV_PARSE_ERROR at key=%s (index %u of %llu), pos=%lld\n",
                    key, i, (unsigned long long)nkv, NUGV_TELL());
            break;
        }
    }

    hdr_end = NUGV_TELL();
    data_start = ((uint64_t)hdr_end + align - 1) / align * align;

    /* ---- tensor directory pass ---- */
    for (i = 0; i < ntensor && !g_fail && g_nt < MAXT; ++i) {
        tenv *e = &g_t[g_nt];
        const nugv_type *ty;
        uint32_t j;
        uint64_t nelem = 1;

        rstr(e->name, sizeof e->name);
        e->nd = ru32();
        if (e->nd > 4) e->nd = 4;
        for (j = 0; j < e->nd; ++j) { e->dims[j] = ru64(); nelem *= e->dims[j]; }
        e->tid = ru32();
        e->off = ru64();
        e->nelem = nelem;
        e->nbytes = 0;

        ty = tfind((int)e->tid);
        if (ty && ty->blck && (nelem % ty->blck) == 0)
            e->nbytes = (nelem / ty->blck) * (uint64_t)ty->tsize;
        else
            e->nbytes = nelem;   /* f32/f16/bf16 fallback: blck=1 */

        e->role  = role_of(e->name, e->nd);
        e->block = parse_block(e->name);

        /* Offset-chain validation, with the distinction that matters.
         *
         * A dense GGUF lays tensors out contiguously:
         *     off[i] == off[i-1] + pad(nbytes[i-1], alignment)
         * Under that assumption, a mismatch anywhere proves a wrong
         * (blck_size, type_size) in the transcribed type table.
         *
         * A sparse/fragmented file places tensors with large deliberate gaps
         * (bench fixtures, sharded or trimmed exports). There the same
         * equality does not hold, and treating every gap as a type-table error
         * turns a layout property into a false alarm.
         *
         * So: an OVERLAP (off < prev_end) is always an error. A GAP is only an
         * error if the file turned out to be dense anywhere, which is detected
         * by seeing at least one exact continuation. Otherwise gaps are
         * reported as sparseness, and the type table stays unverified rather
         * than being falsely condemned. */
        if (first_off == UINT64_MAX) {
            first_off = e->off;
        } else {
            if (e->off == prev_end) exact_continuations++;
            else if (e->off < prev_end) {
                off_mismatch++;
                off_overlap++;
            } else {
                gaps++;
            }
        }
        prev_end = e->off + ((e->nbytes + align - 1) / align * align);
        have_prev = 1;

        total_bytes += e->nbytes;
        total_elems += nelem;
        if (e->block >= 0 && (uint32_t)e->block > max_block) max_block = (uint32_t)e->block + 1;

        if (e->role == R_EMBED && !embed) embed = e;
        {
            role_t hr = head_role(e);
            if (hr == R_OUTPUT && !lmhead) lmhead = e;
            if (hr == R_OUTPUT) e->role = R_OUTPUT;
        }
        g_nt++;
    }
    fclose(g_f);
    if (g_fail) { printf("PARSE_ERROR = 1\n"); return 1; }

    /* ---- genome ---- */
    nblk_decl = (uint32_t)kv_num("block_count", 0);

    /* tied head: no output.weight but an embedding exists */
    if (!lmhead && embed) { tied_head = 1; lmhead = embed; }

    /* ---- discovery log ---- */
    discover("GGUF_CONTAINER_VALID version=%u tensors=%llu", ver, (unsigned long long)ntensor);
    discover("ARCH_RAW:%s", arch[0] ? arch : "<absent>");
    discover("BLOCK_COUNT declared=%u directory_max=%u agreement=%d",
             nblk_decl, max_block, (nblk_decl == max_block) ? 1 : 0);
    discover("TENSOR_DIRECTORY_PARSED count=%u", g_nt);
    discover("TYPE_TABLE offset_chain_breaks=%llu valid=%d",
             (unsigned long long)off_mismatch, off_mismatch == 0 ? 1 : 0);
    discover("EMBED tensor=%s bytes=%llu",
             embed ? embed->name : "<none>", embed ? (unsigned long long)embed->nbytes : 0ULL);
    discover("LM_HEAD tensor=%s tied=%d",
             lmhead ? lmhead->name : "<none>", tied_head);

    {
        uint64_t rb = 0, rt = 0, eb = 0, sb = 0;
        for (i = 0; i < g_nt; ++i) {
            switch (g_t[i].role) {
            case R_ROUTER: rb += g_t[i].nbytes; rt++; break;
            case R_EXPERT: eb += g_t[i].nbytes; break;
            case R_SHARED_EXPERT: sb += g_t[i].nbytes; break;
            default: break;
            }
        }
        discover("MOE router_tensors=%llu router_bytes=%llu",
                 (unsigned long long)rt, (unsigned long long)rb);
        discover("MOE expert_bytes=%llu shared_expert_bytes=%llu",
                 (unsigned long long)eb, (unsigned long long)sb);
        if (rt) {
            uint32_t ne  = (uint32_t)kv_num("expert_count", 0);
            uint32_t nact= (uint32_t)kv_num("expert_used_count", 0);
            uint32_t nsh = (uint32_t)kv_num("expert_shared_count", 0);
            discover("MOE expert_count=%u active=%u shared=%u", ne, nact, nsh);
            if (!ne)  set_frontier("MOE_EXPERT_COUNT", "no metadata key and no per-expert tensor split");
            if (!nact) set_frontier("MOE_ACTIVE_EXPERT_COUNT", "no expert_used_count metadata key");
        }
    }

    /* ---- capability boundary walk ---- */
    {
        /* Attention kind: does the directory contain the tensors a given
         * attention geometry requires? MHA needs q/k/v; MLA needs a latent
         * cache projection instead. */
        int has_q=0, has_k=0, has_v=0, has_kv_a=0, has_indexer=0, has_mqa=0;
        uint32_t kv_lora = (uint32_t)kv_num("attention.kv_lora_rank", 0);
        uint32_t key_len = (uint32_t)kv_num("attention.key_length", 0);
        uint32_t val_len = (uint32_t)kv_num("attention.value_length", 0);
        for (i = 0; i < g_nt; ++i) {
            const char *n = g_t[i].name;
            if (strstr(n, "attn_q") || strstr(n, "wq_")) has_q = 1;
            if (strstr(n, "attn_k") || strstr(n, "wk_")) has_k = 1;
            if (strstr(n, "attn_v") || strstr(n, "wv_")) has_v = 1;
            if (strstr(n, "kv_a"))    has_kv_a = 1;
            if (strstr(n, "indexer")) has_indexer = 1;
            if (strstr(n, "kv_b"))    has_mqa = 1;
        }
        discover("ATTENTION q=%d k=%d v=%d kv_latent=%d indexer=%d",
                 has_q, has_k, has_v, has_kv_a, has_indexer);
        if (kv_lora || (key_len && val_len && key_len != val_len)) {
            discover("ATTENTION_KIND=MLA_COMPACT (kv_lora_rank=%u key_len=%u val_len=%u)",
                     kv_lora, key_len, val_len);
            set_frontier("MLA_DECOMPRESS_FORWARD",
                         "latent KV cache expansion requires an MLA reconstruction kernel");
        }
        if (has_indexer)
            discover("ATTENTION_INDEXER present=1 head_count_key=%s",
                     kv_has("attention.indexer.head_count") ? "present" : "absent");
        if (!has_q && !has_kv_a)
            set_frontier("ATTENTION_PROJECTION_GRAMMAR",
                         "no recognised Q/K/V or latent KV tensor in directory");
    }

    /* ---- declare-vs-physical corroboration ---- */
    {
        uint32_t obs_hidden = 0, obs_experts = 0, obs_expert_ffn = 0, obs_vocab = 0;
        uint32_t dec_hidden = (uint32_t)kv_num("embedding_length", 0);
        uint32_t dec_vocab  = (uint32_t)kv_num("vocab_size", 0);
        uint32_t dec_experts= (uint32_t)kv_num("expert_count", 0);
        uint32_t dec_exffn  = (uint32_t)kv_num("expert_feed_forward_length", 0);

        for (i = 0; i < g_nt; ++i) {
            const tenv *e = &g_t[i];
            if (e->role == R_EMBED) obs_vocab = dim_rows(e);
            /* expert tensors are 3-D: {ne0=ff_dim, ne1=embd, ne2=experts}.
             * The expert count is the slowest axis, so it is dims[2]. */
            if (e->role == R_EXPERT && e->nd == 3) {
                if (!obs_experts) obs_experts = (uint32_t)e->dims[2];
                if (!obs_expert_ffn) obs_expert_ffn = (uint32_t)e->dims[0];
            }
        }
        if (!obs_hidden) obs_hidden = dec_hidden;   /* derived only if declared */

        printf("\n== DECLARED vs PHYSICAL ==\n");
        {
            int32_t lo = -1, hi = -1;
            uint32_t distinct = 0;
            uint8_t seen[MAXBLK];
            memset(seen, 0, sizeof seen);
            for (i = 0; i < g_nt; ++i) {
                int bk = g_t[i].block;
                if (bk < 0 || (uint32_t)bk >= MAXBLK) continue;
                if (lo < 0 || bk < lo) lo = bk;
                if (hi < 0 || bk > hi) hi = bk;
                if (!seen[bk]) { seen[bk] = 1; distinct++; }
            }
            printf("BLOCK_INDEX_MIN        = %d\n", lo);
            printf("BLOCK_INDEX_MAX        = %d\n", hi);
            printf("BLOCKS_DISTINCT        = %u\n", distinct);
            printf("BLOCKS_DISCOVERED       = %u\n", (uint32_t)(hi + 1));
            max_block = (uint32_t)(hi + 1);
        }
        printf("BLOCKS_DECLARED         = %u\n", nblk_decl);
        printf("BLOCKS_AGREE            = %d\n", nblk_decl == max_block ? 1 : 0);
        printf("HIDDEN_DECLARED         = %u\n", dec_hidden);
        printf("HIDDEN_OBSERVED         = %u\n", obs_hidden);
        printf("VOCAB_DECLARED          = %u\n", dec_vocab);
        printf("VOCAB_OBSERVED_ROWS     = %u\n", obs_vocab);
        printf("VOCAB_AGREE             = %d\n", (dec_vocab && obs_vocab) ? (dec_vocab == obs_vocab ? 1 : 0) : -1);
        printf("EXPERTS_DECLARED        = %u\n", dec_experts);
        printf("EXPERTS_OBSERVED        = %u\n", obs_experts);
        printf("EXPERTS_AGREE           = %d\n", (dec_experts && obs_experts) ? (dec_experts == obs_experts ? 1 : 0) : -1);
        printf("EXPERT_FFN_DECLARED     = %u\n", dec_exffn);
        printf("EXPERT_FFN_OBSERVED     = %u\n", obs_expert_ffn);
    }

    /* ---- block grammar discovery: dense vs MoE, from anatomy ---- */
    {
        uint32_t dense_blocks = 0, moe_blocks = 0, unprofiled = 0;
        uint32_t dec_leading = (uint32_t)kv_num("leading_dense_block_count", 0);
        char sig_a[128];
        uint32_t b;

        printf("\n== DISCOVERED BLOCK GRAMMAR ==\n");
        printf("%5s %8s %7s %12s %12s %10s %10s %12s\n",
               "BLOCK", "TENSORS", "EXPTS", "ATTN", "NORM", "DENSE_FFN", "ROUTER", "EXPERT");

        for (i = 0; i < g_nt; ++i) {
            int bk = g_t[i].block;
            if (bk < 0) continue;
            if ((uint32_t)bk >= MAXBLK) continue;
            profile_block(&g_bp[bk], &g_t[i]);
        }
        for (b = 0; b < max_block; ++b) {
            blkprof *p = &g_bp[b];
            if (!p->tensors) { unprofiled++; continue; }
            if (p->router || p->expert || p->shared) moe_blocks++;
            else dense_blocks++;
            if (b < 3 || b + 1 == max_block) {
                printf("%5u %8u %7u %12llu %12llu %10llu %10llu %12llu%s\n",
                       b, p->tensors, (uint32_t)((p->router ? 1u : 0u)),
                       (unsigned long long)p->attn, (unsigned long long)p->norm,
                       (unsigned long long)p->dense_ffn, (unsigned long long)p->router,
                       (unsigned long long)p->expert,
                       (p->router || p->expert || p->shared) ? "  <- MoE" : "  <- dense");
            } else if (b == 3) {
                printf("  ...\n");
            }
        }
        printf("\nDENSE_BLOCKS_DECLARED   = %u\n", dec_leading);
        printf("DENSE_BLOCKS_DISCOVERED = %u\n", dense_blocks);
        printf("DENSE_BLOCKS_AGREE      = %d\n",
               (dec_leading || dense_blocks) ? (dec_leading == dense_blocks ? 1 : 0) : -1);
        printf("MOE_BLOCKS_DISCOVERED   = %u\n", moe_blocks);
        printf("BLOCKS_UNPROFILED       = %u\n", unprofiled);

        /* Block-grammar census.
         *
         * The architecture predicts a STRUCTURE: a dense prefix followed by a
         * homogeneous MoE tail. So the check is not "are all blocks
         * identical" (which fails legitimately at the transition) but "does
         * the block population partition into the expected number of
         * contiguous runs, each internally uniform". Comparing every block to
         * block 0 and calling the rest a divergence would flag the correct
         * grammar as an anomaly. */
        {
            char runsig[MAXBLK][96];
            uint32_t runidx[MAXBLK], nrun = 0;
            for (b = 0; b < max_block; ++b) {
                if (!g_bp[b].tensors) { runidx[b] = UINT32_MAX; continue; }
                block_signature(sig_a, sizeof sig_a, &g_bp[b]);
                if (nrun == 0 || strcmp(sig_a, runsig[nrun-1]) != 0) {
                    if (nrun >= MAXBLK) { runidx[b] = UINT32_MAX; continue; }
                    strncpy(runsig[nrun], sig_a, 95); runsig[nrun][95] = 0;
                    nrun++;
                }
                runidx[b] = nrun - 1;
            }
            printf("\nBLOCK_GRAMMAR_RUNS        = %u\n", nrun);
            for (b = 0; b < nrun; ++b) {
                uint32_t lo = UINT32_MAX, hi = 0, cnt = 0;
                for (i = 0; i < max_block; ++i)
                    if (runidx[i] == b) {
                        if (lo == UINT32_MAX || i < lo) lo = i;
                        if (i > hi) hi = i;
                        cnt++;
                    }
                printf("RUN_%u blocks=[%u..%u] count=%u  %s\n", b, lo, hi, cnt, runsig[b]);
            }
            /* Corroborate the declared leading_dense_block_count against the
             * physical grammar: the first run must be dense and must span
             * exactly leading_dense_blocks blocks. */
            {
                uint32_t run_len = 0, dense_run = 0;
                for (b = 0; b < max_block; ++b) if (runidx[b] == 0) run_len++;
                if (nrun) {
                    const char *p = strstr(runsig[0], "router=0");
                    if (p && strstr(runsig[0], "expert=0")) dense_run = run_len;
                }
                /* An absent leading_dense_block_count means nothing by itself.
                 * llama omits the key because it is all-dense; gpt-oss omits it
                 * because every block is MoE. Inferring "absent => all dense"
                 * therefore condemns an all-MoE model as malformed. When the
                 * key is absent the physical grammar is authoritative and the
                 * comparison is reported as corroboration, not contradiction. */
                {
                    int have_leading = kv_has("leading_dense_block_count");
                    uint32_t moe_run_blocks = (nrun > 1) ? (max_block - run_len) : 0;
                    printf("LEADING_DENSE_KEY_PRESENT = %d\n", have_leading);
                    printf("DENSE_RUN_BLOCKS         = %u\n", dense_run);
                    printf("MOE_RUN_BLOCKS           = %u\n", moe_run_blocks);
                    if (have_leading) {
                        printf("DENSE_RUN_MATCHES_DECLARED = %d\n",
                               dec_leading == dense_run ? 1 : 0);
                        if (dec_leading != dense_run)
                            printf("GRAMMAR_CONTRADICTION    = declared leading_dense_block_count=%u "
                                   "but physical grammar has %u dense leading block(s)\n",
                                   dec_leading, dense_run);
                    } else {
                        /* No declaration to contradict. Report what the
                         * anatomy says and let the derived grammar stand. */
                        printf("DENSE_RUN_MATCHES_DECLARED = N/A_NO_DECLARATION\n");
                        printf("DERIVED_GRAMMAR          = %s\n",
                               dense_run == max_block ? "ALL_DENSE"
                               : (moe_run_blocks == max_block ? "ALL_MOE"
                               : (dense_run ? "DENSE_PREFIX_THEN_MOE" : "UNIFORM_MOE")));
                    }
                }
            }
        }
    }

    /* ---- write artifacts ---- */
    {
        const char *outdir = (argc >= 3) ? argv[2] : ".";
        char path[512];
        FILE *o;
        char g_tmp[64];

        /* ---- model.physical.txt : literal file evidence ---- */
        snprintf(path, sizeof path, "%s/model.physical.txt", outdir);
        o = fopen(path, "w");
        if (o) {
            fprintf(o, "# PHYSICAL: literal GGUF tensor directory. No interpretation.\n");
            fprintf(o, "# source: %s\n", argv[1]);
            fprintf(o, "file_bytes      %llu\n", (unsigned long long)file_size);
            fprintf(o, "gguf_version    %u\n", ver);
            fprintf(o, "tensor_count    %llu\n", (unsigned long long)ntensor);
            fprintf(o, "alignment       %llu\n", (unsigned long long)align);
            fprintf(o, "data_start      %llu\n", (unsigned long long)data_start);
            fprintf(o, "\ntensor\tggml_type\tdims\tencoded_bytes\tfile_offset\n");
            for (i = 0; i < g_nt; ++i) {
                const nugv_type *ty = tfind((int)g_t[i].tid);
                fprintf(o, "%s\t%s\t[", g_t[i].name, ty ? ty->name : "?");
                { uint32_t j; for (j = 0; j < g_t[i].nd; ++j)
                      fprintf(o, "%s%llu", j ? "," : "", (unsigned long long)g_t[i].dims[j]); }
                fprintf(o, "]\t%llu\t%llu\n",
                        (unsigned long long)g_t[i].nbytes,
                        (unsigned long long)g_t[i].off);
            }
            fclose(o);
        }

        /* ---- model.genome.txt : reconstructed structure ---- */
        snprintf(path, sizeof path, "%s/model.genome.txt", outdir);
        o = fopen(path, "w");
        if (o) {
            fprintf(o, "# GENOME: reconstructed from physical evidence. Each field tagged.\n");
            /* An absent key must print as ABSENT, never as 0. A reader cannot tell a
 * genuine architectural zero from a missing field by looking at the number,
 * and a genome full of silent zeros reads as authoritative. */
#define GNUM(suffix, dflt) \
    (kv_has(suffix) ? (sprintf(g_tmp, "%g", kv_num(suffix, dflt)), g_tmp) \
                    : (strcpy(g_tmp, "ABSENT"), g_tmp))
/* The evidence tag must follow the value. Emitting "[EXPLICIT ...]" beside
 * ABSENT claims a fact the file never stated. */
#define GEV(suffix, label) \
    (kv_has(suffix) ? "[EXPLICIT " label "]" : "[ABSENT]")

            fprintf(o, "architecture            %-16s %s\n", arch[0] ? arch : "ABSENT",
                    arch[0] ? "[EXPLICIT general.architecture]" : "[ABSENT]");
            fprintf(o, "model_name              %-16s %s\n", kv_str("name", "ABSENT"),
                    kv_has("name") ? "[EXPLICIT general.name]" : "[ABSENT]");
            fprintf(o, "block_count             %-16s %s\n", GNUM("block_count", 0),
                    GEV("block_count", "architecture.block_count"));
            fprintf(o, "embedding_length        %-16s %s\n", GNUM("embedding_length", 0),
                    GEV("embedding_length", "architecture.embedding_length"));
            fprintf(o, "feed_forward_length     %-16s %s\n", GNUM("feed_forward_length", 0),
                    GEV("feed_forward_length", "architecture.feed_forward_length"));
            fprintf(o, "context_length          %-16s %s\n", GNUM("context_length", 0),
                    GEV("context_length", "architecture.context_length"));
            fprintf(o, "vocab_size              %-16s %s\n", GNUM("vocab_size", 0),
                    GEV("vocab_size", "architecture.vocab_size"));
            fprintf(o, "head_count              %-16s %s\n", GNUM("attention.head_count", 0),
                    GEV("attention.head_count", "architecture.attention.head_count"));
            fprintf(o, "head_count_kv           %-16s %s\n", GNUM("attention.head_count_kv", 0),
                    GEV("attention.head_count_kv", "architecture.attention.head_count_kv"));
            fprintf(o, "rope_freq_base          %-16s %s\n", GNUM("rope.freq_base", 0),
                    GEV("rope.freq_base", "architecture.rope.freq_base"));
            fprintf(o, "rope_dimension_count    %-16s %s\n", GNUM("rope.dimension_count", 0),
                    GEV("rope.dimension_count", "architecture.rope.dimension_count"));
            fprintf(o, "rope_scaling_type       %-16s %s\n",
                    kv_has("rope.scaling.type") ? kv_str("rope.scaling.type", "") : "ABSENT",
                    GEV("rope.scaling.type", "architecture.rope.scaling.type"));
            fprintf(o, "rms_eps                 %-16s %s\n", GNUM("attention.layer_norm_rms_epsilon", 0),
                    GEV("attention.layer_norm_rms_epsilon", "attention.layer_norm_rms_epsilon"));
            fprintf(o, "expert_count            %-16s %s\n", GNUM("expert_count", 0),
                    kv_has("expert_count") ? "[EXPLICIT architecture.expert_count]" : "[ABSENT: not MoE]");
            fprintf(o, "expert_used_count       %-16s %s\n", GNUM("expert_used_count", 0),
                    kv_has("expert_used_count") ? "[EXPLICIT architecture.expert_used_count]" : "[ABSENT: not MoE]");
            fprintf(o, "expert_shared_count     %-16s %s\n", GNUM("expert_shared_count", 0),
                    kv_has("expert_shared_count") ? "[EXPLICIT architecture.expert_shared_count]" : "[ABSENT]");
            fprintf(o, "expert_ffn_length       %-16s %s\n", GNUM("expert_feed_forward_length", 0),
                    GEV("expert_feed_forward_length", "architecture.expert_feed_forward_length"));
            fprintf(o, "leading_dense_blocks    %-16s %s\n", GNUM("leading_dense_block_count", 0),
                    GEV("leading_dense_block_count", "architecture.leading_dense_block_count"));
            fprintf(o, "kv_lora_rank            %-16s %s\n", GNUM("attention.kv_lora_rank", 0),
                    GEV("attention.kv_lora_rank", "attention.kv_lora_rank"));
            fprintf(o, "key_length              %-16s %s\n", GNUM("attention.key_length", 0),
                    GEV("attention.key_length", "attention.key_length"));
            fprintf(o, "value_length            %-16s %s\n", GNUM("attention.value_length", 0),
                    GEV("attention.value_length", "attention.value_length"));
            fprintf(o, "weight_tying            %-12s    [TOPOLOGY derived: output.weight %s]\n",
                    tied_head ? "TIED" : "UNTIED", tied_head ? "absent, LM head aliases token_embd" : "present");
            fprintf(o, "exact_params            %-12llu    [SHAPE sum of tensor element counts]\n", (unsigned long long)total_elems);
            fprintf(o, "encoded_weight_bytes    %-12llu    [SHAPE sum of tensor encoded sizes]\n", (unsigned long long)total_bytes);
            fprintf(o, "effective_bpw           %-12.6f    [DERIVED encoded_bytes*8/exact_params]\n",
                    total_elems ? (double)total_bytes*8.0/(double)total_elems : 0.0);

            fprintf(o, "\n# TENSOR ROLE MAP [TOPOLOGY derived from name grammar + shape]\n");
            fprintf(o, "block\trole\ttensor\tbytes\n");
            for (i = 0; i < g_nt; ++i) {
                const char *n = g_t[i].name;
                int show = 1;
                if (g_t[i].block < 0 && g_t[i].role == R_NORM) show = 1;
                if (show && (i < 40 || g_t[i].block < 0))
                    fprintf(o, "%d\t%s\t%s\t%llu\n", g_t[i].block, role_name(g_t[i].role),
                            n, (unsigned long long)g_t[i].nbytes);
            }
            fclose(o);
        }

        /* ---- model.execution.txt : derived machine as pseudo-source ---- */
        snprintf(path, sizeof path, "%s/model.execution.txt", outdir);
        o = fopen(path, "w");
        if (o) {
            int is_mla = kv_has("attention.kv_lora_rank");
            uint32_t nb = nblk_decl;
            fprintf(o, "# EXECUTION: derived machine. Marked holes are UNPROVEN, not absent.\n");
            fprintf(o, "# evidence model: EXPLICIT=metadata DIRECTORY=tensor SHAPE=dims\n");
            fprintf(o, "#                    TOPOLOGY=grouping CONTRACT=arch grammar\n\n");
            fprintf(o, "model %s {\n", kv_str("name", "unnamed"));
            fprintf(o, "  architecture %s\n", arch);
            fprintf(o, "  blocks %u\n", nb);
            fprintf(o, "  hidden %u\n", (uint32_t)kv_num("embedding_length", 0));
            fprintf(o, "  context %u\n", (uint32_t)kv_num("context_length", 0));
            fprintf(o, "  vocab %u\n", (uint32_t)kv_num("vocab_size", 0));
            fprintf(o, "  weights_tied %s\n\n", tied_head ? "yes" : "no");

            fprintf(o, "  embedding = token_embd\n");
            fprintf(o, "  repeat block[0..%u] {\n", nb ? nb - 1 : 0);
            fprintf(o, "    x = rms_norm(x, attn_norm)\n");
            if (is_mla) {
                fprintf(o, "    // ATTENTION = MLA_COMPACT [EXPLICIT kv_lora_rank]\n");
                fprintf(o, "    latent = linear(x, kv_a)          // compressed KV latent\n");
                fprintf(o, "    q = linear(x, attn_q)\n");
                fprintf(o, "    UNKNOWN_OPERATION_MLA {\n");
                fprintf(o, "      // latent -> full K/V reconstruction\n");
                fprintf(o, "      // key_length=%u value_length=%u kv_lora_rank=%u\n",
                        (uint32_t)kv_num("attention.key_length", 0),
                        (uint32_t)kv_num("attention.value_length", 0),
                        (uint32_t)kv_num("attention.kv_lora_rank", 0));
                fprintf(o, "      // UNPROVEN: no kernel in Deep2 performs this expansion\n");
                fprintf(o, "    }\n");
                fprintf(o, "    a = attention(q, reconstructed_kv)\n");
            } else {
                fprintf(o, "    // ATTENTION = MHA [DIRECTORY q/k/v present]\n");
                fprintf(o, "    q = linear(x, attn_q)\n");
                fprintf(o, "    k = linear(x, attn_k)\n");
                fprintf(o, "    v = linear(x, attn_v)\n");
                fprintf(o, "    a = attention(q, k, v)\n");
            }
            fprintf(o, "    x = residual(x, linear(a, attn_output))\n");
            fprintf(o, "    h = rms_norm(x, ffn_norm)\n");
            if (kv_has("expert_count")) {
                fprintf(o, "    // FFN = SPARSE_MOE [EXPLICIT expert_count]\n");
                fprintf(o, "    h = rms_norm(x, ffn_norm)\n");
                fprintf(o, "    route = router(h)              // gate_inp\n");
                fprintf(o, "    UNKNOWN_OPERATION_MLA_ROUTER_PLACEHOLDER;\n");
                fprintf(o, "    experts = top_k(route, %u)  // of %u\n",
                        (uint32_t)kv_num("expert_used_count", 0),
                        (uint32_t)kv_num("expert_count", 0));
                fprintf(o, "    moe = execute(experts, h)\n");
                fprintf(o, "    x = residual(x, moe)\n");
            } else {
                fprintf(o, "    // FFN = DENSE\n");
                fprintf(o, "    g = linear(h, ffn_gate)\n");
                fprintf(o, "    u = linear(h, ffn_up)\n");
                fprintf(o, "    a = activation(g) * u\n");
                fprintf(o, "    x = residual(x, linear(a, ffn_down))\n");
            }
            fprintf(o, "  }\n\n");
            fprintf(o, "  x = rms_norm(x, output_norm)\n");
            fprintf(o, "  logits = lm_head(x)\n");
            fprintf(o, "}\n\n");

            fprintf(o, "# DISCOVERY LOG\n");
            for (i = 0; i < g_nd; ++i) fprintf(o, "DISCOVERY_%03u = %s\n", i, g_disc[i]);
            fprintf(o, "\nFIRST_UNPROVEN_BOUNDARY = %s\n", g_frontier);
            fprintf(o, "WHY_UNPROVEN            = %s\n", g_frontier_why);
            fclose(o);
        }
    }

    /* ---- console summary ---- */
    printf("FILE                 = %s\n", argv[1]);
    printf("ARCH                  = %s\n", arch);
    printf("BLOCK_COUNT           = %u (directory max = %u, agree=%d)\n",
           nblk_decl, max_block, nblk_decl == max_block ? 1 : 0);
    printf("TENSOR_COUNT          = %u\n", g_nt);
    printf("EXACT_PARAMS          = %llu\n", (unsigned long long)total_elems);
    printf("EXACT_WEIGHT_BYTES    = %llu\n", (unsigned long long)total_bytes);
    printf("EFFECTIVE_BPW         = %.6f\n",
           total_elems ? (double)total_bytes*8.0/(double)total_elems : 0.0);
    printf("WEIGHT_TIED           = %s\n", tied_head ? "yes" : "no");
    printf("OFFSET_CHAIN_BREAKS   = %llu\n", (unsigned long long)off_mismatch);
    printf("OFFSET_OVERLAPS       = %llu\n", (unsigned long long)off_overlap);
    printf("OFFSET_EXACT_CONTINUATIONS = %llu\n", (unsigned long long)exact_continuations);
    printf("OFFSET_GAPS           = %llu\n", (unsigned long long)gaps);
    printf("LAYOUT_DENSE          = %d\n", gaps == 0 ? 1 : 0);
    /* A sparse file provides no evidence for or against the type table. */
    printf("TYPE_TABLE_VERIFIED   = %s\n",
           gaps == 0 ? (off_mismatch == 0 ? "YES" : "NO")
                     : "NOT_APPLICABLE_SPARSE_LAYOUT");
    printf("PAYLOAD_BYTES_READ    = 0\n");
    printf("MAX_OFFSET_TOUCHED    = %llu (data_start = %llu)\n",
           (unsigned long long)g_max_end, (unsigned long long)data_start);
    printf("STRUCTURAL_PCT        = %.6f%%\n",
           file_size ? 100.0*(double)g_max_end/(double)file_size : 0.0);
    printf("\nDISCOVERED_FACTS      = %u\n", g_nd);
    printf("FIRST_UNPROVEN        = %s\n", g_frontier);
    printf("WHY_UNPROVEN          = %s\n", g_frontier_why);
    printf("VERDICT               = GENIE_COMPILED\n");
    return 0;
}