/* ds671_gguf_scan_tensors.c + entry */
#include "ds671_gguf_scan_priv.h"
#include <string.h>

/* ggml type byte sizes for known codes; 0 => unknown */
static uint64_t type_nbytes(uint32_t t, uint64_t ne) {
    /* approximate element bytes for bound checks; Q/K types use block sizes */
    static const uint64_t blk[] = {
        /*0 F32*/4,/*1 F16*/2,/*2 Q4_0*/0,/*3 Q4_1*/0,/*4?*/0,/*5?*/0,
        /*6 Q5_0*/0,/*7 Q5_1*/0,/*8 Q8_0*/0,/*9 Q8_1*/0,
        /*10 Q2_K*/0,/*11 Q3_K*/0,/*12 Q4_K*/0,/*13 Q5_K*/0,/*14 Q6_K*/0,/*15 Q8_K*/0
    };
    if (t < 2) return ne * blk[t];
    (void)blk; return 0; /* quantized: size from file layout, skip size math */
}

int gr_scan_tensors(GgufR *r, GgufShardInfo *o, uint64_t n_tensor) {
    uint64_t i;
    for (i = 0; i < n_tensor; i++) {
        char name[256]; uint32_t nd = 0, ty = 0, d;
        uint64_t off = 0, ne = 1;
        if (gr_str(r, name, sizeof name) || gr_u32(r, &nd)) return GGUF_E_IO;
        if (nd > 4) return GGUF_E_FMT;
        for (d = 0; d < nd; d++) {
            uint64_t dim = 0;
            if (gr_u64(r, &dim)) return GGUF_E_IO;
            if (dim && ne < (UINT64_MAX / dim)) ne *= dim; else if (dim) ne = UINT64_MAX;
        }
        if (gr_u32(r, &ty) || gr_u64(r, &off)) return GGUF_E_IO;
        if (ty < 40) o->quant_hist[ty]++;
        else o->tensor_bad++;
        /* GGUF tensor offset is relative to aligned data section start */
        if (off >= o->file_bytes) o->tensor_bad++;
        else o->tensor_ok++;
        (void)type_nbytes; (void)name; (void)ne;
    }
    /* align to 32 then data */
    {
        uint64_t pad = (32 - (r->pos % 32)) % 32;
        if (pad && gr_skip(r, pad)) return GGUF_E_IO;
        o->data_start = r->pos;
    }
    return GGUF_OK;
}

int gguf_scan_shard(const char *path, GgufShardInfo *out) {
    GgufR r; char magic[4]; uint32_t ver = 0; uint64_t nt = 0, nk = 0; int rc;
    memset(out, 0, sizeof *out);
    if ((rc = gr_open(&r, path))) return rc;
    out->file_bytes = r.size;
    if (gr_read(&r, magic, 4) || memcmp(magic, "GGUF", 4)) { gr_close(&r); return GGUF_E_MAGIC; }
    if (gr_u32(&r, &ver) || ver < 2 || ver > 3) { gr_close(&r); return GGUF_E_VER; }
    out->version = ver;
    if (gr_u64(&r, &nt) || gr_u64(&r, &nk)) { gr_close(&r); return GGUF_E_IO; }
    out->n_tensor = nt; out->n_kv = nk;
    if ((rc = gr_scan_kv(&r, out, nk))) { gr_close(&r); return rc; }
    if ((rc = gr_scan_tensors(&r, out, nt))) { gr_close(&r); return rc; }
    gr_close(&r);
    return GGUF_OK;
}
