/* ds671_gguf_classify.c — name-pattern classify walk */
#include "ds671_gguf_scan_priv.h"
#include <string.h>

static int class_of(const char *n) {
    if (!strcmp(n, "token_embd.weight")) return 0;
    if (!strcmp(n, "output.weight")) return 1;
    if (strstr(n, "norm")) return 6; /* before attn_* so attn_norm counts */
    if (strstr(n, "attn_")) {
        if (strstr(n, "q_a") || strstr(n, "q_b") || strstr(n, "kv_a") ||
            strstr(n, "kv_b") || strstr(n, "k_b") || strstr(n, "v_b")) return 3;
        return 2;
    }
    if (strstr(n, "ffn_gate_exps") || strstr(n, "ffn_up_exps") ||
        strstr(n, "ffn_down_exps") || strstr(n, "ffn_gate_inp") ||
        strstr(n, "ffn_gate_shexp") || strstr(n, "ffn_up_shexp") ||
        strstr(n, "ffn_down_shexp") || strstr(n, "exp_probs_b")) return 5;
    if (strstr(n, "ffn_")) return 4;
    return 7;
}

int gguf_classify_names(const char *path, uint32_t *cls, uint32_t *unres) {
    GgufR r; char magic[4]; uint32_t ver=0; uint64_t nt=0, nk=0, i;
    int rc; memset(cls,0,8*sizeof(uint32_t)); *unres=0;
    if ((rc=gr_open(&r,path))) return rc;
    if (gr_read(&r,magic,4)||memcmp(magic,"GGUF",4)) { gr_close(&r); return GGUF_E_MAGIC; }
    if (gr_u32(&r,&ver)||gr_u64(&r,&nt)||gr_u64(&r,&nk)) { gr_close(&r); return GGUF_E_IO; }
    for (i=0;i<nk;i++) {
        char key[160]; uint32_t t=0;
        if (gr_str(&r,key,sizeof key)||gr_u32(&r,&t)||gr_skip_val(&r,t)) {
            gr_close(&r); return GGUF_E_FMT;
        }
    }
    for (i=0;i<nt;i++) {
        char name[256]; uint32_t nd=0, ty=0, d; uint64_t off=0;
        if (gr_str(&r,name,sizeof name)||gr_u32(&r,&nd)) { gr_close(&r); return GGUF_E_IO; }
        if (nd>4) { gr_close(&r); return GGUF_E_FMT; }
        for (d=0;d<nd;d++) { uint64_t dim; if (gr_u64(&r,&dim)) { gr_close(&r); return GGUF_E_IO; } }
        if (gr_u32(&r,&ty)||gr_u64(&r,&off)) { gr_close(&r); return GGUF_E_IO; }
        if (!name[0]) { (*unres)++; continue; }
        cls[class_of(name)]++;
        (void)off; (void)ty;
    }
    gr_close(&r);
    return GGUF_OK;
}
