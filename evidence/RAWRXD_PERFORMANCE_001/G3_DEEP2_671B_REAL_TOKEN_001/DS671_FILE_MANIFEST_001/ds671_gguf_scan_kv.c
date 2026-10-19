/* ds671_gguf_scan_kv.c */
#include "ds671_gguf_scan_priv.h"
#include <string.h>

static int skip_array(GgufR *r) {
    uint32_t et = 0; uint64_t n = 0, i;
    if (gr_u32(r, &et) || gr_u64(r, &n)) return GGUF_E_IO;
    for (i = 0; i < n; i++) if (gr_skip_val(r, et)) return GGUF_E_FMT;
    return GGUF_OK;
}
int gr_skip_val(GgufR *r, uint32_t t) {
    switch (t) {
    case 0: case 1: case 7: return gr_skip(r, 1);
    case 2: case 3: return gr_skip(r, 2);
    case 4: case 5: case 6: return gr_skip(r, 4);
    case 10: case 11: case 12: return gr_skip(r, 8);
    case 8: return gr_str(r, 0, 0);
    case 9: return skip_array(r);
    default: return GGUF_E_FMT;
    }
}
static void take_u32(GgufShardInfo *o, const char *k, uint32_t v) {
    if (!strcmp(k, "deepseek2.block_count")) o->block_count = v;
    else if (!strcmp(k, "deepseek2.expert_count")) o->expert_count = v;
    else if (!strcmp(k, "deepseek2.expert_used_count")) o->expert_used = v;
    else if (!strcmp(k, "deepseek2.expert_shared_count")) o->expert_shared = v;
    else if (!strcmp(k, "deepseek2.leading_dense_block_count")) o->leading_dense = v;
    else if (!strcmp(k, "deepseek2.embedding_length")) o->embedding_length = v;
    else if (!strcmp(k, "deepseek2.vocab_size")) o->vocab_size = v;
    else if (!strcmp(k, "deepseek2.attention.q_lora_rank")) o->q_lora_rank = v;
    else if (!strcmp(k, "deepseek2.attention.kv_lora_rank")) o->kv_lora_rank = v;
}
int gr_scan_kv(GgufR *r, GgufShardInfo *o, uint64_t n_kv) {
    uint64_t i;
    for (i = 0; i < n_kv; i++) {
        char key[160]; uint32_t t = 0;
        if (gr_str(r, key, sizeof key) || gr_u32(r, &t)) return GGUF_E_IO;
        if (!strcmp(key, "general.architecture") && t == 8) {
            if (gr_str(r, o->architecture, sizeof o->architecture)) return GGUF_E_IO;
        } else if (t == 4) {
            uint32_t v = 0;
            if (gr_u32(r, &v)) return GGUF_E_IO;
            take_u32(o, key, v);
        } else if (gr_skip_val(r, t)) { o->unresolved_kv++; return GGUF_E_FMT; }
    }
    return GGUF_OK;
}
