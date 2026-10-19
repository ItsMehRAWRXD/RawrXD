#include "ds671_gguf_index.h"
#include "ds671_gguf_rd.h"
#include "ds671_tensor_adapter.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int ds671_gguf_scan_shard_exps(
    const char *path, uint32_t shard_index,
    ds671_proj_slot *slots, uint32_t cap, uint32_t *count_io,
    uint64_t *data_offset_out) {
    FILE *f; char magic[4], name[256];
    uint32_t ver, vt, nd, tt, i, d, n, start;
    uint64_t n_ten, n_kv, dims[8], off, pos, base;

    if (!path || !slots || !count_io) return -1;
    n = *count_io; start = n;
    f = fopen(path, "rb");
    if (!f) return -2;
    if (ds671_gguf_rd(f, magic, 4) || ds671_gguf_ru32(f, &ver) ||
        ds671_gguf_ru64(f, &n_ten) || ds671_gguf_ru64(f, &n_kv)) {
        fclose(f); return -3;
    }
    for (i = 0; i < (uint32_t)n_kv; ++i) {
        if (ds671_gguf_rstr(f, name, sizeof(name)) ||
            ds671_gguf_ru32(f, &vt) || ds671_gguf_skipv(f, vt)) {
            fclose(f); return -4;
        }
    }
    for (i = 0; i < (uint32_t)n_ten; ++i) {
        uint32_t blk = 0, proj = 0;
        if (ds671_gguf_rstr(f, name, sizeof(name)) ||
            ds671_gguf_ru32(f, &nd)) { fclose(f); return -5; }
        if (nd > 8) { fclose(f); return -6; }
        for (d = 0; d < nd; ++d)
            if (ds671_gguf_ru64(f, &dims[d])) { fclose(f); return -7; }
        if (ds671_gguf_ru32(f, &tt) || ds671_gguf_ru64(f, &off)) {
            fclose(f); return -8;
        }
        if (ds671_gguf_parse_exps(name, &blk, &proj) == 0 && n < cap) {
            ds671_proj_slot *s = &slots[n++];
            memset(s, 0, sizeof(*s));
            s->blk_layer = blk; s->proj = proj;
            s->shard_index = shard_index; s->ggml_type = tt;
            s->num_experts = nd ? (uint32_t)dims[nd - 1] : 0;
            s->bytes_per_expert = ds671_ggml_bytes_per_expert(tt, dims, nd);
            s->file_offset = off;
        }
    }
    pos = (uint64_t)ftell(f);
    base = pos + ((32 - (pos % 32)) % 32);
    if (data_offset_out) *data_offset_out = base;
    for (i = start; i < n; ++i) slots[i].file_offset += base;
    *count_io = n;
    fclose(f);
    return 0;
}
