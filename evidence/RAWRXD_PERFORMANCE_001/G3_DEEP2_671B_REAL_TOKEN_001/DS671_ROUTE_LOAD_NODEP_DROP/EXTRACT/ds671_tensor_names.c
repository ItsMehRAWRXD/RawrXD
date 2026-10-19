#include "ds671_tensor_adapter.h"
#include <stdio.h>
#include <string.h>

uint32_t ds671_blk_from_moe(const ds671_tensor_adapter *a, uint32_t moe_layer) {
    if (!a) return moe_layer;
    return moe_layer + a->leading_dense;
}

int ds671_format_exps_name(char *out, size_t cap, uint32_t blk, uint32_t proj) {
    const char *p = "gate";
    if (!out || !cap) return -1;
    if (proj == DS671_PROJ_UP) p = "up";
    else if (proj == DS671_PROJ_DOWN) p = "down";
    else if (proj != DS671_PROJ_GATE) return -1;
    return snprintf(out, cap, "blk.%u.ffn_%s_exps.weight", blk, p) < 0 ? -1 : 0;
}

const ds671_proj_slot *ds671_find_proj(
    const ds671_tensor_adapter *a, uint32_t blk, uint32_t proj) {
    uint32_t i;
    if (!a || !a->slots) return 0;
    for (i = 0; i < a->slot_count; ++i) {
        if (a->slots[i].blk_layer == blk && a->slots[i].proj == proj)
            return &a->slots[i];
    }
    return 0;
}

/* GGML type -> (block_elems, block_bytes). Fail-closed on unknown. */
static int ds671_ggml_block(uint32_t t, uint32_t *be, uint32_t *bb) {
    switch (t) {
    case 0:  *be = 1;   *bb = 4;   return 0; /* F32 */
    case 1:  *be = 1;   *bb = 2;   return 0; /* F16 */
    case 2:  *be = 32;  *bb = 18;  return 0; /* Q4_0 */
    case 3:  *be = 32;  *bb = 20;  return 0; /* Q4_1 */
    case 8:  *be = 32;  *bb = 34;  return 0; /* Q8_0 */
    case 10: *be = 256; *bb = 84;  return 0; /* Q2_K */
    case 11: *be = 256; *bb = 110; return 0; /* Q3_K */
    case 12: *be = 256; *bb = 144; return 0; /* Q4_K */
    case 13: *be = 256; *bb = 176; return 0; /* Q5_K */
    case 14: *be = 256; *bb = 210; return 0; /* Q6_K */
    case 30: *be = 1;   *bb = 2;   return 0; /* BF16 */
    default: return -1;
    }
}

uint64_t ds671_ggml_bytes_per_expert(
    uint32_t ggml_type, const uint64_t *dims, uint32_t ndims) {
    uint32_t be = 0, bb = 0, i;
    uint64_t elems = 1, blocks;
    if (!dims || ndims < 2) return 0;
    if (ds671_ggml_block(ggml_type, &be, &bb)) return 0;
    /* Expert axis = last dim (DeepSeek-R1 COMPLETE GGUF). */
    for (i = 0; i + 1 < ndims; ++i) {
        if (!dims[i] || elems > (~0ull) / dims[i]) return 0;
        elems *= dims[i];
    }
    blocks = (elems + be - 1) / be;
    if (blocks > (~0ull) / bb) return 0;
    return blocks * (uint64_t)bb;
}
