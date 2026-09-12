/* deep2_kv_guard.c — reject OOB / stale-generation KV access */
#include "deep2_kv_guard.h"
#include <string.h>
void d2_kv_init(D2KvGuard *k, uint64_t epoch, uint32_t layers, uint32_t max_pos)
{
    memset(k, 0, sizeof *k);
    k->epoch = epoch; k->gen = 1;
    k->layers = layers > D2_KV_MAX_LAYER ? D2_KV_MAX_LAYER : layers;
    k->max_pos = max_pos;
}
int d2_kv_append(D2KvGuard *k, uint32_t layer, uint32_t pos, uint64_t gen)
{
    if (!k) return 0;
    if (gen != k->gen) { k->fail = "KV_STALE_GENERATION"; return 0; }
    if (layer >= k->layers) { k->fail = "KV_LAYER_OOB"; return 0; }
    if (pos >= k->max_pos) { k->fail = "KV_POS_OOB"; return 0; }
    if (pos != k->layer_pos[layer] && pos != k->cur_pos) {
        if (pos < k->layer_pos[layer]) { k->fail = "KV_OVERWRITE"; return 0; }
    }
    k->layer_pos[layer] = pos + 1u;
    k->appends++;
    return 1;
}
int d2_kv_read(D2KvGuard *k, uint32_t layer, uint32_t pos, uint64_t gen)
{
    if (!k) return 0;
    if (gen != k->gen) { k->fail = "KV_STALE_GENERATION"; return 0; }
    if (layer >= k->layers || pos >= k->layer_pos[layer]) {
        k->fail = "KV_READ_UNWRITTEN"; return 0;
    }
    k->reads++;
    return 1;
}
int d2_kv_advance(D2KvGuard *k, uint32_t next_pos)
{
    if (!k) return 0;
    if (next_pos != k->cur_pos + 1u && !(k->cur_pos == 0 && next_pos == 0)) {
        if (next_pos < k->cur_pos) { k->fail = "KV_POS_REGRESS"; return 0; }
    }
    k->cur_pos = next_pos;
    return 1;
}
int d2_kv_reset(D2KvGuard *k, uint64_t new_gen)
{
    uint32_t L;
    if (!k || new_gen == k->gen) { if (k) k->fail = "KV_RESET_SAME_GEN"; return 0; }
    L = k->layers;
    memset(k->layer_pos, 0, sizeof k->layer_pos);
    k->cur_pos = 0; k->gen = new_gen; k->resets++;
    k->layers = L; k->fail = 0;
    return 1;
}
