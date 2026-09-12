/* ss_model_plan_meta.c — GGUF KV metadata → SsModelPlan fields */
#include "ss_model_plan_io.h"
#include <string.h>
int ss_mp_read_meta(FILE *f, SsModelPlan *out, char *arch, uint32_t *align,
                    uint64_t *nt, int read_meta)
{
    uint32_t ver, i, t; uint64_t nk; char key[256];
    if (ss_mp_rd(f, key, 4) || memcmp(key, "GGUF", 4) || ss_mp_rd(f, &ver, 4)) return 1;
    if (ss_mp_rd(f, nt, 8) || ss_mp_rd(f, &nk, 8) || *nt > 200000ull) return 1;
    for (i = 0; i < (uint32_t)nk; ++i) {
        if (ss_mp_rstr(f, key, sizeof key) || ss_mp_rd(f, &t, 4)) return 1;
        if (!strcmp(key, "general.alignment") && t == 4) {
            if (ss_mp_rd(f, align, 4)) return 1; continue;
        }
        if (!read_meta) { if (ss_mp_skip_val_t(f, t)) return 1; continue; }
        if (!strcmp(key, "general.architecture") && t == 8) {
            if (ss_mp_rstr(f, arch, SS_ARCH_NAME_MAX)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".block_count")) {
            if (ss_mp_kv_u32(f, t, &out->blockCount)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".embedding_length")) {
            if (ss_mp_kv_u32(f, t, &out->embeddingLength)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".vocab_size")) {
            if (ss_mp_kv_u32(f, t, &out->vocabSize)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".attention.head_count")) {
            if (ss_mp_kv_u32(f, t, &out->attentionHeads)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".attention.head_count_kv")) {
            if (ss_mp_kv_u32(f, t, &out->kvHeads)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".attention.q_lora_rank")) {
            if (ss_mp_kv_u32(f, t, &out->qLoraRank)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".attention.kv_lora_rank")) {
            if (ss_mp_kv_u32(f, t, &out->kvLoraRank)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".expert_count")) {
            if (ss_mp_kv_u32(f, t, &out->expertCount)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".expert_used_count")) {
            if (ss_mp_kv_u32(f, t, &out->expertTopK)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".expert_shared_count")) {
            if (ss_mp_kv_u32(f, t, &out->expertSharedCount)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".leading_dense_block_count")) {
            if (ss_mp_kv_u32(f, t, &out->leadingDenseBlocks)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".rope.dimension_count")) {
            if (ss_mp_kv_u32(f, t, &out->ropeDim)) return 1; continue;
        }
        if (ss_mp_ends_key(key, ".rope.freq_base")) {
            if (ss_mp_kv_f32(f, t, &out->ropeFreqBase)) return 1; continue;
        }
        if (ss_mp_skip_val_t(f, t)) return 1;
    }
    return 0;
}
