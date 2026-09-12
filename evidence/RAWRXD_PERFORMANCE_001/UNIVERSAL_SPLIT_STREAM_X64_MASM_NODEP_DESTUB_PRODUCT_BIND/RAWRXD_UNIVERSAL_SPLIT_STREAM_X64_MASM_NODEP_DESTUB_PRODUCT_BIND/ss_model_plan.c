/* ss_model_plan.c — build / build_split / print */
#include "ss_model_plan.h"
#include "ss_model_plan_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void ss_model_plan_recompute(SsModelPlan *p)
{
    uint32_t i;
    if (!p) return;
    p->blocksPresent = 0;
    for (i = 0; i < p->blockCount; ++i)
        if (p->blocks[i].attnNorm.present) p->blocksPresent++;
    p->planReal = p->metaReal && p->tokenEmbedding.present && p->outputNorm.present
                  && p->outputWeight.present && p->blockCount
                  && p->blocksPresent == p->blockCount;
}
static void remember_path(SsModelPlan *p, uint32_t shard_index, const char *path)
{
    if (shard_index >= SS_MAX_SHARDS) return;
    strncpy(p->shardPaths[shard_index], path, SS_SHARD_PATH_MAX - 1);
    if (shard_index + 1 > p->shardCount) p->shardCount = shard_index + 1;
}
int ss_model_plan_build(const char *shard_path, SsModelPlan *out)
{
    if (!shard_path || !out) return 1;
    memset(out, 0, sizeof *out);
    if (ss_mp_build_one(out, shard_path, 0, 1)) return 1;
    remember_path(out, 0, shard_path);
    ss_model_plan_recompute(out);
    return out->planReal ? 0 : 1;
}
static int parse_split(const char *path, char *dir, size_t dcap, char *stem, size_t scap,
                       uint32_t *idx, uint32_t *total)
{
    const char *slash, *base, *of, *dash; size_t n;
    slash = strrchr(path, '\\'); if (!slash) slash = strrchr(path, '/');
    base = slash ? slash + 1 : path;
    n = (size_t)(base - path); if (n >= dcap) return 1;
    memcpy(dir, path, n); dir[n] = 0;
    of = strstr(base, "-of-");
    if (!of || of - base < 6) return 1;
    dash = of - 1;
    while (dash > base && *dash != '-') dash--;
    if (*dash != '-') return 1;
    n = (size_t)(dash - base); if (n >= scap) return 1;
    memcpy(stem, base, n); stem[n] = 0;
    *idx = (uint32_t)strtoul(dash + 1, 0, 10);
    *total = (uint32_t)strtoul(of + 4, 0, 10);
    if (!*idx || !*total || *idx > *total || *total > SS_MAX_SHARDS) return 1;
    return 0;
}
int ss_model_plan_build_split(const char *shard1_path, SsModelPlan *out)
{
    char dir[512], stem[256], path[SS_SHARD_PATH_MAX]; uint32_t idx, total, i;
    if (!shard1_path || !out) return 1;
    memset(out, 0, sizeof *out);
    if (parse_split(shard1_path, dir, sizeof dir, stem, sizeof stem, &idx, &total))
        return ss_model_plan_build(shard1_path, out);
    for (i = 1; i <= total; ++i) {
        sprintf(path, "%s%s-%05u-of-%05u.gguf", dir, stem, i, total);
        if (i == 1) {
            if (ss_mp_build_one(out, path, 0, 1)) return 1;
            remember_path(out, 0, path);
        } else {
            if (ss_model_plan_merge_shard(out, path, i - 1)) {
                ss_model_plan_recompute(out);
                return 1;
            }
            remember_path(out, i - 1, path);
        }
    }
    ss_model_plan_recompute(out);
    return out->planReal ? 0 : 1;
}
int ss_model_plan_build_multi(const char *shard1_path, SsModelPlan *out)
{
    return ss_model_plan_build_split(shard1_path, out);
}
void ss_model_plan_print(const SsModelPlan *p)
{
    uint32_t i, attn_ok = 0;
    if (!p) return;
    printf("MODEL_PLAN_REAL=%u BLOCK_COUNT_METADATA_REAL=%u ARCH=%s\n",
           p->planReal, p->metaReal, p->architecture);
    printf("EMBEDDING_LENGTH=%u VOCAB_SIZE=%u BLOCK_COUNT=%u\n",
           p->embeddingLength, p->vocabSize, p->blockCount);
    printf("BLOCKS_PRESENT=%u BLOCKS_EXPECTED=%u SHARDS_MERGED=%u\n",
           p->blocksPresent, p->blockCount, p->shardsMerged);
    printf("ATTN_HEADS=%u KV_HEADS=%u Q_LORA=%u KV_LORA=%u ROPE_DIM=%u\n",
           p->attentionHeads, p->kvHeads, p->qLoraRank, p->kvLoraRank, p->ropeDim);
    printf("EXPERT_COUNT=%u EXPERT_TOPK=%u SHARED=%u LEADING_DENSE=%u\n",
           p->expertCount, p->expertTopK, p->expertSharedCount, p->leadingDenseBlocks);
    printf("TOKEN_EMBD_PRESENT=%d OUTPUT_NORM_PRESENT=%d LM_HEAD_PRESENT=%d\n",
           p->tokenEmbedding.present, p->outputNorm.present, p->outputWeight.present);
    for (i = 0; i < p->blockCount && i < 8; ++i) {
        const SsBlockPlan *b = &p->blocks[i];
        printf("BLOCK_%u roles=%u moe=%u attn_norm=%d q_a=%d kv_a=%d attn_out=%d ffn_norm=%d\n",
               i, b->rolesBound, b->isMoe, b->attnNorm.present, b->qA.present,
               b->kvA.present, b->attnOut.present, b->ffnNorm.present);
        if (b->attnNorm.present && b->qA.present && b->kvA.present && b->attnOut.present)
            attn_ok++;
    }
    printf("ATTENTION_LAYOUT_BOUND_SAMPLE=%u FULL_MODEL_FORWARD=0 ABBREVIATED_CHAIN=1 PROMOTE=0\n",
           attn_ok);
}
void ss_model_plan_print_inventory(const SsModelPlan *p)
{
    uint32_t i, moe = 0, dense = 0;
    if (!p) return;
    for (i = 0; i < p->blockCount; ++i) {
        if (p->blocks[i].isMoe) moe++;
        else if (p->blocks[i].denseGate.present) dense++;
    }
    printf("MULTI_SHARD_INVENTORY_PASS=%u SHARD_COUNT=%u MOE_BLOCKS=%u DENSE_BLOCKS=%u\n",
           p->planReal, p->shardCount, moe, dense);
    printf("FULL_MODEL_FORWARD=0 ATTENTION_REAL=0 KV_CACHE_REAL=0 MOE_ROUTER_REAL=0\n");
}
