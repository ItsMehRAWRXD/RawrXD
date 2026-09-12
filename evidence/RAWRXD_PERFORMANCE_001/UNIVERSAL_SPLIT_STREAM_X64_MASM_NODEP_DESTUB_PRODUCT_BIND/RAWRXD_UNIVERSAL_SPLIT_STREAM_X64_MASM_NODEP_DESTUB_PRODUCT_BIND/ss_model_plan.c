/* ss_model_plan.c — single-shard GGUF → SsModelPlan (metadata + roles) */
#include "ss_model_plan.h"
#include "ss_tensor_roles.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { char name[160]; uint64_t rel, dims[4], elems; uint32_t ty, nd; } Ent;
static int rd(FILE *f, void *p, size_t n) { return fread(p, 1, n, f) == n ? 0 : 1; }
static int sk(FILE *f, int64_t n) { return _fseeki64(f, n, SEEK_CUR) ? 1 : 0; }
static int rstr(FILE *f, char *buf, size_t cap)
{
    uint64_t n; if (rd(f, &n, 8) || n >= cap) return 1;
    if (n && rd(f, buf, (size_t)n)) return 1; buf[n] = 0; return 0;
}
static int skip_val_t(FILE *f, uint32_t t)
{
    uint32_t at; uint64_t n, i;
    if (t <= 1 || t == 7 || t == 10) return sk(f, 1);
    if (t <= 3) return sk(f, 2);
    if (t <= 6) return sk(f, 4);
    if (t == 8) { if (rd(f, &n, 8)) return 1; return sk(f, (int64_t)n); }
    if (t == 11 || t == 12) return sk(f, 8);
    if (t != 9) return 1;
    if (rd(f, &at, 4) || rd(f, &n, 8)) return 1;
    for (i = 0; i < n; ++i) {
        if (at == 8) { uint64_t sn; if (rd(f, &sn, 8) || sk(f, (int64_t)sn)) return 1; }
        else {
            uint64_t sz = (at <= 1 || at == 7 || at == 10) ? 1 : (at <= 3 ? 2 : (at <= 6 ? 4 : 8));
            if (sk(f, (int64_t)sz)) return 1;
        }
    }
    return 0;
}
static int skip_val(FILE *f)
{
    uint32_t t; if (rd(f, &t, 4)) return 1; return skip_val_t(f, t);
}
static uint32_t map_codec(uint32_t ty)
{
    if (ty == 0) return SS_CODEC_F32;
    if (ty == 1) return SS_CODEC_F16;
    if (ty == 12) return SS_CODEC_Q4_K;
    if (ty == 13) return SS_CODEC_Q5_K;
    if (ty == 14) return SS_CODEC_Q6_K;
    return SS_CODEC_UNKNOWN;
}
static uint64_t idhash(const char *n, uint64_t abs, uint64_t bytes, uint32_t ty)
{
    uint64_t h = 14695981039346656037ull; size_t i;
    for (i = 0; n[i]; ++i) { h ^= (unsigned char)n[i]; h *= 1099511628211ull; }
    h ^= abs; h *= 1099511628211ull; h ^= bytes; h *= 1099511628211ull; h ^= ty;
    return h;
}
static void fill_ref(SsTensorRef *r, const Ent *e, uint64_t base, uint64_t bytes)
{
    uint32_t i;
    memset(r, 0, sizeof *r);
    r->present = 1; r->fileOffset = base + e->rel; r->bytes = bytes;
    r->nDims = e->nd; r->codec = map_codec(e->ty);
    for (i = 0; i < e->nd && i < 4; ++i) r->dims[i] = e->dims[i];
    r->identity = idhash(e->name, r->fileOffset, r->bytes, e->ty);
}
static SsTensorRef *role_slot(SsBlockPlan *b, SsTensorRole role)
{
    switch (role) {
    case SS_ROLE_ATTN_NORM: return &b->attnNorm;
    case SS_ROLE_Q_A: return &b->qA;
    case SS_ROLE_Q_B: return &b->qB;
    case SS_ROLE_Q_A_NORM: return &b->qANorm;
    case SS_ROLE_KV_A: return &b->kvA;
    case SS_ROLE_KV_B: return &b->kvB;
    case SS_ROLE_KV_A_NORM: return &b->kvANorm;
    case SS_ROLE_ATTN_OUT: return &b->attnOut;
    case SS_ROLE_FFN_NORM: return &b->ffnNorm;
    case SS_ROLE_ROUTER: return &b->router;
    case SS_ROLE_EXPERT_GATE: return &b->expertGate;
    case SS_ROLE_EXPERT_UP: return &b->expertUp;
    case SS_ROLE_EXPERT_DOWN: return &b->expertDown;
    case SS_ROLE_SHARED_GATE: return &b->sharedGate;
    case SS_ROLE_SHARED_UP: return &b->sharedUp;
    case SS_ROLE_SHARED_DOWN: return &b->sharedDown;
    case SS_ROLE_DENSE_GATE: return &b->denseGate;
    case SS_ROLE_DENSE_UP: return &b->denseUp;
    case SS_ROLE_DENSE_DOWN: return &b->denseDown;
    default: return 0;
    }
}
static int kv_u32(FILE *f, uint32_t t, uint32_t *o)
{
    if (t == 4) { uint32_t v; if (rd(f, &v, 4)) return 1; *o = v; return 0; }
    if (t == 5) { int32_t v; if (rd(f, &v, 4)) return 1; *o = (uint32_t)v; return 0; }
    if (t == 11) { uint64_t v; if (rd(f, &v, 8)) return 1; *o = (uint32_t)v; return 0; }
    return skip_val_t(f, t);
}
static int kv_f32(FILE *f, uint32_t t, float *o)
{
    if (t == 6) return rd(f, o, 4);
    return skip_val_t(f, t);
}
static int ends_key(const char *k, const char *suf)
{
    size_t a = strlen(k), b = strlen(suf);
    return a >= b && !strcmp(k + a - b, suf);
}
int ss_model_plan_build(const char *path, SsModelPlan *out)
{
    FILE *f; uint32_t ver, i, j, align = 32; uint64_t nt, nk, base;
    char key[256], arch[SS_ARCH_NAME_MAX]; Ent *e = 0;
    if (!path || !out) return 1;
    memset(out, 0, sizeof *out); arch[0] = 0;
    f = fopen(path, "rb"); if (!f) return 1;
    if (rd(f, key, 4) || memcmp(key, "GGUF", 4) || rd(f, &ver, 4)) goto bad;
    if (rd(f, &nt, 8) || rd(f, &nk, 8) || nt > 200000ull) goto bad;
    for (i = 0; i < (uint32_t)nk; ++i) {
        uint32_t t;
        if (rstr(f, key, sizeof key) || rd(f, &t, 4)) goto bad;
        if (!strcmp(key, "general.alignment") && t == 4) {
            if (rd(f, &align, 4)) goto bad; continue;
        }
        if (!strcmp(key, "general.architecture") && t == 8) {
            if (rstr(f, arch, sizeof arch)) goto bad; continue;
        }
        if (ends_key(key, ".block_count")) { if (kv_u32(f, t, &out->blockCount)) goto bad; continue; }
        if (ends_key(key, ".embedding_length")) { if (kv_u32(f, t, &out->embeddingLength)) goto bad; continue; }
        if (ends_key(key, ".vocab_size")) { if (kv_u32(f, t, &out->vocabSize)) goto bad; continue; }
        if (ends_key(key, ".attention.head_count")) { if (kv_u32(f, t, &out->attentionHeads)) goto bad; continue; }
        if (ends_key(key, ".attention.head_count_kv")) { if (kv_u32(f, t, &out->kvHeads)) goto bad; continue; }
        if (ends_key(key, ".attention.q_lora_rank")) { if (kv_u32(f, t, &out->qLoraRank)) goto bad; continue; }
        if (ends_key(key, ".attention.kv_lora_rank")) { if (kv_u32(f, t, &out->kvLoraRank)) goto bad; continue; }
        if (ends_key(key, ".expert_count")) { if (kv_u32(f, t, &out->expertCount)) goto bad; continue; }
        if (ends_key(key, ".expert_used_count")) { if (kv_u32(f, t, &out->expertTopK)) goto bad; continue; }
        if (ends_key(key, ".expert_shared_count")) { if (kv_u32(f, t, &out->expertSharedCount)) goto bad; continue; }
        if (ends_key(key, ".leading_dense_block_count")) { if (kv_u32(f, t, &out->leadingDenseBlocks)) goto bad; continue; }
        if (ends_key(key, ".rope.dimension_count")) { if (kv_u32(f, t, &out->ropeDim)) goto bad; continue; }
        if (ends_key(key, ".rope.freq_base")) { if (kv_f32(f, t, &out->ropeFreqBase)) goto bad; continue; }
        if (skip_val_t(f, t)) goto bad;
    }
    strncpy(out->architecture, arch, SS_ARCH_NAME_MAX - 1);
    out->metaReal = (out->blockCount && out->embeddingLength && arch[0]) ? 1 : 0;
    if (out->blockCount > SS_MAX_BLOCKS) out->blockCount = SS_MAX_BLOCKS;
    e = (Ent *)calloc((size_t)nt, sizeof(Ent));
    if (!e) goto bad;
    for (i = 0; i < (uint32_t)nt; ++i) {
        uint64_t elems = 1, off, dims[4]; uint32_t nd, ty;
        if (rstr(f, e[i].name, sizeof e[i].name) || rd(f, &nd, 4) || nd > 4) goto bad;
        for (j = 0; j < nd; ++j) { if (rd(f, &dims[j], 8)) goto bad; elems *= dims[j]; e[i].dims[j] = dims[j]; }
        if (rd(f, &ty, 4) || rd(f, &off, 8)) goto bad;
        e[i].nd = nd; e[i].ty = ty; e[i].rel = off; e[i].elems = elems;
    }
    base = (uint64_t)_ftelli64(f);
    base = (base + (uint64_t)align - 1ull) & ~((uint64_t)align - 1ull);
    for (i = 0; i < (uint32_t)nt; ++i) {
        uint64_t best = ~(uint64_t)0, bytes; uint32_t k; SsRoleHit hit; SsTensorRef *slot;
        for (k = 0; k < (uint32_t)nt; ++k)
            if (e[k].rel > e[i].rel && e[k].rel < best) best = e[k].rel;
        bytes = (best != ~(uint64_t)0) ? (best - e[i].rel) : 0;
        if (!bytes) continue;
        if (ss_tensor_role_parse(e[i].name, &hit)) continue;
        if (hit.role == SS_ROLE_TOKEN_EMBD) { fill_ref(&out->tokenEmbedding, &e[i], base, bytes); continue; }
        if (hit.role == SS_ROLE_OUTPUT_NORM) { fill_ref(&out->outputNorm, &e[i], base, bytes); continue; }
        if (hit.role == SS_ROLE_LM_HEAD) { fill_ref(&out->outputWeight, &e[i], base, bytes); continue; }
        if (hit.block < 0 || (uint32_t)hit.block >= SS_MAX_BLOCKS) continue;
        if ((uint32_t)hit.block >= out->blockCount && out->blockCount)
            continue;
        slot = role_slot(&out->blocks[hit.block], hit.role);
        if (!slot) continue;
        fill_ref(slot, &e[i], base, bytes);
        out->blocks[hit.block].rolesBound++;
        if (hit.role == SS_ROLE_ROUTER || hit.role == SS_ROLE_EXPERT_GATE)
            out->blocks[hit.block].isMoe = 1;
    }
    for (i = 0; i < out->blockCount; ++i)
        if (out->blocks[i].attnNorm.present) out->blocksPresent++;
    out->planReal = out->metaReal && out->tokenEmbedding.present && out->outputNorm.present
                    && out->outputWeight.present && out->blocksPresent > 0;
    free(e); fclose(f);
    return out->planReal ? 0 : 1;
bad:
    free(e); if (f) fclose(f); return 1;
}
void ss_model_plan_print(const SsModelPlan *p)
{
    uint32_t i, attn_ok = 0;
    if (!p) return;
    printf("MODEL_PLAN_REAL=%u BLOCK_COUNT_METADATA_REAL=%u ARCH=%s\n",
           p->planReal, p->metaReal, p->architecture);
    printf("EMBEDDING_LENGTH=%u VOCAB_SIZE=%u BLOCK_COUNT=%u BLOCKS_PRESENT_IN_SHARD=%u\n",
           p->embeddingLength, p->vocabSize, p->blockCount, p->blocksPresent);
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
