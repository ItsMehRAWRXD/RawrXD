/* ss_model_plan_io.c — GGUF IO helpers for model plan */
#include "ss_model_plan_io.h"
#include <string.h>
int ss_mp_rd(FILE *f, void *p, size_t n) { return fread(p, 1, n, f) == n ? 0 : 1; }
int ss_mp_sk(FILE *f, int64_t n) { return _fseeki64(f, n, SEEK_CUR) ? 1 : 0; }
int ss_mp_rstr(FILE *f, char *buf, size_t cap)
{
    uint64_t n; if (ss_mp_rd(f, &n, 8) || n >= cap) return 1;
    if (n && ss_mp_rd(f, buf, (size_t)n)) return 1; buf[n] = 0; return 0;
}
int ss_mp_skip_val_t(FILE *f, uint32_t t)
{
    uint32_t at; uint64_t n, i;
    if (t <= 1 || t == 7 || t == 10) return ss_mp_sk(f, 1);
    if (t <= 3) return ss_mp_sk(f, 2);
    if (t <= 6) return ss_mp_sk(f, 4);
    if (t == 8) { if (ss_mp_rd(f, &n, 8)) return 1; return ss_mp_sk(f, (int64_t)n); }
    if (t == 11 || t == 12) return ss_mp_sk(f, 8);
    if (t != 9) return 1;
    if (ss_mp_rd(f, &at, 4) || ss_mp_rd(f, &n, 8)) return 1;
    for (i = 0; i < n; ++i) {
        if (at == 8) { uint64_t sn; if (ss_mp_rd(f, &sn, 8) || ss_mp_sk(f, (int64_t)sn)) return 1; }
        else {
            uint64_t sz = (at <= 1 || at == 7 || at == 10) ? 1 : (at <= 3 ? 2 : (at <= 6 ? 4 : 8));
            if (ss_mp_sk(f, (int64_t)sz)) return 1;
        }
    }
    return 0;
}
int ss_mp_kv_u32(FILE *f, uint32_t t, uint32_t *o)
{
    if (t == 4) { uint32_t v; if (ss_mp_rd(f, &v, 4)) return 1; *o = v; return 0; }
    if (t == 5) { int32_t v; if (ss_mp_rd(f, &v, 4)) return 1; *o = (uint32_t)v; return 0; }
    if (t == 11) { uint64_t v; if (ss_mp_rd(f, &v, 8)) return 1; *o = (uint32_t)v; return 0; }
    return ss_mp_skip_val_t(f, t);
}
int ss_mp_kv_f32(FILE *f, uint32_t t, float *o)
{
    if (t == 6) return ss_mp_rd(f, o, 4);
    return ss_mp_skip_val_t(f, t);
}
int ss_mp_ends_key(const char *k, const char *suf)
{
    size_t a = strlen(k), b = strlen(suf);
    return a >= b && !strcmp(k + a - b, suf);
}
uint32_t ss_mp_map_codec(uint32_t ty)
{
    if (ty == 0) return SS_CODEC_F32;
    if (ty == 1) return SS_CODEC_F16;
    if (ty == 12) return SS_CODEC_Q4_K;
    if (ty == 13) return SS_CODEC_Q5_K;
    if (ty == 14) return SS_CODEC_Q6_K;
    return SS_CODEC_UNKNOWN;
}
uint64_t ss_mp_tensor_nbytes(uint32_t ty, uint64_t elems)
{
    uint64_t nb;
    if (ty == 0) return elems * 4ull;
    if (ty == 1) return elems * 2ull;
    if (ty == 12) { nb = (elems + 255ull) / 256ull; return nb * 144ull; }
    if (ty == 13) { nb = (elems + 255ull) / 256ull; return nb * 192ull; }
    if (ty == 14) { nb = (elems + 255ull) / 256ull; return nb * 210ull; }
    return 0;
}
void ss_mp_fill_ref(SsTensorRef *r, const SsPlanEnt *e, uint64_t base, uint64_t bytes,
                    uint32_t shard_index)
{
    uint32_t i; uint64_t h = 14695981039346656037ull; size_t n;
    memset(r, 0, sizeof *r);
    r->present = 1; r->fileOffset = base + e->rel; r->bytes = bytes;
    r->nDims = e->nd; r->codec = ss_mp_map_codec(e->ty); r->shardIndex = shard_index;
    for (i = 0; i < e->nd && i < 4; ++i) r->dims[i] = e->dims[i];
    for (n = 0; e->name[n]; ++n) { h ^= (unsigned char)e->name[n]; h *= 1099511628211ull; }
    h ^= r->fileOffset; h *= 1099511628211ull; h ^= bytes; h *= 1099511628211ull;
    h ^= e->ty; h ^= ((uint64_t)shard_index << 32); r->identity = h;
}
SsTensorRef *ss_mp_role_slot(SsBlockPlan *b, SsTensorRole role)
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
    case SS_ROLE_EXP_PROBS_BIAS: return &b->expProbsB;
    default: return 0;
    }
}
