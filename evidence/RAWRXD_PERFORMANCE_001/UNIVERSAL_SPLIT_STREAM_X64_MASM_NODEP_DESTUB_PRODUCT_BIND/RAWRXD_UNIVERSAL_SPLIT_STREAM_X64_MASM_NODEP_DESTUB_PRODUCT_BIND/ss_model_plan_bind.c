/* ss_model_plan_bind.c — tensor inventory → SsModelPlan slots */
#include "ss_model_plan_io.h"
#include <stdlib.h>
#include <string.h>
static int take_slot(SsTensorRef *slot, const SsPlanEnt *e, uint64_t base, uint64_t bytes,
                     uint32_t shard_index)
{
    if (slot->present) return 0;
    ss_mp_fill_ref(slot, e, base, bytes, shard_index);
    return 1;
}
int ss_mp_bind_tensors(SsModelPlan *out, SsPlanEnt *e, uint32_t nt, uint64_t base,
                       uint32_t shard_index, int allow_meta_overwrite)
{
    uint32_t i, k;
    (void)allow_meta_overwrite;
    for (i = 0; i < nt; ++i) {
        uint64_t best = ~(uint64_t)0, bytes; SsRoleHit hit; SsTensorRef *slot;
        for (k = 0; k < nt; ++k)
            if (e[k].rel > e[i].rel && e[k].rel < best) best = e[k].rel;
        bytes = (best != ~(uint64_t)0) ? (best - e[i].rel) : 0;
        if (!bytes) continue;
        if (ss_tensor_role_parse(e[i].name, &hit)) continue;
        if (hit.role == SS_ROLE_TOKEN_EMBD) {
            take_slot(&out->tokenEmbedding, &e[i], base, bytes, shard_index); continue;
        }
        if (hit.role == SS_ROLE_OUTPUT_NORM) {
            take_slot(&out->outputNorm, &e[i], base, bytes, shard_index); continue;
        }
        if (hit.role == SS_ROLE_LM_HEAD) {
            take_slot(&out->outputWeight, &e[i], base, bytes, shard_index); continue;
        }
        if (hit.block < 0 || (uint32_t)hit.block >= SS_MAX_BLOCKS) continue;
        if (out->blockCount && (uint32_t)hit.block >= out->blockCount) continue;
        slot = ss_mp_role_slot(&out->blocks[hit.block], hit.role);
        if (!slot) continue;
        if (take_slot(slot, &e[i], base, bytes, shard_index))
            out->blocks[hit.block].rolesBound++;
        if (hit.role == SS_ROLE_ROUTER || hit.role == SS_ROLE_EXPERT_GATE)
            out->blocks[hit.block].isMoe = 1;
    }
    return 0;
}
static int load_ents(FILE *f, SsPlanEnt **out_e, uint32_t nt, uint32_t align, uint64_t *base_out)
{
    SsPlanEnt *e; uint32_t i, j; uint64_t base;
    e = (SsPlanEnt *)calloc((size_t)nt, sizeof(SsPlanEnt));
    if (!e) return 1;
    for (i = 0; i < nt; ++i) {
        uint64_t elems = 1, off, dims[4]; uint32_t nd, ty;
        if (ss_mp_rstr(f, e[i].name, sizeof e[i].name) || ss_mp_rd(f, &nd, 4) || nd > 4)
            { free(e); return 1; }
        for (j = 0; j < nd; ++j) {
            if (ss_mp_rd(f, &dims[j], 8)) { free(e); return 1; }
            elems *= dims[j]; e[i].dims[j] = dims[j];
        }
        if (ss_mp_rd(f, &ty, 4) || ss_mp_rd(f, &off, 8)) { free(e); return 1; }
        e[i].nd = nd; e[i].ty = ty; e[i].rel = off; e[i].elems = elems;
    }
    base = (uint64_t)_ftelli64(f);
    base = (base + (uint64_t)align - 1ull) & ~((uint64_t)align - 1ull);
    *out_e = e; *base_out = base;
    return 0;
}
int ss_model_plan_merge_shard(SsModelPlan *plan, const char *path, uint32_t shard_index)
{
    FILE *f; char arch[SS_ARCH_NAME_MAX]; uint32_t align = 32; uint64_t nt, base;
    SsPlanEnt *e = 0; int rc = 1;
    if (!plan || !path) return 1;
    f = fopen(path, "rb"); if (!f) return 1;
    arch[0] = 0;
    if (ss_mp_read_meta(f, plan, arch, &align, &nt, 0)) goto done;
    if (load_ents(f, &e, (uint32_t)nt, align, &base)) goto done;
    if (ss_mp_bind_tensors(plan, e, (uint32_t)nt, base, shard_index, 0)) goto done;
    plan->shardsMerged++;
    rc = 0;
done:
    free(e); fclose(f); return rc;
}
int ss_mp_build_one(SsModelPlan *out, const char *path, uint32_t shard_index, int read_meta)
{
    FILE *f; char arch[SS_ARCH_NAME_MAX]; uint32_t align = 32; uint64_t nt, base;
    SsPlanEnt *e = 0; int rc = 1;
    f = fopen(path, "rb"); if (!f) return 1;
    arch[0] = 0;
    if (ss_mp_read_meta(f, out, arch, &align, &nt, read_meta)) goto done;
    if (read_meta) {
        strncpy(out->architecture, arch, SS_ARCH_NAME_MAX - 1);
        out->metaReal = (out->blockCount && out->embeddingLength && arch[0]) ? 1 : 0;
        if (out->blockCount > SS_MAX_BLOCKS) out->blockCount = SS_MAX_BLOCKS;
    }
    if (load_ents(f, &e, (uint32_t)nt, align, &base)) goto done;
    if (ss_mp_bind_tensors(out, e, (uint32_t)nt, base, shard_index, read_meta)) goto done;
    out->shardsMerged = 1;
    rc = 0;
done:
    free(e); fclose(f); return rc;
}
