#include "deep2_residency_solver.h"
#include "deep2_e2e_types.h"

static int d2_place_one(
    const D2ResidencyNode* n,
    const D2ResidencyCapacity* cap,
    D2ResidencyPlacement* p,
    D2ResidencyResult* r,
    uint32_t forced_tier)
{
    uint32_t tier = forced_tier;
    if (!n || !p || !r || !cap || !n->bytes) return D2_EINVAL;

    if (tier == D2_TIER_NONE) {
        /* Prefer the requested GPU, then the other GPU, then RAM, then mmap. */
        if (n->preferred_gpu == 0 &&
            (n->flags & D2_RES_ALLOW_GPU0) &&
            r->gpu0_used + n->bytes <= cap->gpu0_bytes)
            tier = D2_TIER_GPU0;
        else if (n->preferred_gpu == 1 &&
            (n->flags & D2_RES_ALLOW_GPU1) &&
            r->gpu1_used + n->bytes <= cap->gpu1_bytes)
            tier = D2_TIER_GPU1;
        else if ((n->flags & D2_RES_ALLOW_GPU0) &&
            r->gpu0_used + n->bytes <= cap->gpu0_bytes)
            tier = D2_TIER_GPU0;
        else if ((n->flags & D2_RES_ALLOW_GPU1) &&
            r->gpu1_used + n->bytes <= cap->gpu1_bytes)
            tier = D2_TIER_GPU1;
        else if ((n->flags & D2_RES_ALLOW_RAM) &&
            r->ram_used + n->bytes <= cap->ram_bytes)
            tier = D2_TIER_RAM;
        else if (n->flags & D2_RES_ALLOW_MMAP)
            tier = D2_TIER_MMAP;
        else
            return D2_ENOSPACE;
    }

    if (tier == D2_TIER_GPU0) {
        if (!(n->flags & D2_RES_ALLOW_GPU0) ||
            r->gpu0_used + n->bytes > cap->gpu0_bytes) return D2_ENOSPACE;
        r->gpu0_used += n->bytes;
        if (n->flags & D2_RES_HOT_EXEC) r->hot_gpu_bytes += n->bytes;
    } else if (tier == D2_TIER_GPU1) {
        if (!(n->flags & D2_RES_ALLOW_GPU1) ||
            r->gpu1_used + n->bytes > cap->gpu1_bytes) return D2_ENOSPACE;
        r->gpu1_used += n->bytes;
        if (n->flags & D2_RES_HOT_EXEC) r->hot_gpu_bytes += n->bytes;
    } else if (tier == D2_TIER_RAM) {
        if (!(n->flags & D2_RES_ALLOW_RAM) ||
            r->ram_used + n->bytes > cap->ram_bytes) return D2_ENOSPACE;
        r->ram_used += n->bytes;
        if (n->flags & D2_RES_HOT_EXEC)
            r->critical_path_mmap_required = 1; /* hot exec not GPU resident */
    } else if (tier == D2_TIER_MMAP) {
        if (!(n->flags & D2_RES_ALLOW_MMAP)) return D2_ENOSPACE;
        r->mmap_backed += n->bytes;
        r->cold_bytes += n->bytes;
        if ((n->flags & D2_RES_HOT_EXEC) && !(n->flags & D2_RES_COLD_OK))
            r->critical_path_mmap_required = 1;
    } else {
        return D2_EINVAL;
    }

    p->id = n->id;
    p->bytes = n->bytes;
    p->tier = tier;
    p->exact_range_only = 1;
    return D2_OK;
}

static uint64_t d2_score(const D2ResidencyNode* n) {
    uint64_t mib = (n->bytes + ((1u << 20) - 1)) >> 20;
    if (!mib) mib = 1;
    return (n->hotness + 1) / mib;
}

int d2_residency_plan(
    const D2ResidencyNode* nodes,
    size_t count,
    const D2ResidencyCapacity* cap,
    D2ResidencyPlacement* out,
    D2ResidencyResult* result)
{
    size_t i, placed = 0;
    uint8_t selected[512] = {0};
    int rc;

    if (!nodes || !cap || !out || !result || !count || count > 512)
        return D2_EINVAL;

    *result = (D2ResidencyResult){0};

    /* Pass 1: hard pins and fixed KV/scratch preferences. */
    for (i = 0; i < count; ++i) {
        uint32_t forced = D2_TIER_NONE;
        if ((nodes[i].flags & D2_RES_PIN_GPU0) &&
            (nodes[i].flags & D2_RES_PIN_GPU1))
            return D2_EINVAL;
        if (nodes[i].flags & D2_RES_PIN_GPU0) forced = D2_TIER_GPU0;
        if (nodes[i].flags & D2_RES_PIN_GPU1) forced = D2_TIER_GPU1;
        if (forced != D2_TIER_NONE) {
            rc = d2_place_one(&nodes[i], cap, &out[i], result, forced);
            if (rc) return rc;
            selected[i] = 1;
            placed++;
        }
    }

    /* Pass 2: hotness/byte greedy, deterministic and allocation-free. */
    while (placed < count) {
        size_t best = count;
        uint64_t best_score = 0;
        for (i = 0; i < count; ++i) {
            uint64_t s;
            if (selected[i]) continue;
            s = d2_score(&nodes[i]);
            if (best == count || s > best_score ||
                (s == best_score && nodes[i].id < nodes[best].id))
            {
                best = i;
                best_score = s;
            }
        }
        if (best == count) break;

        rc = d2_place_one(&nodes[best], cap, &out[best], result, D2_TIER_NONE);
        if (rc) return rc;
        selected[best] = 1;
        placed++;
    }

    result->full_materialization_required = 0;
    result->fit =
        placed == count &&
        result->critical_path_mmap_required == 0 &&
        result->full_materialization_required == 0;

    return result->fit ? D2_OK : D2_EAUTH;
}
