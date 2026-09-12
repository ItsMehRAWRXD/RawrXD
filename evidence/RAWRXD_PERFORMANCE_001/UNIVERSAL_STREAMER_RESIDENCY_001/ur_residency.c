/* ur_residency.c — require: auth, alias, join-wait, atomic MG claim */
#include "ur_internal.h"
#include <stdlib.h>

static void fill_out(UrCacheSlot *s, uint64_t off, uint64_t n,
                     const uint8_t **p, uint64_t *len, UrGeneration *g)
{
    *p = s->bytes + off; *len = n;
    if (g) *g = s->generation;
}

int ur_require_region(UrRuntime *r, UrTicket ticket, UrRegionId id,
                      UrRequestReason reason, const uint8_t **ptr_out,
                      uint64_t *len_out, UrGeneration *gen_out)
{
    UrRegionDesc d; UrCacheSlot *slot, *alias; uint8_t *buf; uint64_t got = 0, aoff = 0; int rc;
    if (!r || !ptr_out || !len_out || !id) return UR_E_ARG;
    if (reason != UR_REASON_CURRENT_OP && reason != UR_REASON_SPECULATIVE) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    rc = ur_op_permit(&r->auth, r->owner, ticket, reason);
    if (rc == UR_E_SPEC) { r->tel.reject_spec++; ur_sync_unlock(&r->sync); return rc; }
    if (rc == UR_E_AUTH) { r->tel.reject_auth++; r->tel.reject_stale++; ur_sync_unlock(&r->sync); return rc; }
    if (rc || (rc = ur_index_get(&r->index, id, &d))) { ur_sync_unlock(&r->sync); return rc; }
    for (;;) {
        slot = ur_cache_find(r, id);
        if (slot && (slot->state == UR_WARM || slot->state == UR_HOT) && slot->bytes) {
            if (slot->state == UR_HOT) r->tel.hot_hits++; else r->tel.warm_hits++;
            slot->pin_count++; fill_out(slot, 0, slot->length, ptr_out, len_out, gen_out);
            ur_sync_unlock(&r->sync); return UR_OK;
        }
        if (ur_alias_lookup(r, &d, &alias, &aoff)) {
            r->tel.alias_hits++; alias->pin_count++;
            if (ur_lease_add(r, id, alias->id)) { alias->pin_count--; ur_sync_unlock(&r->sync); return UR_E_OOM; }
            fill_out(alias, aoff, d.length, ptr_out, len_out, gen_out);
            ur_sync_unlock(&r->sync); return UR_OK;
        }
        if (slot && slot->state == UR_MG_IN_PROGRESS) {
            r->tel.join_waits++;
            ur_sync_wait(&r->sync);
            slot = ur_cache_find(r, id);
            if (slot && (slot->state == UR_WARM || slot->state == UR_HOT) && slot->bytes) {
                r->tel.join_commits++;
                if (slot->state == UR_HOT) r->tel.hot_hits++; else r->tel.warm_hits++;
                slot->pin_count++; fill_out(slot, 0, slot->length, ptr_out, len_out, gen_out);
                ur_sync_unlock(&r->sync); return UR_OK;
            }
            continue; /* failed claim or still racing — retry under lock */
        }
        break;
    }
    if (!slot) { slot = ur_cache_alloc(r, id); if (!slot) { ur_sync_unlock(&r->sync); return UR_E_OOM; } }
    if (r->host_budget && ur_cache_resident_bytes(r) + d.length > r->host_budget) {
        r->tel.reject_budget++; ur_sync_unlock(&r->sync); return UR_E_BUDGET;
    }
    if (slot->state == UR_FAILED) slot->state = UR_COLD;
    if (slot->mg_claimed) { r->tel.duplicate_first_touch++; ur_sync_unlock(&r->sync); return UR_E_STATE; }
    slot->desc = d; slot->mg_claimed = 1; slot->state = UR_MG_IN_PROGRESS;
    r->tel.mg_claim_winners++;
    ur_sync_unlock(&r->sync);
    if (!r->provider.read_range) {
        ur_sync_lock(&r->sync);
        slot->state = UR_FAILED; slot->mg_claimed = 0; r->tel.mg_fail++;
        ur_sync_wake(&r->sync); ur_sync_unlock(&r->sync); return UR_E_STATE;
    }
    buf = (uint8_t *)malloc((size_t)d.length);
    if (!buf || (rc = r->provider.read_range(r->provider.ctx, d.offset, d.length, buf, &got)) || got != d.length) {
        if (buf) free(buf);
        ur_sync_lock(&r->sync);
        slot->bytes = 0; slot->length = 0; slot->state = UR_COLD; slot->mg_claimed = 0;
        r->tel.mg_fail++; ur_sync_wake(&r->sync); ur_sync_unlock(&r->sync);
        return buf ? (rc ? rc : UR_E_SHORT) : UR_E_OOM;
    }
    ur_sync_lock(&r->sync);
    r->tel.disk_reads++; r->tel.disk_bytes += got; r->tel.mg_loads++; r->tel.mg_bytes += got;
    slot->bytes = buf; slot->length = got; slot->generation++;
    slot->state = UR_WARM; slot->mg_claimed = 0; slot->pin_count = 1;
    fill_out(slot, 0, slot->length, ptr_out, len_out, gen_out);
    ur_sync_wake(&r->sync); ur_sync_unlock(&r->sync);
    return UR_OK;
}

int usr_resolve(UrRuntime *r, UrRegionId region, UrRegionDesc *out)
{ return ur_index_get(&r->index, region, out); }
int usr_require(UrRuntime *r, UrRegionId region, UrTicket ticket,
                const uint8_t **out_ptr, uint64_t *out_len)
{ return ur_require_region(r, ticket, region, UR_REASON_CURRENT_OP, out_ptr, out_len, 0); }
int usr_mark_hot(UrRuntime *r, UrRegionId region)
{ return ur_promote_hot(r, region); }
