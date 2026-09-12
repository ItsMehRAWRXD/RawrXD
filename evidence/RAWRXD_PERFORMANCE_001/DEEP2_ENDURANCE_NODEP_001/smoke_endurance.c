/* smoke_endurance.c — separate from deep2_benchmark; CERT_BINARY_TOUCHED=0 */
#include "deep2_decode_invariant.h"
#include "deep2_kv_guard.h"
#include "deep2_arena_guard.h"
#include "ss_vk_lifetime.h"
#include "ss_vk_fence_ring.h"
#include "ss_vk_descriptor_ring.h"
#include "deep2_tensor_range_guard.h"
#include "deep2_residency_backpressure.h"
#include "deep2_generation_epoch.h"
#include "deep2_device_health.h"
#include "deep2_progress_watch.h"
#include "deep2_state_digest.h"
#include "deep2_longrun_stats.h"
#include "deep2_receipt_journal.h"
#include "deep2_product_destub.h"
#include <stdio.h>
static int fail(const char *s) { printf("SMOKE_FAIL=%s\n", s); return 1; }
int main(void)
{
    D2Inv inv; D2KvGuard kv; D2ArenaGuard ar; D2Lt lt; D2Fr fr; D2Dr dr;
    D2RangeGuard rg; D2ResBp res; D2Epoch ep; D2DevHealth dh; D2ProgWatch pw;
    D2Stat st; D2Rj rj; D2DestubAudit ds; D2Range auth;
    uint32_t i, idx; uint64_t dig = 0;
    printf("DEEP2_ENDURANCE_SMOKE CERT_BINARY_TOUCHED=0\n");
    d2_inv_init(&inv, 1, 1);
    for (i = 0; i < 4; ++i) {
        if (!d2_inv_begin_fwd(&inv, i, 0)) return fail(inv.fail ? inv.fail : "inv");
        if (!d2_inv_end_fwd(&inv, 1)) return fail("inv_end");
        if (!d2_inv_commit(&inv, i)) return fail(inv.fail);
        if (!d2_inv_advance(&inv, i + 1ull)) return fail(inv.fail);
    }
    if (!d2_inv_reconcile(&inv, 4)) return fail("inv_reconcile");
    d2_kv_init(&kv, 1, 8, 1024);
    for (i = 0; i < 8; ++i) {
        if (!d2_kv_append(&kv, i % 8, i, 1)) return fail(kv.fail);
        if (!d2_kv_read(&kv, i % 8, i, 1)) return fail(kv.fail);
        d2_kv_advance(&kv, i + 1u);
    }
    d2_arena_init(&ar);
    if (!d2_arena_add(&ar, 0x1000, 0x10000, 1)) return fail("arena_add");
    if (!d2_arena_claim(&ar, 0, 0, 64)) return fail("arena_claim");
    d2_arena_freeze(&ar);
    if (d2_arena_note_alloc(&ar)) return fail("alloc_should_fail");
    if (!d2_arena_check_canaries(&ar)) return fail("canary");
    d2_lt_init(&lt);
    if (!d2_lt_create(&lt, 42, D2_LT_BUF, 1)) return fail("lt_c");
    if (!d2_lt_destroy(&lt, 42, D2_LT_BUF)) return fail("lt_d");
    if (!d2_lt_reconcile(&lt)) return fail("lt_rec");
    d2_fr_init(&fr, 4);
    if (!d2_fr_acquire(&fr, &idx)) return fail("fr_acq");
    if (!d2_fr_record(&fr, idx) || !d2_fr_submit(&fr, idx)) return fail("fr_sub");
    if (!d2_fr_signal(&fr, idx) || !d2_fr_release(&fr, idx)) return fail("fr_sig");
    d2_dr_init(&dr, 8);
    if (!d2_dr_bind(&dr, 0, 1) || !d2_dr_release(&dr, 0, 1)) return fail("dr");
    d2_rg_init(&rg); auth.shard = 0; auth.off = 100; auth.bytes = 50; auth.codec = 14;
    if (!d2_rg_check(&rg, &auth, 100, 40)) return fail("rg");
    d2_res_init(&res, 4, 8);
    if (!d2_res_admit(&res, D2_RES_HOT) || !d2_res_release(&res, D2_RES_HOT))
        return fail("res");
    d2_ep_init(&ep, 1);
    if (!d2_ep_accept(&ep, 1)) return fail("ep");
    d2_dh_init(&dh); d2_dh_note_submit(&dh, 0, "smoke");
    d2_pw_init(&pw); d2_pw_tick(&pw, 1, 1, 1, "smoke");
    dig = d2_digest_u64(0, 0xABC); d2_st_init(&st); d2_st_add(&st, 10);
    d2_rj_init(&rj); d2_rj_append(&rj, 1, 0, 1, 1, 1, 0);
    d2_destub_init(&ds);
    printf("TOP5_SMOKE=PASS MODULES=15 DIGEST=0x%llX\n", (unsigned long long)dig);
    printf("PRODUCT_LINKED_INTO_CERT=0 MERGE_AFTER_TARGET64=1\n");
    printf("SMOKE_RC=0 PROMOTE=0\n");
    return 0;
}
