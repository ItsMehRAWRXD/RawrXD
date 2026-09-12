/* ss_ar_endurance.c — invariant / health / journal on product AR path */
#include "ss_ar_endurance.h"
#include "ss_vk_survive.h"
#include <stdio.h>
void ar_endurance_begin(ArUser *u)
{
    if (!u) return;
    d2_inv_init(&u->inv, 1, 1);
    d2_dh_init(&u->dh);
    d2_rj_init(&u->journal);
    printf("ENDURANCE_PRODUCT_MERGED=1\n");
    printf("PRODUCT_LINKED_INTO_CERT=1\n");
    fflush(stdout);
}
int ar_endurance_end_fwd(ArUser *u, uint64_t pos)
{
    SsSurviveSnap s; char when[40];
    if (!u) return 0;
    if (!d2_inv_end_fwd(&u->inv, 1)) {
        u->stop = u->inv.fail ? u->inv.fail : "INVARIANT_END_FAIL";
        printf("AUTHORIZATION_STOP_REASON=%s\n", u->stop);
        return 0;
    }
    sprintf(when, "POST_TOKEN%llu_FORWARD", (unsigned long long)pos);
    ss_vk_survive_probe(u->v, when, 0, &s);
    if (!s.device_alive || !s.noop_submit_ok) {
        u->device_lost = 1; u->post_last_alive = 0;
        if (pos == 1) u->post_tok1_alive = 0;
        d2_dh_note_submit(&u->dh, -4, "AR_FORWARD");
        sprintf(u->stop_buf, "TOKEN%llu_DEVICE_LOST", (unsigned long long)pos);
        u->stop = u->stop_buf;
        printf("AUTHORIZATION_STOP_REASON=%s\n", u->stop);
        return 0;
    }
    d2_dh_note_submit(&u->dh, 0, "AR_FORWARD");
    d2_rj_append(&u->journal, pos, pos, u->inv.fwd, u->inv.commit, u->inv.adv, 0);
    u->post_last_alive = 1;
    if (pos == 1) u->post_tok1_alive = 1;
    return 1;
}
int ar_endurance_finish(ArUser *u, uint64_t target)
{
    if (!u) return 0;
    if (u->device_lost || u->dh.device_lost) return 0;
    return d2_inv_reconcile(&u->inv, target);
}
void ar_endurance_print(const ArUser *u, uint64_t target)
{
    int ok;
    if (!u) return;
    ok = d2_inv_reconcile(&u->inv, target) && !u->device_lost && !u->dh.device_lost;
    printf("ENDURANCE_INVARIANT=%s\n", ok ? "PASS" : "FAIL");
    printf("ENDURANCE_FWD=%llu FULL_BLOCK=%llu COMMIT=%llu ADV=%llu GEN=%llu\n",
           (unsigned long long)u->inv.fwd, (unsigned long long)u->inv.full_block,
           (unsigned long long)u->inv.commit, (unsigned long long)u->inv.adv,
           (unsigned long long)u->inv.gen);
    printf("ENDURANCE_SEALED_REUSE=%llu DEVICE_LOST=%u JOURNAL_N=%u\n",
           (unsigned long long)u->inv.sealed_reuse, u->device_lost, u->journal.n);
    if (u->inv.fail) printf("ENDURANCE_FAIL=%s\n", u->inv.fail);
    fflush(stdout);
}
