/* deep2_receipt_journal.h — append-only observed events; no PASS mint */
#ifndef DEEP2_RECEIPT_JOURNAL_H
#define DEEP2_RECEIPT_JOURNAL_H
#include <stdint.h>
#define D2_RJ_MAX 128
typedef struct {
    uint64_t tick, pos, fwd, commit, adv;
    int32_t vr; uint32_t flags;
} D2RjEnt;
typedef struct {
    D2RjEnt e[D2_RJ_MAX];
    uint32_t n, truncated;
} D2Rj;
void d2_rj_init(D2Rj *j);
int d2_rj_append(D2Rj *j, uint64_t tick, uint64_t pos, uint64_t fwd,
                 uint64_t commit, uint64_t adv, int32_t vr);
/* minting PASS from journal alone is forbidden — caller must reconcile */
#endif
