/* ss_vk_fence_ring.c — explicit FREE→RECORD→SUBMIT→SIGNAL→FREE */
#include "ss_vk_fence_ring.h"
#include <string.h>
void d2_fr_init(D2Fr *r, uint32_t n)
{
    uint32_t i;
    memset(r, 0, sizeof *r);
    r->n = n && n <= D2_FR_SLOTS ? n : D2_FR_SLOTS;
    for (i = 0; i < r->n; ++i) {
        r->s[i].fence_h = 1000ull + i;
        r->s[i].cb_h = 2000ull + i;
        r->s[i].state = D2_FR_FREE;
    }
}
int d2_fr_acquire(D2Fr *r, uint32_t *idx)
{
    uint32_t i;
    if (!r || !idx) return 0;
    for (i = 0; i < r->n; ++i) {
        uint32_t j = (r->head + i) % r->n;
        if (r->s[j].state == D2_FR_FREE) {
            *idx = j; r->head = (j + 1u) % r->n; return 1;
        }
    }
    r->fail = "FR_NO_FREE_SLOT"; return 0;
}
int d2_fr_record(D2Fr *r, uint32_t idx)
{
    if (!r || idx >= r->n) return 0;
    if (r->s[idx].state != D2_FR_FREE && r->s[idx].state != D2_FR_SIGNALED) {
        r->fail = "FR_RECORD_BAD_STATE"; return 0;
    }
    r->s[idx].state = D2_FR_RECORDED; return 1;
}
int d2_fr_submit(D2Fr *r, uint32_t idx)
{
    if (!r || idx >= r->n) return 0;
    if (r->s[idx].state != D2_FR_RECORDED) { r->fail = "FR_SUBMIT_BAD_STATE"; return 0; }
    r->submit_serial++; r->s[idx].serial = r->submit_serial;
    r->s[idx].state = D2_FR_SUBMITTED; r->in_flight++;
    return 1;
}
int d2_fr_signal(D2Fr *r, uint32_t idx)
{
    if (!r || idx >= r->n) return 0;
    if (r->s[idx].state != D2_FR_SUBMITTED) { r->fail = "FR_SIGNAL_BEFORE_SUBMIT"; return 0; }
    r->s[idx].state = D2_FR_SIGNALED; r->complete_serial = r->s[idx].serial;
    if (r->in_flight) r->in_flight--;
    return 1;
}
int d2_fr_release(D2Fr *r, uint32_t idx)
{
    if (!r || idx >= r->n) return 0;
    if (r->s[idx].state != D2_FR_SIGNALED) { r->fail = "FR_RELEASE_BEFORE_SIGNAL"; return 0; }
    r->s[idx].state = D2_FR_FREE; return 1;
}
