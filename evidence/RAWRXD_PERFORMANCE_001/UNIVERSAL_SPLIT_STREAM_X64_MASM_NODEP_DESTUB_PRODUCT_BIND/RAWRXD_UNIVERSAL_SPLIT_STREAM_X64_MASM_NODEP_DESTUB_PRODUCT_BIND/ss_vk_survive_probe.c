/* ss_vk_survive_probe.c — compose budget+noop(+optional embd) survival snap */
#include "ss_vk_survive.h"
#include "ss_vk_api.h"
#include "ss_vk_block_util.h"
#include <stdio.h>
#include <string.h>
int ss_vk_embd(SsVk *v);
int ss_vk_survive_probe(SsVk *v, const char *when, int try_embd, SsSurviveSnap *s)
{
    int rc;
    if (!v || !s) return 100;
    memset(s, 0, sizeof *s);
    s->when = when; s->device_alive = 1; s->embd_submit_ok = -1;
    ss_vk_survive_budget(v, s);
    rc = ss_vk_survive_noop(v, s);
    if (rc || !s->device_alive) {
        ss_vk_survive_print(s);
        return 100;
    }
    if (try_embd) {
        ss_vk_pool_recreate(v);
        ss_vk_embd_pipe_reset(v);
        rc = ss_vk_embd(v);
        s->embd_submit_ok = (rc == 0) ? 1 : 0;
        if (rc) s->device_alive = 0; /* embd prints EMBD_FAIL; treat as survival fail */
        /* Distinguish DEVICE_LOST messenger: embd may fail without loss — keep alive if noop ok */
        if (rc) {
            /* Re-check with noop; if noop still works, device alive but embd path broken */
            SsSurviveSnap n2;
            memset(&n2, 0, sizeof n2);
            n2.when = "recheck_after_embd_fail";
            n2.device_alive = 1;
            if (ss_vk_survive_noop(v, &n2) == 0 && n2.device_alive) {
                s->device_alive = 1;
                s->last_vr = n2.last_vr;
            } else {
                s->device_alive = 0;
                s->last_vr = n2.last_vr ? n2.last_vr : s->last_vr;
            }
        }
    }
    ss_vk_survive_print(s);
    return (s->device_alive && s->noop_submit_ok &&
            (!try_embd || s->embd_submit_ok == 1)) ? 0 : 100;
}
