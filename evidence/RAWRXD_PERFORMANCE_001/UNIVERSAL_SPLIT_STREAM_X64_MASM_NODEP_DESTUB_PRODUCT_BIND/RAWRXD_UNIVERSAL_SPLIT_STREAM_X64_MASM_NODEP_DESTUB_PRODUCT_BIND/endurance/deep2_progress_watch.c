/* deep2_progress_watch.c */
#include "deep2_progress_watch.h"
void d2_pw_init(D2ProgWatch *w)
{
    w->last_token_serial = w->last_op_serial = w->last_change_tick = 0;
    w->stall_ticks = 0; w->stall_owner = 0;
}
void d2_pw_tick(D2ProgWatch *w, uint64_t now, uint64_t tok, uint64_t op,
                const char *owner)
{
    if (!w) return;
    if (tok != w->last_token_serial || op != w->last_op_serial) {
        w->last_token_serial = tok; w->last_op_serial = op;
        w->last_change_tick = now; w->stall_ticks = 0; w->stall_owner = 0;
        return;
    }
    w->stall_ticks = now - w->last_change_tick;
    if (w->stall_ticks && !w->stall_owner)
        w->stall_owner = owner ? owner : "STALL_OWNER_UNKNOWN";
}
int d2_pw_stalled(const D2ProgWatch *w, uint64_t max_idle)
{
    return w && w->stall_ticks > max_idle;
}
