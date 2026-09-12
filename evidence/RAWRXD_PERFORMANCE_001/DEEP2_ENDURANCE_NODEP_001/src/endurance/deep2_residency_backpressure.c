/* deep2_residency_backpressure.c */
#include "deep2_residency_backpressure.h"
void d2_res_init(D2ResBp *r, uint32_t max_hot, uint32_t max_warm)
{
    r->max_hot = max_hot; r->max_warm = max_warm;
    r->hot_n = r->warm_n = r->peak_hot = r->peak_warm = 0; r->fail = 0;
}
int d2_res_admit(D2ResBp *r, uint32_t to_state)
{
    if (!r) return 0;
    if (to_state == D2_RES_HOT) {
        if (r->hot_n >= r->max_hot) { r->fail = "HOT_BACKPRESSURE"; return 0; }
        r->hot_n++; if (r->hot_n > r->peak_hot) r->peak_hot = r->hot_n;
    } else if (to_state == D2_RES_WARM) {
        if (r->warm_n >= r->max_warm) { r->fail = "WARM_BACKPRESSURE"; return 0; }
        r->warm_n++; if (r->warm_n > r->peak_warm) r->peak_warm = r->warm_n;
    }
    return 1;
}
int d2_res_release(D2ResBp *r, uint32_t from_state)
{
    if (!r) return 0;
    if (from_state == D2_RES_HOT && r->hot_n) r->hot_n--;
    else if (from_state == D2_RES_WARM && r->warm_n) r->warm_n--;
    return 1;
}
int d2_res_plateau_ok(const D2ResBp *r)
{
    return r && r->peak_hot <= r->max_hot && r->peak_warm <= r->max_warm;
}
