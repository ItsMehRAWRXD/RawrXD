/* deep2_residency_backpressure.h */
#ifndef DEEP2_RESIDENCY_BACKPRESSURE_H
#define DEEP2_RESIDENCY_BACKPRESSURE_H
#include <stdint.h>
enum { D2_RES_COLD=0, D2_RES_WARM=1, D2_RES_HOT=2, D2_RES_PIN=3 };
typedef struct {
    uint32_t max_hot, max_warm, hot_n, warm_n, peak_hot, peak_warm;
    const char *fail;
} D2ResBp;
void d2_res_init(D2ResBp *r, uint32_t max_hot, uint32_t max_warm);
int d2_res_admit(D2ResBp *r, uint32_t to_state);
int d2_res_release(D2ResBp *r, uint32_t from_state);
int d2_res_plateau_ok(const D2ResBp *r);
#endif
