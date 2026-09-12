/* ss_ar_tps.h — dedicated full-model decode timing (authority gate) */
#ifndef SS_AR_TPS_H
#define SS_AR_TPS_H
#include <stdint.h>
#define D2_TPS_MAX 128
typedef struct {
    uint64_t freq, wall0, wall1, t0;
    uint64_t sample[D2_TPS_MAX];
    uint32_t n;
} D2Tps;
void d2_tps_begin(D2Tps *t);
void d2_tps_token_enter(D2Tps *t);
void d2_tps_token_leave(D2Tps *t);
void d2_tps_end(D2Tps *t);
void d2_tps_print(const D2Tps *t, uint64_t gen, int decode_pass,
                  uint32_t sealed, uint32_t device_lost);
#endif
