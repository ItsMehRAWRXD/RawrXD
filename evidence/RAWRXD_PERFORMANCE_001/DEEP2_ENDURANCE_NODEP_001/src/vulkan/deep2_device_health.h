/* deep2_device_health.h */
#ifndef DEEP2_DEVICE_HEALTH_H
#define DEEP2_DEVICE_HEALTH_H
#include <stdint.h>
typedef struct {
    int32_t last_vr;
    uint64_t submit_serial, complete_serial;
    uint32_t qidle_ok, device_lost;
    const char *first_fail_owner;
} D2DevHealth;
void d2_dh_init(D2DevHealth *h);
void d2_dh_note_submit(D2DevHealth *h, int32_t vr, const char *owner);
void d2_dh_note_complete(D2DevHealth *h, uint64_t serial);
void d2_dh_note_qidle(D2DevHealth *h, int ok);
#endif
