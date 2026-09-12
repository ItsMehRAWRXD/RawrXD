/* deep2_device_health.c */
#include "deep2_device_health.h"
void d2_dh_init(D2DevHealth *h)
{
    h->last_vr = 0; h->submit_serial = h->complete_serial = 0;
    h->qidle_ok = 1; h->device_lost = 0; h->first_fail_owner = 0;
}
void d2_dh_note_submit(D2DevHealth *h, int32_t vr, const char *owner)
{
    h->last_vr = vr; h->submit_serial++;
    if (vr == -4 /* VK_ERROR_DEVICE_LOST */) {
        h->device_lost = 1;
        if (!h->first_fail_owner) h->first_fail_owner = owner ? owner : "UNKNOWN";
    } else if (vr < 0 && !h->first_fail_owner)
        h->first_fail_owner = owner ? owner : "UNKNOWN";
}
void d2_dh_note_complete(D2DevHealth *h, uint64_t serial)
{
    if (serial > h->complete_serial) h->complete_serial = serial;
}
void d2_dh_note_qidle(D2DevHealth *h, int ok) { h->qidle_ok = ok ? 1u : 0u; }
