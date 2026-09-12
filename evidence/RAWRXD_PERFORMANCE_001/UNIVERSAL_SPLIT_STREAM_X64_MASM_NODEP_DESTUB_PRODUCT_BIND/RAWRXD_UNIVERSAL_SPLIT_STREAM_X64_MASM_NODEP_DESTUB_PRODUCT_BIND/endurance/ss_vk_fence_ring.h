/* ss_vk_fence_ring.h — reusable fence/CB ring; no reuse before signal */
#ifndef SS_VK_FENCE_RING_H
#define SS_VK_FENCE_RING_H
#include <stdint.h>
#define D2_FR_SLOTS 16
enum { D2_FR_FREE=0, D2_FR_RECORDED=1, D2_FR_SUBMITTED=2, D2_FR_SIGNALED=3 };
typedef struct {
    uint64_t fence_h, cb_h; uint32_t state; uint64_t serial;
} D2FrSlot;
typedef struct {
    D2FrSlot s[D2_FR_SLOTS];
    uint32_t n, head, in_flight;
    uint64_t submit_serial, complete_serial;
    const char *fail;
} D2Fr;
void d2_fr_init(D2Fr *r, uint32_t n);
int d2_fr_acquire(D2Fr *r, uint32_t *idx);
int d2_fr_record(D2Fr *r, uint32_t idx);
int d2_fr_submit(D2Fr *r, uint32_t idx);
int d2_fr_signal(D2Fr *r, uint32_t idx);
int d2_fr_release(D2Fr *r, uint32_t idx);
#endif
