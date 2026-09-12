/* ss_vk_descriptor_ring.h — fixed DS ring keyed by slot+generation */
#ifndef SS_VK_DESCRIPTOR_RING_H
#define SS_VK_DESCRIPTOR_RING_H
#include <stdint.h>
#define D2_DR_SLOTS 32
typedef struct {
    uint64_t set_h; uint64_t gen; uint32_t busy;
} D2DrSlot;
typedef struct {
    D2DrSlot s[D2_DR_SLOTS];
    uint32_t n, busy_n, peak_busy;
    uint64_t binds;
    const char *fail;
} D2Dr;
void d2_dr_init(D2Dr *d, uint32_t n);
int d2_dr_bind(D2Dr *d, uint32_t slot, uint64_t gen);
int d2_dr_release(D2Dr *d, uint32_t slot, uint64_t gen);
int d2_dr_constant_after_warmup(const D2Dr *d);
#endif
