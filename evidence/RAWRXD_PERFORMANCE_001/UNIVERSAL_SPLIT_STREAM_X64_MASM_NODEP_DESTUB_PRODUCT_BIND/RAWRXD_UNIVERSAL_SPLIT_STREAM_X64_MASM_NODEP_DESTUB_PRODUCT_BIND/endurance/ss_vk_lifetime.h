/* ss_vk_lifetime.h — opaque handle lifetime registry (no Vulkan headers) */
#ifndef SS_VK_LIFETIME_H
#define SS_VK_LIFETIME_H
#include <stdint.h>
#define D2_LT_MAX 256
enum { D2_LT_BUF=1, D2_LT_MEM=2, D2_LT_POOL=3, D2_LT_FENCE=4,
       D2_LT_SEM=5, D2_LT_DS=6, D2_LT_VIEW=7, D2_LT_MAP=8 };
typedef struct {
    uint64_t handle; uint32_t kind, alive; uint64_t epoch;
} D2LtEnt;
typedef struct {
    D2LtEnt e[D2_LT_MAX];
    uint32_t n, creates, destroys;
    const char *fail;
} D2Lt;
void d2_lt_init(D2Lt *L);
int d2_lt_create(D2Lt *L, uint64_t h, uint32_t kind, uint64_t epoch);
int d2_lt_destroy(D2Lt *L, uint64_t h, uint32_t kind);
int d2_lt_alive(const D2Lt *L, uint64_t h);
int d2_lt_reconcile(const D2Lt *L); /* creates==destroys && none alive */
#endif
