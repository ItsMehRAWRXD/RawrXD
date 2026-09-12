/* d2_cancel.h — cooperative cancel at token boundaries */
#ifndef D2_CANCEL_H
#define D2_CANCEL_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct D2Cancel {
    volatile uint32_t requested;
} D2Cancel;
static inline void d2_cancel_clear(D2Cancel *c)
{
    if (c) c->requested = 0u;
}
static inline void d2_cancel_request(D2Cancel *c)
{
    if (c) c->requested = 1u;
}
static inline int d2_cancel_requested(const D2Cancel *c)
{
    return c && c->requested ? 1 : 0;
}
#ifdef __cplusplus
}
#endif
#endif
