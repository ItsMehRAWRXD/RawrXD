/* deep2_product_destub.h — audit residual stubs; does not mint PASS */
#ifndef DEEP2_PRODUCT_DESTUB_H
#define DEEP2_PRODUCT_DESTUB_H
#include <stdint.h>
typedef struct {
    uint32_t stub_symbols_known;
    uint32_t stub_symbols_linked; /* set by build audit */
    uint32_t stub_executed;
    const char *owner;
} D2DestubAudit;
void d2_destub_init(D2DestubAudit *a);
int d2_destub_clean(const D2DestubAudit *a);
#endif
