/* deep2_product_destub.c */
#include "deep2_product_destub.h"
void d2_destub_init(D2DestubAudit *a)
{
    a->stub_symbols_known = 0;
    a->stub_symbols_linked = 0; /* OPEN until product link audit */
    a->stub_executed = 0;
    a->owner = "PRODUCT_DESTUB_AUDIT";
}
int d2_destub_clean(const D2DestubAudit *a)
{
    return a && a->stub_symbols_linked == 0 && a->stub_executed == 0;
}
