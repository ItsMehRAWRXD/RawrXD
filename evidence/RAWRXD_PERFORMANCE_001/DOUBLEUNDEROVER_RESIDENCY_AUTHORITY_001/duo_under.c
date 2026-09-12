/* duo_under.c — UNDER: authorize/observe COLD→MG→WARM; MG does not mint HOT */
#include "duo_ticket.h"
int duo_authorize_warm(const DuoTicket *t)
{
    uint32_t need = DUO_F_PROVIDER | DUO_F_RANGE;
    if (!t || t->rev_range) return DUO_E_REVOKED;
    if ((t->facts & need) != need || !t->length || !t->op_ticket) return DUO_E_ORDER;
    return DUO_OK;
}
int duo_observe_warm(DuoTicket *t, uint64_t region, uint64_t ticket, uint64_t mg)
{
    if (!t) return DUO_E_ARG;
    if (duo_authorize_warm(t) != DUO_OK) return DUO_E_ORDER;
    if (t->region_id != region || t->op_ticket != ticket) return DUO_E_STABLE;
    if (t->rev_phys) return DUO_E_REVOKED;
    t->mg_loads = mg;
    t->facts |= DUO_F_WARM_RES;
    return DUO_OK;
}
int duo_revoke_physical(DuoTicket *t)
{
    if (!t) return DUO_E_ARG;
    t->rev_phys = 1;
    t->rev_hot = 1;
    t->rev_cons = 1;
    return DUO_OK;
}
