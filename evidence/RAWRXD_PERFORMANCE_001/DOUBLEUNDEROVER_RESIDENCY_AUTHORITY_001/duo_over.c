/* duo_over.c — OVER: WARM→HOT auth from layer; cannot mint consumer/decode */
#include "duo_ticket.h"
int duo_authorize_hot(const DuoTicket *t)
{
    uint32_t need = DUO_F_WARM_RES | DUO_F_OP_BOUND | DUO_F_GEN_MATCH;
    if (!t || t->rev_range || t->rev_phys || t->rev_hot) return DUO_E_REVOKED;
    if (duo_authorize_warm(t) != DUO_OK) return DUO_E_ORDER;
    if ((t->facts & need) != need) return DUO_E_ORDER;
    if (!t->generation || !t->owner) return DUO_E_ORDER;
    return DUO_OK;
}
int duo_observe_hot(DuoTicket *t, uint64_t region, uint64_t ticket, uint64_t gen)
{
    if (!t || !gen) return DUO_E_ARG;
    if (duo_authorize_hot(t) != DUO_OK) return DUO_E_ORDER;
    if (t->region_id != region || t->op_ticket != ticket) return DUO_E_STABLE;
    if ((t->facts & DUO_F_HOT_RES) && t->generation != gen) return DUO_E_STABLE;
    if (t->generation != gen) return DUO_E_STABLE;
    t->facts |= DUO_F_HOT_RES;
    return DUO_OK;
}
int duo_observe_parity(DuoTicket *t, uint64_t region, uint64_t gen, int parity_ok)
{
    if (!t || !parity_ok) return DUO_E_ARG;
    if (!(t->facts & DUO_F_HOT_RES) || t->rev_hot) return DUO_E_ORDER;
    if (t->region_id != region || t->generation != gen) return DUO_E_STABLE;
    t->facts |= DUO_F_PARITY;
    return DUO_OK;
}
int duo_authorize_residency(const DuoTicket *t)
{
    if (duo_authorize_hot(t) != DUO_OK) return DUO_E_ORDER;
    return (t && (t->facts & DUO_F_HOT_RES)) ? DUO_OK : DUO_E_ORDER;
}
