/* duo_oo.c — OVER-OVER: consumer import facts; cannot mint logits/token */
#include "duo_ticket.h"
int duo_observe_interop(DuoTicket *t, uint64_t region, uint64_t gen, int established)
{
    if (!t || !established) return DUO_E_ARG;
    if (duo_authorize_residency(t) != DUO_OK) return DUO_E_ORDER;
    if (t->region_id != region || t->generation != gen) return DUO_E_STABLE;
    if (t->rev_cons || t->rev_owner) return DUO_E_REVOKED;
    t->facts |= DUO_F_IMPORTED;
    return DUO_OK;
}
int duo_observe_consumer_ran(DuoTicket *t, uint64_t region, uint64_t gen)
{
    if (!t) return DUO_E_ARG;
    if (duo_authorize_consumer(t) != DUO_OK) return DUO_E_ORDER;
    if (t->region_id != region || t->generation != gen) return DUO_E_STABLE;
    t->facts |= DUO_F_CONSUMER_RAN;
    return DUO_OK;
}
int duo_observe_logits(DuoTicket *t, uint64_t region, uint64_t gen)
{
    if (!t) return DUO_E_ARG;
    if (!(t->facts & DUO_F_CONSUMER_RAN)) return DUO_E_ORDER;
    if (t->region_id != region || t->generation != gen) return DUO_E_STABLE;
    t->facts |= DUO_F_LOGITS;
    return DUO_OK;
}
int duo_observe_token(DuoTicket *t, uint64_t region, uint64_t gen)
{
    if (!t) return DUO_E_ARG;
    if (!(t->facts & DUO_F_LOGITS)) return DUO_E_ORDER;
    if (t->region_id != region || t->generation != gen) return DUO_E_STABLE;
    t->facts |= DUO_F_TOKEN;
    return DUO_OK;
}
int duo_authorize_consumer(const DuoTicket *t)
{
    if (duo_authorize_residency(t) != DUO_OK) return DUO_E_ORDER;
    if (!t || t->rev_cons || t->rev_owner) return DUO_E_REVOKED;
    if (!(t->facts & DUO_F_IMPORTED)) return DUO_HOLD_INTEROP;
    return DUO_OK;
}
int duo_authorize_commit(const DuoTicket *t)
{
    uint32_t need = DUO_F_IMPORTED | DUO_F_CONSUMER_RAN | DUO_F_LOGITS | DUO_F_TOKEN;
    if (duo_authorize_consumer(t) != DUO_OK) return DUO_E_ORDER;
    if ((t->facts & need) != need) return DUO_HOLD;
    return DUO_OK;
}
