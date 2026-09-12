/* duo_uu.c — UNDER-UNDER: immutable provider/range truth only */
#include "duo_ticket.h"
void duo_ticket_clear(DuoTicket *t)
{
    if (!t) return;
    t->region_id = t->op_ticket = t->generation = t->owner = 0;
    t->offset = t->length = t->req_off = t->req_len = t->codec = t->mg_loads = 0;
    t->facts = t->rev_range = t->rev_phys = t->rev_hot = t->rev_owner = t->rev_cons = 0;
}
uint32_t duo_facts(const DuoTicket *t) { return t ? t->facts : 0; }
static int same_rt(const DuoTicket *t, uint64_t region, uint64_t ticket)
{
    return t->region_id == region && t->op_ticket == ticket;
}
int duo_observe_range(DuoTicket *t, uint64_t region, uint64_t ticket,
                      uint64_t off, uint64_t len, int identity_ok)
{
    if (!t || !region || !ticket || !len || !identity_ok) return DUO_E_ARG;
    if (t->rev_range) return DUO_E_REVOKED;
    if (t->facts & DUO_F_RANGE) {
        if (!same_rt(t, region, ticket) || t->offset != off || t->length != len)
            return DUO_E_STABLE;
        return DUO_OK;
    }
    t->region_id = region; t->op_ticket = ticket; t->offset = off; t->length = len;
    t->facts |= DUO_F_PROVIDER | DUO_F_RANGE;
    return DUO_OK;
}
int duo_validate_range(const DuoTicket *t, uint64_t region, uint64_t ticket,
                       uint64_t off, uint64_t len)
{
    if (!t || !(t->facts & DUO_F_RANGE) || t->rev_range) return DUO_E_ARG;
    if (!same_rt(t, region, ticket) || t->offset != off || t->length != len)
        return DUO_E_STABLE;
    return DUO_OK;
}
int duo_revoke_range(DuoTicket *t)
{
    if (!t) return DUO_E_ARG;
    t->rev_range = 1;
    t->rev_phys = 1;
    t->rev_hot = 1;
    t->rev_cons = 1;
    return DUO_OK;
}
