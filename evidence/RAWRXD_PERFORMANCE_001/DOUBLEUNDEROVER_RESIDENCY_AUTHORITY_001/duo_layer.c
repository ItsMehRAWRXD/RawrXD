/* duo_layer.c — LAYER firewall: current-op owns resident range (no HOT mint) */
#include "duo_ticket.h"
int duo_layer_bind(DuoTicket *t, uint64_t region, uint64_t ticket, uint64_t gen,
                   uint64_t owner, uint64_t off, uint64_t len, uint64_t codec)
{
    uint64_t end, rend;
    if (!t || !region || !ticket || !gen || !owner || !len) return DUO_E_ARG;
    if (duo_authorize_warm(t) != DUO_OK) return DUO_E_ORDER;
    if (!(t->facts & DUO_F_WARM_RES) || t->rev_phys) return DUO_E_ORDER;
    if (t->region_id != region || t->op_ticket != ticket) return DUO_E_STABLE;
    end = off + len; rend = t->offset + t->length;
    if (off < t->offset || end < off || end > rend) return DUO_E_CONTAIN;
    t->generation = gen;
    t->owner = owner;
    t->req_off = off;
    t->req_len = len;
    t->codec = codec;
    t->facts |= DUO_F_OP_BOUND | DUO_F_GEN_MATCH;
    return DUO_OK;
}
