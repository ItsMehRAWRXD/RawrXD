/* duo_revoke.c — authority descends on revoke; facts are not erased */
#include "duo_ticket.h"
int duo_revoke_generation(DuoTicket *t)
{
    if (!t) return DUO_E_ARG;
    t->rev_hot = 1;
    t->rev_cons = 1;
    return DUO_OK;
}
int duo_revoke_owner(DuoTicket *t)
{
    if (!t) return DUO_E_ARG;
    t->rev_owner = 1;
    t->rev_cons = 1;
    return DUO_OK;
}
int duo_revoke_downstream(DuoTicket *t)
{
    if (!t) return DUO_E_ARG;
    t->rev_cons = 1;
    return DUO_OK;
}
uint32_t duo_granted(const DuoTicket *t)
{
    uint32_t g;
    if (!t) return 0;
    g = t->facts & (DUO_F_PROVIDER | DUO_F_RANGE | DUO_F_WARM_RES | DUO_F_OP_BOUND |
                    DUO_F_GEN_MATCH | DUO_F_HOT_RES | DUO_F_IMPORTED);
    if (duo_authorize_warm(t) == DUO_OK) g |= DUO_A_WARM;
    if (duo_authorize_hot(t) == DUO_OK && (t->facts & DUO_F_HOT_RES)) g |= DUO_A_HOT;
    if (duo_authorize_consumer(t) == DUO_OK) g |= DUO_A_CONSUMER;
    return g;
}
int duo_auth_level(const DuoTicket *t)
{
    if (!t) return DUO_AUTH_NONE;
    if (duo_authorize_commit(t) == DUO_OK) return DUO_AUTH_COMMIT;
    if ((t->facts & DUO_F_CONSUMER_RAN) && duo_authorize_consumer(t) == DUO_OK)
        return DUO_AUTH_EXECUTION;
    if (duo_authorize_consumer(t) == DUO_OK) return DUO_AUTH_OO;
    if (duo_authorize_residency(t) == DUO_OK) return DUO_AUTH_OVER;
    if ((t->facts & (DUO_F_OP_BOUND | DUO_F_GEN_MATCH)) == (DUO_F_OP_BOUND | DUO_F_GEN_MATCH)
        && duo_authorize_warm(t) == DUO_OK)
        return DUO_AUTH_LAYER;
    if ((t->facts & DUO_F_WARM_RES) && duo_authorize_warm(t) == DUO_OK)
        return DUO_AUTH_UNDER;
    if ((t->facts & DUO_F_RANGE) && !t->rev_range) return DUO_AUTH_UU;
    return DUO_AUTH_NONE;
}
