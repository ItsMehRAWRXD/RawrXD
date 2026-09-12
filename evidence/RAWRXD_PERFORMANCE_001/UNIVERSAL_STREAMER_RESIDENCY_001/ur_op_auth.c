/* ur_op_auth.c */
#include "ur_op_auth.h"
#include <string.h>

void ur_op_clear(UrOpAuth *a)
{
    if (!a) return;
    memset(a, 0, sizeof *a);
}

int ur_op_begin(UrOpAuth *a, UrOwner owner, UrTicket *out_ticket)
{
    if (!a || !out_ticket || !owner) return UR_E_ARG;
    if (a->open || a->failed) return UR_E_STATE;
    a->owner = owner;
    a->live = ++a->next;
    a->open = 1;
    *out_ticket = a->live;
    return UR_OK;
}

int ur_op_end(UrOpAuth *a, UrOwner owner, UrTicket ticket, int ok)
{
    if (!a) return UR_E_ARG;
    if (!a->open || a->owner != owner || a->live != ticket) return UR_E_AUTH;
    a->open = 0;
    if (!ok) a->failed = 1;
    a->live = 0;
    return UR_OK;
}

int ur_op_permit(const UrOpAuth *a, UrOwner owner, UrTicket ticket,
                 UrRequestReason reason)
{
    if (!a) return UR_E_ARG;
    if (reason != UR_REASON_CURRENT_OP) return UR_E_SPEC;
    if (a->failed || !a->open) return UR_E_AUTH;
    if (a->owner != owner || a->live != ticket) return UR_E_AUTH;
    return UR_OK;
}
