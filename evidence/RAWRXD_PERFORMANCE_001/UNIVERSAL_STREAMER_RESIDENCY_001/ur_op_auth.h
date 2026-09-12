/* ur_op_auth.h — CURRENT_OP_IO_AUTHORITY + NO_SPECULATION */
#ifndef UR_OP_AUTH_H
#define UR_OP_AUTH_H
#include "ur_types.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    UrOwner owner;
    UrTicket live;
    UrTicket next;
    uint32_t open;
    uint32_t failed;
} UrOpAuth;

void ur_op_clear(UrOpAuth *a);
int ur_op_begin(UrOpAuth *a, UrOwner owner, UrTicket *out_ticket);
int ur_op_end(UrOpAuth *a, UrOwner owner, UrTicket ticket, int ok);
/* Returns UR_E_SPEC if reason speculative; UR_E_AUTH if ticket stale */
int ur_op_permit(const UrOpAuth *a, UrOwner owner, UrTicket ticket,
                 UrRequestReason reason);

#ifdef __cplusplus
}
#endif
#endif
