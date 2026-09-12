/* duo_ticket.h — DoubleUnderOverLayer 5-gate lattice (facts ≠ authority) */
#ifndef DUO_TICKET_H
#define DUO_TICKET_H
#include <stdint.h>
#define DUO_OK 0
#define DUO_HOLD 1
#define DUO_E_ARG -1
#define DUO_E_ORDER -2
#define DUO_E_STABLE -3
#define DUO_E_REVOKED -4
#define DUO_E_CONTAIN -5
#define DUO_HOLD_INTEROP 100
#define DUO_F_PROVIDER (1u << 0)
#define DUO_F_RANGE (1u << 1)
#define DUO_F_WARM_RES (1u << 3)
#define DUO_F_OP_BOUND (1u << 4)
#define DUO_F_GEN_MATCH (1u << 5)
#define DUO_F_HOT_RES (1u << 7)
#define DUO_F_IMPORTED (1u << 9)
#define DUO_F_PARITY (1u << 10)
#define DUO_F_CONSUMER_RAN (1u << 11)
#define DUO_F_LOGITS (1u << 12)
#define DUO_F_TOKEN (1u << 13)
#define DUO_A_WARM (1u << 2)
#define DUO_A_HOT (1u << 6)
#define DUO_A_CONSUMER (1u << 8)
#define DUO_FACT_RANGE DUO_F_RANGE
#define DUO_FACT_WARM DUO_F_WARM_RES
#define DUO_FACT_HOT DUO_F_HOT_RES
#define DUO_FACT_PARITY DUO_F_PARITY
#define DUO_FACT_INTEROP DUO_F_IMPORTED
#define DUO_FACT_CONSUMER_RAN DUO_F_CONSUMER_RAN
#define DUO_FACT_LOGITS DUO_F_LOGITS
#define DUO_FACT_TOKEN DUO_F_TOKEN
#define DUO_AUTH_NONE 0
#define DUO_AUTH_UU 1
#define DUO_AUTH_UNDER 2
#define DUO_AUTH_LAYER 3
#define DUO_AUTH_OVER 4
#define DUO_AUTH_OO 5
#define DUO_AUTH_RESIDENCY DUO_AUTH_OVER
#define DUO_AUTH_CONSUMER DUO_AUTH_OO
#define DUO_AUTH_EXECUTION 6
#define DUO_AUTH_COMMIT 7
typedef struct {
    uint64_t region_id, op_ticket, generation, owner, offset, length;
    uint64_t req_off, req_len, codec, mg_loads;
    uint32_t facts, rev_range, rev_phys, rev_hot, rev_owner, rev_cons;
} DuoTicket;
void duo_ticket_clear(DuoTicket *t);
uint32_t duo_facts(const DuoTicket *t);
uint32_t duo_granted(const DuoTicket *t);
int duo_observe_range(DuoTicket *t, uint64_t region, uint64_t ticket,
                      uint64_t off, uint64_t len, int identity_ok);
int duo_validate_range(const DuoTicket *t, uint64_t region, uint64_t ticket,
                       uint64_t off, uint64_t len);
int duo_revoke_range(DuoTicket *t);
int duo_authorize_warm(const DuoTicket *t);
int duo_observe_warm(DuoTicket *t, uint64_t region, uint64_t ticket, uint64_t mg);
int duo_layer_bind(DuoTicket *t, uint64_t region, uint64_t ticket, uint64_t gen,
                   uint64_t owner, uint64_t off, uint64_t len, uint64_t codec);
int duo_authorize_hot(const DuoTicket *t);
int duo_observe_hot(DuoTicket *t, uint64_t region, uint64_t ticket, uint64_t gen);
int duo_observe_parity(DuoTicket *t, uint64_t region, uint64_t gen, int parity_ok);
int duo_observe_interop(DuoTicket *t, uint64_t region, uint64_t gen, int established);
int duo_observe_consumer_ran(DuoTicket *t, uint64_t region, uint64_t gen);
int duo_observe_logits(DuoTicket *t, uint64_t region, uint64_t gen);
int duo_observe_token(DuoTicket *t, uint64_t region, uint64_t gen);
int duo_revoke_physical(DuoTicket *t);
int duo_revoke_generation(DuoTicket *t);
int duo_revoke_owner(DuoTicket *t);
int duo_authorize_residency(const DuoTicket *t);
int duo_authorize_consumer(const DuoTicket *t);
int duo_authorize_commit(const DuoTicket *t);
int duo_revoke_downstream(DuoTicket *t);
int duo_auth_level(const DuoTicket *t);
#endif
