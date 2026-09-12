/* smoke_duo.c — 5-layer lattice; no HOT without LAYER; HOT survives consumer revoke */
#include "duo_ticket.h"
#include <stdio.h>
static int fail(const char *s) { printf("FAIL=%s\n", s); return 1; }
int main(void)
{
    DuoTicket t; int rc; const uint64_t R = 0x2D9A0160ull, L = 521256960ull;
    duo_ticket_clear(&t);
    if (duo_observe_hot(&t, 1, 1, 1) != DUO_E_ORDER) return fail("HOT_WITHOUT_RANGE");
    if (t.facts & DUO_F_HOT_RES) return fail("HOT_MINTED");
    if (duo_observe_range(&t, R, 1, R, L, 1)) return fail("RANGE");
    if (duo_observe_warm(&t, R, 1, 1)) return fail("WARM");
    if (duo_observe_hot(&t, R, 1, 1) != DUO_E_ORDER) return fail("HOT_WITHOUT_LAYER");
    if (duo_layer_bind(&t, R, 1, 1, 1, R, L, 12)) return fail("LAYER");
    if (duo_observe_hot(&t, R, 1, 1)) return fail("HOT");
    if (duo_observe_parity(&t, R, 1, 1)) return fail("PARITY");
    if (duo_authorize_residency(&t) != DUO_OK) return fail("RES_AUTH");
    rc = duo_authorize_consumer(&t);
    if (rc != DUO_HOLD_INTEROP) return fail("CONSUMER_MUST_HOLD");
    if (duo_authorize_commit(&t) == DUO_OK) return fail("COMMIT_EARLY");
    if (duo_auth_level(&t) != DUO_AUTH_OVER) return fail("LEVEL");
    if (duo_observe_token(&t, R, 1) != DUO_E_ORDER) return fail("TOKEN_MINT");
    if (duo_revoke_downstream(&t)) return fail("REVOKE");
    if (!(t.facts & DUO_F_HOT_RES)) return fail("HOT_ERASED");
    if (duo_authorize_residency(&t) != DUO_OK) return fail("RES_AFTER_REVOKE");
    if (duo_authorize_consumer(&t) != DUO_E_REVOKED) return fail("BIND_AFTER_REVOKE");
    if (duo_observe_interop(&t, R, 1, 1) != DUO_E_REVOKED) return fail("INTEROP_AFTER_REVOKE");
    printf("DOUBLEUNDEROVER_RESIDENCY_AUTHORITY_001=PASS\n");
    printf("HOT_WITHOUT_LAYER=INVALID CONSUMER_WITHOUT_HOT=HOLD\n");
    printf("TOKEN_WITHOUT_CONSUMER=INVALID REVOCATION_KEEPS_HOT=1\n");
    printf("DOUBLE_OVER=HOLD REASON=D3D12_VULKAN_INTEROP_NOT_ESTABLISHED\n");
    printf("MG_REDEFINED=0 PROMOTE=0\n");
    return 0;
}
