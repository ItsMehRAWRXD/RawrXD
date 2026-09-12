/* duo_emit.c — ingest observed split-stream facts; over recomputes auth */
#include "duo_ticket.h"
#include <stdio.h>
int duo_ingest_split_stream(DuoTicket *t, uint64_t region, uint64_t ticket,
                            uint64_t off, uint64_t len, int identity,
                            uint64_t warm, uint64_t mg, uint64_t hot,
                            uint64_t gen, int parity, int gpu,
                            uint64_t owner, uint64_t codec)
{
    int rc;
    if (!t) return DUO_E_ARG;
    duo_ticket_clear(t);
    rc = duo_observe_range(t, region, ticket, off, len, identity);
    if (rc) return rc;
    if (!warm) return DUO_OK;
    rc = duo_observe_warm(t, region, ticket, mg);
    if (rc) return rc;
    rc = duo_layer_bind(t, region, ticket, gen ? gen : 1, owner ? owner : 1, off, len, codec);
    if (rc) return rc;
    if (!hot || !gpu) return DUO_OK;
    rc = duo_observe_hot(t, region, ticket, gen ? gen : 1);
    if (rc) return rc;
    if (parity) rc = duo_observe_parity(t, region, gen ? gen : 1, 1);
    return rc;
}
void duo_print_disposition(const DuoTicket *t, const char *stop)
{
    uint32_t g; int ac, lv;
    if (!t) return;
    g = duo_granted(t);
    ac = duo_authorize_consumer(t);
    lv = duo_auth_level(t);
    printf("PHYSICAL_STATE=%s\n", (t->facts & DUO_F_HOT_RES) ? "HOT" : ((t->facts & DUO_F_WARM_RES) ? "WARM" : "COLD"));
    printf("DOUBLE_UNDER ProviderObserved=%u ExactRangeBound=%u\n",
           !!(g & DUO_F_PROVIDER), !!(g & DUO_F_RANGE));
    printf("UNDER WarmAuthorized=%u WarmResident=%u MG_LOADS=%llu MG_OWNS_AUTHORIZATION=0\n",
           !!(g & DUO_A_WARM), !!(g & DUO_F_WARM_RES), (unsigned long long)t->mg_loads);
    printf("LAYER OperationBound=%u GenerationMatch=%u\n",
           !!(g & DUO_F_OP_BOUND), !!(g & DUO_F_GEN_MATCH));
    printf("OVER HotAuthorized=%u HotResident=%u PARITY=%u\n",
           !!(g & DUO_A_HOT), !!(g & DUO_F_HOT_RES), !!(t->facts & DUO_F_PARITY));
    printf("DOUBLE_OVER ConsumerAuthorized=%u ConsumerImported=%u\n",
           !!(g & DUO_A_CONSUMER), !!(t->facts & DUO_F_IMPORTED));
    printf("OVER_CONSUMER_AUTHORIZE=%s AUTH_LEVEL=%d\n",
           ac == DUO_OK ? "PASS" : (ac == DUO_HOLD_INTEROP ? "HOLD" : "FAIL"), lv);
    printf("CONSUMER_RAN=%d LOGITS=%d TOKEN=%d REVOKED_CONSUMER=%u\n",
           !!(t->facts & DUO_F_CONSUMER_RAN), !!(t->facts & DUO_F_LOGITS),
           !!(t->facts & DUO_F_TOKEN), t->rev_cons);
    printf("RESIDENCY_VALID=%d CONSUMER_BIND_VALID=%d\n",
           duo_authorize_residency(t) == DUO_OK, ac == DUO_OK);
    printf("AUTHORIZATION_STOP_REASON=%s\n", stop ? stop : "");
    printf("HOTPATCH_MAY_SET_AUTHORITY_RESULT_DIRECTLY=0 PROMOTE=0\n");
}
