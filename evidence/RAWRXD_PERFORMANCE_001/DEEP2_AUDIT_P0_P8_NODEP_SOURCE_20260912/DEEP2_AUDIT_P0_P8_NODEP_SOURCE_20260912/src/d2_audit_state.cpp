#include "deep2_audit_nodep.h"
extern "C" int d2_apply_external_full_tps_authority(D2AuthorityState* s, uint32_t sealed_authority) {
    if (!s) return 0;
    /* This source cannot mint authority. It may only preserve an externally sealed 0/1 state. */
    s->full_model_tps_authority = sealed_authority ? 1u : 0u;
    return 1;
}
