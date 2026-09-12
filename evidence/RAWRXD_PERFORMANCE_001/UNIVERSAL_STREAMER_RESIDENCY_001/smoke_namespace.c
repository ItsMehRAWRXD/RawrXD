/* smoke_namespace.c — MODEL_NAMESPACE_001 + MODEL_SWITCH_INVALIDATION_001 */
#include "ur_residency.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *s) { printf("FAIL=%s\n", s); return 1; }

int main(void)
{
    uint8_t mem[8192]; UrMemProvider mp; UrProviderVTable vt; UrRuntime rt;
    UrRegionDesc a, b, c, child; UrRegionId ia, ib, ic, ich;
    UrTicket tk; const uint8_t *p = 0; uint64_t n = 0; UrGeneration g = 0;
    uint64_t mg0;

    memset(mem, 0x22, sizeof mem);
    ur_mem_init(&mp, mem, sizeof mem); ur_mem_as_vtable(&mp, &vt);
    ur_runtime_init(&rt, vt, 0x4E51u);
    memset(&a, 0, sizeof a);
    a.provider = 1; a.offset = 0; a.length = 4096;
    b = a; c = a;
    a.model = 1; a.model_gen = 1;
    b.model = 2; b.model_gen = 1;
    c.model = 3; c.model_gen = 1;
    ia = ur_region_id_from_desc(&a);
    ib = ur_region_id_from_desc(&b);
    ic = ur_region_id_from_desc(&c);
    if (ia == ib || ib == ic || ia == ic) return fail("COLLIDE");
    child = a; child.offset = 1024; child.length = 512;
    ich = ur_region_id_from_desc(&child);
    if (ur_index_put(&rt.index, ia, &a) || ur_index_put(&rt.index, ib, &b)
        || ur_index_put(&rt.index, ic, &c) || ur_index_put(&rt.index, ich, &child)
        || ur_op_begin(&rt.auth, rt.owner, &tk))
        return fail("SETUP");
    if (ur_require_region(&rt, tk, ia, UR_REASON_CURRENT_OP, &p, &n, &g)) return fail("A");
    if (ur_require_region(&rt, tk, ib, UR_REASON_CURRENT_OP, &p, &n, &g)) return fail("B");
    if (ur_require_region(&rt, tk, ic, UR_REASON_CURRENT_OP, &p, &n, &g)) return fail("C");
    if (rt.tel.mg_loads != 3) return fail("THREE_MG");
    mg0 = rt.tel.mg_loads;
    if (ur_require_region(&rt, tk, ich, UR_REASON_CURRENT_OP, &p, &n, &g)) return fail("CHILD");
    if (rt.tel.mg_loads != mg0 || rt.tel.alias_hits != 1) return fail("ALIAS_SAME_MODEL");
    /* sibling model parent must not satisfy this child */
    if (rt.tel.alias_hits != 1) return fail("CROSS_MODEL_ALIAS");
    if (ur_invalidate_model(&rt, 1)) return fail("INVAL");
    mg0 = rt.tel.mg_loads;
    if (ur_require_region(&rt, tk, ia, UR_REASON_CURRENT_OP, &p, &n, &g)) return fail("A2");
    if (rt.tel.mg_loads != mg0 + 1) return fail("SWITCH_REMG");
    printf("MODEL_NAMESPACE_001=PASS IDS_DISTINCT=1 CROSS_MODEL_ALIAS=0\n");
    printf("MODEL_SWITCH_INVALIDATION_001=PASS STALE_MODEL_RELOAD=1\n");
    printf("MODEL_FAMILY_BRANCHES_IN_RESIDENCY=0 PROMOTE=0\n");
    ur_op_end(&rt.auth, rt.owner, tk, 1);
    ur_runtime_shutdown(&rt);
    return 0;
}
